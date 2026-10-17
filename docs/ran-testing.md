# RAN stack: srsRAN Project replacement, UE connectivity, and E2SM-KPM telemetry

Estado: **1 UE real confirmado de punta a punta (RACH → RRC → PDU Session → internet real vía
el UPF → tráfico real hasta `victim` → KPM por UE atribuido correctamente en el RIC).**
Multi-UE (broker GNU-Radio): **confirmado que SÍ puede aislar 3 UEs reales** (7 PRACH distintos
+ 1 attach completo en una corrida) tras arreglar dos causas raíz reales (preamble hardcodeado
en srsRAN_4G, `ue` con vCPUs insuficientes) — pero sigue siendo no-determinístico, peor que el
~50% de flakiness de RACH ya conocido para 1 solo UE.
Split CU/DU en VMs separadas (`ran` = CU, `du` nueva VM): **confirmado funcionando de punta a
punta, plano de control Y plano de datos** (RACH → RRC → PDU Session → 5/5 ICMP real, 0%
pérdida, F1 real por red, no loopback). La causa raíz de un bloqueo real en el plano de datos
resultó ser `du` subdimensionada (4 vCPU → el pool de hilos real-time del propio proyecto queda
en 1 solo hilo) y no un bug de código — subir a 8 vCPUs lo resolvió sin ningún parche de
concurrencia. Ver §8.
`amf_ue_ngap_id` real vía E2SM-KPM (antes solo `gnb_cu_ue_f1ap`, un índice interno del DU):
**confirmado funcionando** tras portar el ID real del AMF al proveedor de medición del CU-CP.
Ver §7. `amf_ue_ngap_id` y `gnb_cu_ue_f1ap` ahora viajan **juntos** en la misma indicación KPM del
CU-CP (correlación F1AP, sin tocar CU-UP/E1AP) y se confirmó la cadena de correlación completa
KPM → AMF → SUPI/IMSI → sesión SMF → sesión UPF, todo automatizado en un solo playbook. Ver §9.
Fecha: 2026-09-20/21.

Automatización: `deploy/vm-lab/ansible/playbooks/test_single_ue.yml`,
`test_three_ue_broker.yml`, `test_kpm_validation.yml`, `test_split_cu_du.yml` — ver §5 y §9.

## 1. Reemplazo de OCUDU por srsRAN Project

El `ran_srsran` role usaba OCUDU (el propio fork/sucesor de srsRAN Project) como gNB. Tras una
sesión larga de debugging persiguiendo un fallo de RACH no resuelto sobre OCUDU (ver el
historial de commits de `ran_srsran` para el detalle completo — bugs de executor-stall,
reconexión ZMQ, y un bug de logger que resultó estar mal diagnosticado), se decidió volver al
proyecto original. No es una afirmación de que OCUDU tuviera la culpa — el propio README de
srsRAN Project (commit `4bf1543`, de su mantenedor oficial) ya apunta a OCUDU como su sucesor —
pero srsRAN Project es el más probado/usado de los dos, y valía la pena reintentar ahí.

**Cambios:**
- `/opt/ocudu` eliminado por completo de la VM `ran` (1.8GB).
- `ran_srsran/tasks/main.yml` clona `github.com/srsRAN/srsRAN_Project`, pinneado a
  `release_25_10` (el tag más reciente al momento, vía `git ls-remote --tags` — no floating en
  `main`, mismo criterio que `srsRAN_4G`/OCUDU ya seguían).
- 3 de los 4 patches de OCUDU se **portaron** (no copiaron a ciegas) al código real de
  srsRAN Project, confirmando primero que el mismo patrón de bug existe ahí:
  - `srsran-rlc-am-executor-stall-workaround.patch` y
    `srsran-f1ap-du-executor-stall-workaround.patch` — aplicaron con el mismo patrón
    (`execute_and_continue_on_blocking()`/`defer_and_continue_on_blocking()` suspendido para
    siempre bajo virtualización), confirmado presente verbatim vía grep antes de aplicar.
  - `srsran-zmq-reconnect.patch` — reescrito desde cero: srsRAN Project **no tenía ningún**
    mecanismo de recuperación para un REQ/REP ZMQ desincronizado (confirmado: no existe
    `reconnect()`/`rebind()` en el código original), a diferencia de OCUDU que ya lo tenía
    parcheado. Incluye también el throttle de EAGAIN (backoff de 500µs) de la misma sesión de
    debugging.
  - El workaround de MAC/RLC-TM (`ocudu-571-executor-stall-workaround.patch` original) **no se
    portó** — el mismo patrón de código existe en `mac_cell_processor.cpp`, pero el gNB arrancó
    limpio sin necesitarlo. Si el gNB se cuelga al activar la celda, ese es el primer lugar a
    revisar.

## 2. UE único, cross-VM: confirmado de punta a punta

Setup real usado (no colocado — gNB en `ran`, UE en `ue`, dos VMs separadas, tráfico ZMQ real
sobre la red RAN):

```
ran:  gnb -c /etc/srsran/gnb_zmq.yaml
ue:   srsue /etc/srsran/ue_direct_zmq.conf
```

Resultado confirmado en corridas reales: RACH → `RRC Connected` → `PDU Session Establishment
successful, IP: 10.45.1.2` → `RRC NR reconfiguration successful` → operación estable continua
(PUCCH/BSR cicleando, sin errores en 4 líneas de log en toda la corrida).

**No-determinismo conocido, sin arreglo de aplicación encontrado:** el RACH falla ocasionalmente
en el primer intento (7/7 preambles transmitidos, nunca respondidos por el gNB). Reintentar
(matar y relanzar el UE, a veces también el gNB) resuelve en 1-3 intentos, siempre. El playbook
`test_single_ue.yml` no reintenta automáticamente — si falla, simplemente volvé a correrlo.

**Paso manual que SÍ hace falta siempre** (no se puede provisionar de antemano — la interfaz no
existe hasta que `srsue` corre): agregar una ruta por defecto dentro del netns del UE.
`srsue`'s `[gw]` crea `tun_srsue` con la IP asignada pero nunca agrega la ruta:

```bash
ip netns exec ue1 ip link set lo up
ip netns exec ue1 ip route add default via 10.45.1.1 dev tun_srsue
```

(el playbook lo hace automático, derivando el gateway de la IP asignada en vez de hardcodearlo)

## 3. Conectividad real: internet y `victim`, validada pasando por el UPF

Dos gaps de infraestructura reales en `core5g`, **nunca configurados hasta ahora** — el UE
llegaba a tener PDU Session pero cualquier tráfico salía con "Network is unreachable" o se
perdía en el camino:

1. **`FORWARD` en DROP por defecto** (cosa de Docker: inserta `DOCKER-USER`/`DOCKER-FORWARD`
   como primer salto de `FORWARD`, y `ogstun` — la interfaz de datos del UPF — no es una
   interfaz manejada por Docker, así que nunca matcheaba nada).
2. **Sin masquerade para el pool de UE** (`10.45.0.0/16`) — así que aunque se forwardeara, no
   había forma de que la respuesta volviera.

Arreglado con reglas idempotentes en `core5g_open5gs/tasks/main.yml` (`DOCKER-USER` ACCEPT para
`ogstun` en ambas direcciones + `MASQUERADE` del pool de UE saliendo por `ens160`, que cae
dentro del masquerade `10.10.0.0/24` que el control node ya tenía).

**Validado con evidencia real, no solo "el ping funcionó":**
- Internet: `ping -c 5 8.8.8.8` desde el netns del UE → 5/5, 0% pérdida. Captura simultánea con
  `tcpdump -i ogstun` en `core5g` → los 10 paquetes (5 request + 5 reply), ya desencapsulados de
  GTP-U, confirmando que el UPF está genuinamente en el camino.
- `victim` (10.10.0.100, dirección MGMT — la única alcanzable desde el pool de UE; la dirección
  ENT_DC de `victim` solo es alcanzable vía el bridge de `pe`, arquitectura distinta): 5/5,
  0% pérdida, RTT 129-253ms.

## 4. E2SM-KPM: subscribe+indicate con atribución real por UE

### 4.1. `xapp_kpm_moni` contra el RIC real (no el simulador ns-3)

Importante: `simulation/parse_xapp_kpm_log.py` y `ddos_xapp_events.csv` son de un pipeline
**distinto**, basado en ns-3 — no confundir con esto. Acá se usó el propio binario de ejemplo de
FlexRIC (`/opt/flexric/build/examples/xApp/c/monitor/xapp_kpm_moni`) contra el `nearRT-RIC` real
de la VM `ric`, suscrito al gNB real.

Dos bugs encontrados y arreglados en el camino (ambos ya en `gnb_zmq.yaml.j2`):

1. **`-a 127.0.0.1` cuelga para siempre** ("Resending Setup Request after timeout") — el
   `nearRT-RIC` solo bindea sus sockets SCTP (E2AP 36421, E42 36422) en su dirección real
   (`ric_addr`, confirmado vía `ss`/`lsof`), nunca en loopback. Hay que usar `-a {{ ric_addr }}`.
2. **`e2sm_rc_enabled: true` crashea el xApp** con un `assert()` fallido decodificando el
   service model RC (`rc_dec_asn.c:dec_ran_func_ctrl_it`, un campo ASN.1 no implementado en este
   build de FlexRIC) — pasa ANTES de que el xApp llegue siquiera a suscribirse a KPM. Como este
   lab no usa RIC Control, se deshabilitó (`e2sm_rc_enabled: false`).

### 4.2. Atribución por UE (Style 4/5, no solo agregado por celda)

Con el gNB arrancando limpio, las indicaciones SÍ llegaban, pero **ninguna traía identidad de
UE** — todas Format 1 (agregado de celda). Rastreado hasta el código real de srsRAN Project:

`e2sm_kpm_report_service_style4::collect_measurements()` → `get_ues_matching_test_conditions()`
→ solo devuelve UEs presentes en `ue_aggr_rlc_metrics` → ese mapa solo se llena vía
`report_metrics(rlc_metrics)` → ese callback solo se conecta en absoluto si
`metrics.layers.enable_rlc` es `true` en el YAML del gNB. Sin eso, `build_rlc_du_metrics()`
retorna temprano y **nunca crea nada** — ni el productor ni el consumidor que conecta con E2.
`metrics.periodicity.du_report_period` (necesario para el resto del pipeline de métricas) NO
alcanza solo — son dos flags separados.

**No hizo falta portar código de OCUDU** — era un gap de configuración real, no de wiring.

Confirmado con correlación temporal exacta (ping burst real mientras el xApp capturaba):

| Indicación | Tipo | `DRB.UEThpDl/Ul` |
|---|---|---|
| agregado (sin UE ID) | Style 1 | 49.00 / 59.00 kbps |
| **`UE ID = gNB-DU, gnb_cu_ue_f1ap = 0`** | Style 4 | **49.00 / 59.00 kbps — idénticos** |
| pico del burst (ambos) | — | 98.00 / 89.00 kbps |
| ping terminado (ambos) | — | 0.00 / 0.00 kbps |

## 5. Automatización

Playbooks en `deploy/vm-lab/ansible/playbooks/` (asumen que `site.yml` ya corrió, no compilan
nada — solo lanzan/prueban los binarios ya construidos):

```bash
cd deploy/vm-lab/ansible
ansible-playbook playbooks/test_single_ue.yml                     # §2 + §3
ansible-playbook playbooks/test_single_ue.yml -e victim_addr=X    # victim custom
ansible-playbook playbooks/test_kpm_validation.yml                # §4 (requiere §2 corrido antes)
ansible-playbook playbooks/test_three_ue_broker.yml                # §6 -- ver limitación abajo
ansible-playbook playbooks/test_split_cu_du.yml                    # §8 + §9 (split CU/DU + correlación)
ansible-playbook playbooks/test_split_cu_du.yml --tags kpm,correlate  # solo KPM + correlación (requiere corrida completa antes)
```

## 6. Multi-UE (broker GNU-Radio): puede aislar 3 UEs reales, pero no de forma confiable

El camino multi-UE (`multi_ue_scenario.grc`, combina el UL de 3 UEs hacia el gNB y reparte el
DL) estaba documentado como roto entre VMs ("se cuelga después del handshake ZMQ"). Eso resultó
ser cierto solo parcialmente: **nunca se había corrido headless/en el orden correcto.**
`grcc` (persistido en `ue_srsue/tasks/main.yml`) compila el `.grc` a un script Python standalone
que corre bajo `xvfb-run` sin necesitar GUI — y con eso, sí corre.

### 6.1. Primer intento: no era un test de 3 UEs real — dos causas raíz reales

Con `test_three_ue_broker.yml` corriendo por primera vez: los 3 `srsue` reportaban
individualmente "RRC Connected" con el **mismo** `c-rnti=0x4601` y el **mismo** `tti=174`
exactos, pero el gNB solo veía una detección de PRACH y un contexto de UE. Dos causas reales,
ninguna en el `.grc`:

1. **`preamble_index` hardcodeado a `0` en srsRAN_4G.** `proc_ra_nr.cc`'s
   `ra_resource_selection()` (38.321 §5.1.2) está literalmente marcado `(TODO)` en su propio
   comentario — nunca implementa selección de preamble, así que TODOS los UEs, siempre,
   transmiten el preamble 0 en la ocasión 0. Bit-idénticos entre sí — ninguna lógica de
   combinación del broker podría distinguirlos. Arreglado con
   `srsran4g-random-preamble.patch` (`ue_srsue/files/`): aleatoriza `preamble_index` (seed por
   proceso, PID+tiempo), reseleccionado en cada reintento.
2. **`ue` con solo 2 vCPUs, 4x sobresuscrita.** Con 3 `srsue` + el broker corriendo DSP
   real-time simultáneo: `load average: 6.95`, 7-9 procesos en cola, 92-102k context-switches/s
   — mismo patrón que ya había forzado subir `ran` de 4 a 8 vCPUs (`f750440`). Redimensionado a
   8 vCPUs (`govc vm.change -vm ue -c 8`, tras `vm.power -off`/`-on`).

Efecto lateral encontrado al redimensionar: **un reboot borra los network namespaces** (viven en
`/var/run/netns`, tmpfs) — `ue1`'s propio `srsue` fallaba con "Failed to setup/configure GW
interface" porque su netns ya no existía. Arreglado con un servicio systemd oneshot
(`srsue-netns.service`) que los recrea en cada boot, sin depender de volver a correr Ansible.

### 6.2. Con ambos fixes: confirmado que SÍ puede aislar 3 UEs reales — pero no siempre

En una corrida real: **7 detecciones de PRACH genuinamente distintas** en el log del gNB
(`tc-rnti=0x4601` a `0x4607`, cada una con su propio `preamble` real), y **al menos 1 UE**
completando el attach entero (RACH → RRC Connected → RRC NR reconfiguration successful). El
broker no está fundamentalmente roto — puede darle a cada UE un canal de RF genuinamente
distinguible.

**Pero sigue siendo no-determinístico, y peor que el caso de 1 solo UE.** 4 corridas después del
fix: 1 éxito (7 PRACH/1 attach completo), 3 con 0 detecciones — comparado con el ~50% de
flakiness de RACH ya documentado para un solo UE (ver §2), esto parece contención adicional real
entre los 3 UEs, no solo la misma flakiness de siempre.

**Nuevo modo de fallo encontrado, distinto del original:** con la detección de PRACH ya
funcionando, UE2/UE3 SÍ consiguen que el gNB les detecte el preamble y les agende una ocasión de
PUSCH para el Msg3 (RRC Setup Request) — pero ese Msg3 llega con `crc=KO` sistemáticamente,
descartado tras 4 reintentos (`sinr=infdB`, un valor sospechoso). La detección de PRACH es
por correlación (tolerante a interferencia); el Msg3 es data real codificada, mucho más sensible.
Hipótesis, no confirmada: el broker suma las muestras de los 3 UEs en el dominio temporal sin
modelar un offset de timing/CFO por UE — necesario en OFDM real para que la ortogonalidad entre
subportadoras de transmisores simultáneos no se rompa. Arreglarlo necesitaría rediseñar esa
lógica de combinación en el `.grc` — no investigado más a fondo, es un trabajo de DSP más grande
que un patch puntual.

**Estado práctico: tratar "3 UEs reales" como posible pero no confiable.** Para cualquier prueba
que necesite conectividad real con más de un UE de forma consistente, seguir usando corridas
secuenciales de `test_single_ue.yml` en vez de depender del broker hasta que §6.2's modo de
fallo del Msg3 se resuelva.

## 7. `amf_ue_ngap_id` real vía E2SM-KPM (no solo `gnb_cu_ue_f1ap`)

**Motivación:** el DU ya exponía `gnb_cu_ue_f1ap` (un índice interno del RAN, se resetea con
cada reconexión) vía KPM Style 4/5 — pero no el `amf_ue_ngap_id` real (asignado por el AMF del
core, el identificador que realmente ata la sesión de radio a un suscriptor real). Confirmado
leyendo el código de srsRAN Project: `e2sm_kpm_cu_meas_provider_impl` (el único camino posible
hacia `amf_ue_ngap_id`) nunca se instanciaba desde el `gnb` fusionado — solo desde `apps/cu/
cu.cpp` — y el propio proveedor del CU-CP no tenía **ninguna** métrica registrada ni acceso al
CU-CP/NGAP en absoluto.

**Parche aplicado** (contra `release_25_10`, en `/opt/srsRAN_Project` durante el build de
`ran_srsran`): añade `get_amf_ue_id_and_guami()`/`get_ue_indexes()` a `cu_configurator` (nueva
interfaz `ngap_ue_id_translator::get_guami()`, análoga a la ya existente `get_amf_ue_id()`),
inyecta ese `cu_configurator` al constructor de `e2sm_kpm_cu_cp_meas_provider_impl` (mismo patrón
de DI que ya usaba el executor de E2SM-RC), y registra una métrica nueva (`RRC.ConnMean`,
NRCellCU, UE_LEVEL) cuyo propósito real no es el valor en sí sino forzar que
`get_ues_matching_test_conditions()` construya un `ue_id_gnb_s` real con `amf_ue_ngap_id` +
`guami` para cada UE conectado.

**Confirmado funcionando en una corrida real** (xApp `xapp_kpm_moni` suscrito al agente E2 del
CU-CP):
```
UE ID type = gNB, amf_ue_ngap_id = 27
RRC.ConnMean = 1 []
```
CU y DU siguen estables (sin crash) tras la suscripción con los 4 estilos de reporte combinados.

**Limitación conocida:** el tráfico real (throughput, volumen RLC) solo se puede atar hoy al
`gnb_cu_ue_f1ap` del DU, no directamente al `amf_ue_ngap_id` — el CU-CP solo expone la métrica
sintética de arriba, no tráfico real (eso vive en CU-UP, cuyo propio proveedor de KPM
(`DRB.PdcpReordDelayUl`/`DRB.PacketSuccessRateUlgNBUu`) sigue sin `cu_configurator` inyectado,
así que tampoco llevaría `amf_ue_ngap_id` aunque se habilite su agente E2 — ver §8 sobre
habilitar `enable_cu_up_e2`).

## 8. Split CU/DU en VMs separadas (`ran` = CU, `du` = nueva VM)

**Estado final: confirmado funcionando de punta a punta, incluyendo el plano de datos**
(5/5 ICMP, 0% pérdida, real ping desde el UE hasta `victim`'s MGMT address cruzando las 3 VMs
reales). Ver §8.4 para la resolución final.

**Motivación:** llevar el split CU/DU (antes same-VM, F1 por loopback) a una arquitectura más
realista — CU y DU en VMs distintas, F1 por red real. Nueva VM `du` (8 vCPU, 8GB RAM, 20GB
disco, `10.10.0.10`/`10.40.0.4`) agregada a `topology.yaml`, nuevo rol `du_srsran` (compila solo
`srsdu`, aplica los 3 patches DU-relevantes que ya usaba `ran_srsran`). `ran_srsran` ya no
compila ni despliega `srsdu`. Nota: la VM `du` empezó en 4 vCPU y se subió a 8 — ver §8.4 para
por qué esa era la causa raíz real del bloqueo de plano de datos, no un problema de código.

### 8.1. Bug real encontrado: F1-U y N3 compitiendo por el mismo puerto GTP-U

Al mover `cu_up.f1u.socket.bind_addr` de loopback (`127.0.10.1`) a la IP real de `ran`
(`10.40.0.2`, la misma que usa N3 hacia el AMF/UPF), el CU crasheaba al arrancar:
`Failed to bind UDP socket to 10.40.0.2:2152. Address already in use`. Confirmado con un bind
UDP crudo en Python (funcionaba perfecto momentos después del crash) que **no era un proceso
externo** — F1-U y N3 son dos gateways GTP-U separados dentro del mismo proceso `srscu`, ambos
con puerto por defecto 2152 (`f1u_sockets_appconfig::bind_port`/`n3_udp_cfg.bind_port`, ambos
`GTPU_PORT`). Al reusar la misma IP para los dos, chocan. **Fix:** puerto explícito distinto
para F1-U (`bind_port: 2153` en el CU, `peer_port: 2153` en el DU) — misma IP, puertos distintos.

**Bug de anidamiento YAML descubierto en el camino:** `f1u:` va anidado bajo `cu_up:` en el
schema CLI11 del CU (`add_subcommand(*cu_up_subcmd, "f1u", ...)`), pero es de **nivel superior**
en el DU (`app.add_subcommand("f1u", ...)`, sin padre) — inconsistencia real entre los dos
schemas de la propia srsRAN Project, misma clase de gotcha que el ya documentado
`enable_cu_cp_e2`/`enable_du_e2`.

### 8.2. Bug real encontrado: el DU nunca activaba la celda cruzando VMs

Con F1 ya conectado por red real (`10.40.0.2 <-> 10.40.0.4`, confirmado por
`/proc/net/sctp/assocs`, y el propio log del DU: `F1-C: Connection to CU-CP on 10.40.0.2:38472
completed`), el UE nunca intentaba ni un PRACH — el DU se quedaba colgado, tan poco responsivo
que ni siquiera reaccionaba a un `SIGTERM` limpio (forzó `kill -9` tras 5+ segundos).

Coincide con un riesgo ya documentado desde que se portaron los otros 2 workarounds de
executor-stall de OCUDU#571 en esta misma VM lab: el 3er workaround (MAC + RLC TM,
`lib/mac/mac_dl/mac_cell_processor.cpp` + `lib/rlc/rlc_tx_tm_entity.cpp`) nunca se había
necesitado porque la versión same-VM (loopback) no lo disparaba — cruzar a una red real entre
VMs parece ser justo el cambio de timing que lo expone. Portado contra `release_25_10` (el
intento original, de un commit anterior de este mismo repo, targeteaba OCUDU/`release_26_04` y
ya no aplicaba limpio) — mismo patrón: reemplazar
`execute_and_continue_on_blocking()`/`defer_and_continue_on_blocking()` (que nunca se
despachan bajo virtualización) por ejecución inline vía `launch_no_op_task()`.

**Confirmado funcionando en una corrida real** tras el fix: RACH → RRC Connected → PDU Session
Establishment → RRC NR reconfiguration successful, cruzando las 3 VMs (`ran`, `du`, `ue`) reales.

### 8.3. Bloqueo encontrado (y descartado como código): el plano de datos (DRB) no fluía

Con el attach completo confirmado, el tráfico real (ping desde el UE) **nunca llegaba** a
`core5g` (confirmado con `tcpdump` en `core5g`: cero paquetes ICMP recibidos). El log del propio
UE mostraba la causa aparente: los SDUs sí se generaban y entraban a la cola RLC (`DRB1: Tx
SDU`), pero la cola **crecía sin parar** (`tx_sdu_queue_len=18, 19, 20...`) — nunca se
transmitían por el aire.

**Prueba de control decisiva:** el `gnb` fusionado (mismo release, SIN el parche de §8.2) en la
misma VM `ran`, mismo UE — **0% de pérdida, 5/5 ICMP**. Esto descartó de raíz cualquier problema
de RF/ZMQ, UPF o ruteo, y apuntó directo al parche de §8.2 como la causa: el patrón original
(`execute_and_continue_on_blocking`/`defer_and_continue_on_blocking`, que despacha a
`cell_exec`) no solo evita bloqueos — también **serializa todas las mutaciones de estado del
scheduler en un único hilo**. Al reemplazarlo por ejecución inline (`launch_no_op_task()`,
confirmado en su propio código: se completa 100% síncrono, sin ninguna suspensión), esa garantía
de seguridad de hilos desaparece — `add_ue()`/`addmod_bearers()` ahora mutan el estado del
scheduler desde el hilo que sea, no necesariamente el mismo que el bucle de tiempo real del
scheduler lee.

### 8.4. Causa raíz real, confirmada, y resuelta sin parche de código

`ps -T` sobre el proceso real reveló la causa raíz exacta: el pool de hilos real-time de
`srsdu` (`apps/services/worker_manager/worker_manager.cpp: get_default_nof_workers()`, fórmula
`max(min(estimado, vCPUs - min(vCPUs, 3)), 1)`) tenía **un solo hilo** (`main_pool#0`) con 4
vCPUs — 3 se reservan siempre como "spare" (kernel, timing de RU) sin importar el total. El
mismo código, en la VM `ran` con 8 vCPUs (usado por el `gnb` fusionado), crea **5 hilos**
(`main_pool#0-4`). Un pool de un solo hilo garantiza un interbloqueo para cualquier tarea que
dependa de otra tarea encolada en ese mismo hilo — exactamente lo que `cell_exec`/
`pcell_executor` sufrían. El parche de §8.2 no arreglaba un bug de virtualización inherente (como
asumía el propio issue de OCUDU#571, que tampoco identifica la causa raíz) — enmascaraba una VM
subdimensionada.

**Fix real:** subir `du` de 4 a 8 vCPUs (`topology.yaml`, vía `govc vm.change -vm du -c 8 -m
8192`) y **revertir por completo** el parche de §8.2 (`git checkout --` sobre los 2 archivos,
recompilar). Confirmado en una corrida real: `ps -T` ahora muestra 5 hilos `main_pool#0-4`
(igual que `ran`), attach completo (RACH → RRC → PDU Session), y **tráfico de datos real
funcionando — 5/5 ICMP, 0% pérdida**, cruzando las 3 VMs (`ran`, `du`, `ue`) reales.

**Lección:** el patch de executor-stall (§8.2, `srsran-mac-rlc-tm-executor-stall-workaround.patch`)
se mantiene en `du_srsran/files/` como referencia histórica pero **ya no se aplica** — quedó
documentado en el propio `tasks/main.yml` del rol por qué existe y por qué no se usa. Antes de
portar un workaround de concurrencia para un síntoma "bajo virtualización", vale la pena
primero medir el pool de hilos real (`ps -T -o tid,psr,pri,rtprio,comm`) — puede que el problema
sea simplemente CPUs insuficientes para la fórmula de sizing del propio proyecto, no un bug de
la plataforma.

**Estado final:** el split CU/DU en VMs separadas funciona de punta a punta — plano de control
(RACH/RRC/PDU Session, F1 real) y plano de datos (tráfico real, confirmado) — sin necesitar
ningún parche de concurrencia, solo el vCPU count correcto.

## 9. Correlación `amf_ue_ngap_id` ↔ `gnb_cu_ue_f1ap` ↔ sesión del core, automatizada

**Motivación:** §7 dejó `amf_ue_ngap_id` disponible vía KPM, pero solo o el AMF ID o el F1AP ID
aparecían por indicación (nunca los dos juntos), y no existía ninguna forma automatizada de
confirmar que ese `amf_ue_ngap_id` correspondía realmente a una sesión concreta en el core
(AMF/SMF/UPF). Esta sección cierra ambos huecos: primero llevando los dos IDs a la misma
indicación KPM, y después atando ese ID a las líneas reales del log del core y reportando la
cadena completa en un solo playbook.

### 9.1. Parche: `amf_ue_ngap_id` y `gnb_cu_ue_f1ap` en la misma indicación KPM

**Alternativa descartada primero:** extender la correlación hasta CU-UP (sus propias métricas de
PDCP, `DRB.PdcpReordDelayUl`/etc, mencionadas como limitación en §7) requeriría un puente E1AP
completo — CU-CP y CU-UP usan namespaces de `ue_index_t` genuinamente separados
(`srs_cu_cp::ue_index_t` vs `srs_cu_up::ue_index_t`), y la interfaz pública de `cu_up_interface`
es deliberadamente mínima (`start()`/`stop()`), sin ningún gancho hoy para exponer ese mapeo.
Alcance descartado a propósito — CU-CP ya rastrea internamente `gnb_cu_ue_f1ap_id` vía F1AP-CU,
así que correlacionar ahí es mucho más chico y no toca CU-UP en absoluto.

**Parche aplicado** (`ran_srsran/files/srsran-cu-f1ap-ue-id-kpm-correlation.patch`, contra
`release_25_10`): nueva interfaz `f1ap_ue_id_translator` (mismo patrón que
`ngap_ue_id_translator` de §7) en `include/srsran/f1ap/cu_cp/f1ap_cu.h`, implementada en
`f1ap_cu_impl.h` leyendo directamente `ue_ctxt_list[ue_index].ue_ids.cu_ue_f1ap_id` (ya poblado,
sin nuevo estado). `cu_configurator`/`cu_configurator_impl` ganan
`get_f1ap_ue_id_for_kpm(ue_index)`, que resuelve `ue_index → du_index → f1ap_handler` y delega ahí.
`e2sm_kpm_cu_meas_provider_impl::append_gnb_ue_id()` llama a esto además de
`get_amf_ue_id_and_guami()` (ya existente) y agrega el resultado a `gnb_cu_ue_f1ap_id_list` de la
misma IE `ue_id_gnb_s` — un solo record KPM, dos IDs.

**Colisión de nombres encontrada:** el primer intento nombró el método
`get_gnb_cu_ue_f1ap_id`, que ya existía como **función libre** en `f1ap_cu_impl.cpp` (extrae el
F1AP ID de PDUs ASN.1 crudos) — el ocultamiento de nombres de C++ rompió 3 call sites no
relacionados ("cannot convert `asn1::f1ap::successful_outcome_s` to `ue_index_t`"). Renombrado a
`get_f1ap_ue_id_for_kpm` en los 6 archivos del patch.

**Confirmado funcionando** (`xapp_kpm_moni`, una sola indicación):
```
UE ID type = gNB, amf_ue_ngap_id = 37
gnb_cu_ue_f1ap = 0
```

### 9.2. Bug encontrado en el xApp de ejemplo: escondía uno de los dos IDs

Con el patch de 9.1 ya llenando ambos campos, `xapp_kpm_moni.c`'s propio `log_gnb_ue_id()`
seguía imprimiendo **solo uno** — su `if/else` original trataba "hay lista F1AP" y "hay
`amf_ue_ngap_id`" como mutuamente excluyentes, cuando en realidad `amf_ue_ngap_id` es un campo
obligatorio de la IE `UEID-GNB` (no parte del choice opcional de la lista F1AP) y un proveedor
real puede legítimamente llenar los dos en el mismo record. Arreglado imprimiendo
`amf_ue_ngap_id` incondicionalmente y la lista F1AP si está presente, sin `else`. Bundleado como
3er fix en el ya existente `flexric-kpm-moni-workaround.patch` (`ric_flexric/files/`) — el bug
vivía en el xApp de ejemplo, no en el protocolo ni en FlexRIC.

### 9.3. Cadena de correlación con el core confirmada de punta a punta

Con `amf_ue_ngap_id` disponible por KPM, se confirmó que corresponde exactamente a la misma
sesión visible en los logs del core (`docker logs open5gs_5gc`, un solo contenedor con
AMF/SMF/UPF) y en la tabla de sesiones del UPF. Ejemplo real, capturado en una sola corrida:

| Fuente | Campo | Valor |
|---|---|---|
| KPM (CU-CP de `srscu`) | `amf_ue_ngap_id` | `37` |
| Log del AMF (core) | `AMF_UE_NGAP_ID` | `...AMF_UE_NGAP_ID[37]...` |
| Log del AMF (core) | SUPI/IMSI | `imsi-001010123456780` |
| Log del SMF (core) | DNN + IP asignada | `...UE SUPI[imsi-001010123456780] DNN[srsapn] IPv4[10.45.1.2]...` |
| Log del UPF (core) | F-SEID + APN | `...UE F-SEID[UP:0x56 CP:0x2e8] APN[srsapn] PDN-Type[1] IPv4[10.45.1.2]...` |

**Bug real encontrado extrayendo el SUPI:** el primer intento buscaba `imsi-[0-9]+` en la línea
"known UE by SUCI" del log del AMF — esa línea solo contiene `suci-...` (el identificador cifrado
que se usa antes de que el AMF resuelva la identidad real), nunca `imsi-...`. El SUPI real
aparece recién unas líneas después, en una línea `UE SUPI[imsi-...]` separada. Arreglado
ampliando la ventana de búsqueda (`grep -A30`) y buscando directamente `'UE SUPI\[imsi-'`.

### 9.4. Automatización: `playbooks/test_split_cu_du.yml`

Playbook nuevo (~330 líneas, 5 plays) que cubre de punta a punta el split CU/DU de §8 **y** la
correlación de esta sección, con tags para correr solo un tramo:

1. **`ran_srsran`** (sin tag): mata cualquier `srscu` viejo, lanza uno limpio, confirma que sigue
   vivo.
2. **`du_srsran`** (sin tag): mata cualquier `srsdu` viejo, lanza uno limpio, confirma que sigue
   vivo Y que la asociación SCTP de F1 real está arriba (`grep -cE '\s38472\s'
   /proc/net/sctp/assocs` — ver bug de formato abajo).
3. **`ue_srsue`** (sin tag; ping de víctima con tag `victim`, tráfico de fondo con tag `kpm`):
   mata cualquier `srsue` viejo, lo lanza con la config split-DU, sondea hasta 12×2s por "PDU
   Session Establishment successful", falla con guía de reintento si no aparece (la flakiness de
   RACH de §2/§6 sigue aplicando aquí — no es un bug nuevo de la automatización, ver más abajo).
4. **`ric_flexric`** (tag `kpm`): mata cualquier `xapp_kpm_moni` viejo, reinicia el `nearRT-RIC`
   si no está corriendo, captura KPM 12s, extrae el par `amf_ue_ngap_id`/`gnb_cu_ue_f1ap` de la
   misma indicación.
5. **`core5g_open5gs`** (tag `correlate`): toma el `amf_ue_ngap_id` capturado por el play
   anterior (vía `hostvars`), y reconstruye la tabla completa de 9.3 grepeando
   `docker logs open5gs_5gc`.

**Confirmado en una corrida real** (`--tags kpm,correlate`, reusando un attach previo):
`PLAY RECAP` sin fallos, tabla de correlación completa e idéntica a la de 9.3 impresa al final.

**Bugs encontrados y arreglados mientras se construía este playbook** (más allá de los ya
cubiertos en 9.1-9.3):

- **Formato real de `/proc/net/sctp/assocs`:** un primer intento buscaba `:38472` (notación
  `addr:port`) — ese archivo usa **columnas separadas por espacios** (`LPORT`/`RPORT`), nunca esa
  notación. Arreglado con `grep -cE '\s38472\s'`.
- **YAML roto por comillas anidadas:** un `name:` de tarea con comillas simples y dobles mezcladas
  en un escalar multi-línea rompía el parser ("mapping values are not allowed in this context").
  Arreglado reescribiendo el texto para no necesitar comillas embebidas.
- **Tarea de ruteo sin tag `always`:** la tarea que configura las rutas del netns del UE no tenía
  tag — al correr `--tags victim,kpm,correlate` (saltándose el play 3 completo) se saltaba también
  el ruteo, y el ping a `victim` fallaba con "Network is unreachable". Arreglado con
  `tags: [always]`.

**Flakiness de RACH durante pruebas automatizadas:** se encontraron varias corridas consecutivas
donde el UE nunca intentaba RACH (o lo intentaba sin respuesta), pese a que la misma secuencia de
comandos manual funcionaba. Investigado a fondo (esperas más largas, reinicios limpios completos)
y descartado como bug nuevo — coincide con la flakiness de RACH ya documentada en todo el
proyecto (~50%+ de fallo por intento, peor aún en escenarios split, ver §2/§6). El propio
playbook documenta esto en su cabecera e instruye reintentar, mismo patrón ya establecido por
`test_single_ue.yml`.
