# Bug: mobile's SYN telemetry nunca llegó al core5g real desplegado

## Origen

`docs/ATTACK_PLAN_REGENERATION_VALIDATION.md` (traffic-generator-pucp)
reportó que, durante la validación de `composition1_mobile` y
`composition3`, la señal SYN de `mobile` estaba **completamente
ausente** de `observed_rates` — ningún grupo con `domains=["mobile"]`
se reportó, pese a que `attack_pps_actual` confirmaba que el tráfico
SÍ se envió (364,9 pps reales desde `ue1`).

## Diagnóstico

1. Sondeo directo al bridge de telemetría en core5g
   (`http://10.10.0.5:8766/telemetry`, bypaseando el controlador por
   completo) durante un ataque de prueba (pipeline suspendido): **cero**
   filas `protocol=="TCP_SYN"` en `flows`, confirmando que el problema
   no está en cómo el orquestador consume la telemetría — el bridge
   mismo nunca la produce.
2. Captura directa de `sudo conntrack -E -e NEW -p tcp` en core5g
   mientras se lanzaba el mismo ataque: el kernel **sí** genera los
   eventos `[NEW] tcp ... SYN_SENT src=10.45.1.2 dst=10.55.0.100 ...`
   esperados — la señal cruda SÍ existe y es exactamente lo que
   `oran_bridge/ue_telemetry_api.py`'s `_CT_NEW_SYN_RE` espera.
3. Inspección del proceso real en core5g
   (`ps aux | grep ue_telemetry` → `/opt/isp-ddos-ryu/ue_telemetry_api.py`,
   gestionado por `ue-telemetry-api.service`, systemd, corriendo desde
   antes de cualquier trabajo de hoy): **el archivo desplegado no tenía
   `_conntrack_syn_event_loop`, `SynRateWindow` ni `parse_new_syn_event`
   en absoluto** (0 coincidencias via `grep`) — una versión del script
   anterior a cuando se agregó la funcionalidad de streaming de SYN al
   repositorio. El mismo patrón que `THRESHOLD_CONTROL_PATH_FIX.md`: el
   código correcto existe en el repo, pero nunca llegó al proceso real.

## Complicación: el desplegado también había divergido en su propia
dirección

Al comparar el archivo desplegado completo contra el del repositorio,
el desplegado **no era simplemente más viejo** — tenía SU PROPIA
mejora que el repo no tenía: persistencia de sesiones UE entre
reinicios del contenedor Open5GS (`SESSION_CACHE_PATH`, un cache
"generation-bound" atado al `container_generation`/`State.StartedAt`
de Docker, con detección de rotación del log vía inode) y manejo
explícito de eventos `Removed Session`. El repo, en cambio, solo tenía
una limpieza simple por TTL (`SESSION_TTL_S`).

Esto significa que simplemente copiar el archivo del repo sobre el
desplegado habría **revertido** esa mejora de persistencia de
sesiones. En vez de eso, se hizo un merge explícito: se tomó el
archivo REALMENTE desplegado como base y se le agregó, sin tocar nada
más, exactamente la funcionalidad de streaming de SYN que faltaba
(imports, constantes `SYN_RATE_WINDOW_S`/`SYN_FRAME_BYTES`, el regex
`_CT_NEW_SYN_RE`, `parse_new_syn_event`, `SynRateWindow`, los campos
`syn_events_connected`/`syn_window` en `_State`, el hilo
`_conntrack_syn_event_loop`, la función `build_flow_rows` y su uso en
el handler, y el nuevo campo `syn_events_connected` en la respuesta
JSON). El archivo resultante reemplaza ahora tanto al desplegado en
core5g como al de este repositorio — ambos quedan sincronizados y con
las dos mejoras (persistencia de sesiones + streaming de SYN) juntas.

## Validación

`oran_bridge/test_ue_telemetry_syn.py` (10 pruebas, ya existentes en
el repo, nunca antes ejecutadas contra el archivo realmente
desplegado) — todas pasan contra el archivo fusionado. Suite completa:
180 pruebas, todas pasan.

Desplegado a `/opt/isp-ddos-ryu/ue_telemetry_api.py` en core5g
(10.10.0.5) con tu confirmación (respaldo guardado como
`ue_telemetry_api.py.bak-20261020`), servicio `ue-telemetry-api.service`
reiniciado y confirmado `active`.

**Confirmado en vivo, extremo a extremo**: re-ejecutando
`composition1_mobile` (pipeline suspendido, misma tasa objetivo
364,9 pps):
- Sondeo directo al bridge (`/telemetry`): 119 muestras con filas
  `protocol=="TCP_SYN"` para `src_ip=10.45.1.2` (ue1), subiendo de
  63 pps a >300 pps conforme la ventana deslizante de 2s se llena.
- `observed_rates` del propio controlador (vía `LAB_AUDIT`): 117
  muestras con `trigger_pps` para el grupo `domains=["mobile"]`,
  valores consistentes (38,5 → 336,0 pps) — la señal ahora SÍ llega
  completa, desde el kernel hasta la instrumentación del motor de
  detección.

Pipeline restaurado correctamente al finalizar.

## Supuestos

- No se tocó `_log_tail_loop`'s persistencia de sesiones ni ningún otro
  comportamiento ya desplegado — el único cambio de comportamiento
  real es que ahora SÍ se reporta la tasa SYN de mobile; todo lo demás
  es exactamente el mismo código que ya corría en producción.
- El archivo del repositorio (`oran_bridge/ue_telemetry_api.py`) se
  actualizó para igualar exactamente lo desplegado — a partir de ahora
  ambos deberían mantenerse sincronizados manualmente (no hay git ni
  CI en core5g para esto).
