# Investigación: pico transitorio ~2x en enterprise (SYN)

## Origen

`docs/ATTACK_PLAN_REGENERATION_VALIDATION.md` (traffic-generator-pucp)
reportó que `enterprise` mostraba un agregado SYN observado por el
controlador de ~1.9-2x la tasa de ataque real planificada/emitida, a
diferencia de `fixed` (que coincidía casi exacto).

## Hallazgo 1 — no es un sobreconteo sostenido

En una corrida de 60s (116 muestras de `on_flow_stats`), la mediana fue
349,85 pps (vs. 364,9 pps planificados — dentro del ±15%), con solo
5-9 muestras anómalas saltando a ~690-712 pps, recurriendo cada
~10-15s. Confirmado con un solo `dpid` en todas las muestras (descarta
doble conteo por dos switches reportando el mismo flujo).

## Hipótesis descartada — colisión de clave en FlowCollector

Se sospechó inicialmente una colisión en
`collectors/flow_collector.py`'s `prev_flows` (indexado por `(dpid,
src_ip, dst_ip, proto, dst_port)`, sin `priority`): que una entrada
OpenFlow vieja (por expirar, `hard_timeout=VALIDATED_FLOW_HARD_TIMEOUT`)
y su reemplazo reciente coincidieran en la misma clave dentro de un
mismo `OFPFlowStatsReply`. Se implementó un fix defensivo (agrupar por
clave, no emitir si hay más de un `stat` por clave en el mismo `body`)
con 4 pruebas nuevas (`collectors/test_flow_collector.py`) — **se
mantiene porque es correcto y no tiene costo**, pero instrumentación de
seguimiento (`COLLISION_DEBUG`, con `dpid`+`priority`, desplegada y
removida en el camino) confirmó que esta colisión **nunca ocurre en la
práctica**: 472 líneas de diagnóstico, cero colisiones detectadas,
mientras el pico seguía apareciendo. Esta no era la causa.

## Causa real — doble origen: `on_packet_in` + `on_flow_stats`

`telemetry/openflow_adapter.py` tiene DOS caminos independientes que
pueden reportar la tasa SYN del mismo par `(src, dst)`:

1. **`on_flow_stats`** vía la regla "twin" SYN (`forwarding/syn_twin.py`,
   prioridad `SYN_TWIN_PRIORITY`), que cuenta por contador OpenFlow
   acumulado — el camino normal una vez que el flujo está "validado"
   (`is_validated_flow()` en `orchestration/controller.py`).
2. **`on_packet_in`** vía `DDoSCollector`, que cuenta paquete por
   paquete cuando SÍ llegan al controlador — el camino normal mientras
   el flujo está en estado "provisional" (regla de 2s,
   `LearningSwitch.PROVISIONAL_TIMEOUT`).

El diseño asume que estos dos caminos son **mutuamente excluyentes en
el tiempo** (provisional → packet_in cuenta; validado → flow_stats
cuenta, packet-in deja de dispararse). Pero `VALIDATED_FLOW_HARD_TIMEOUT`
(30s) fuerza una reinstalación periódica de la regla — y durante esa
breve transición, el primer paquete tras la expiración SÍ vuelve a
pasar por `packet-in` (reinicia el ciclo provisional) **mientras el
contador de flow-stats de la regla twin recién-reinstalada también
sigue reportando** un valor normal (su propio polling, no reseteado de
forma sincronizada). `detection/engine.py`'s `_protocol_rate()` suma
`e.pps` de **todos** los `TelemetryEvent` con `protocol=="TCP_SYN"` del
grupo, sin distinguir su origen — así que durante esa ventana de
transición, el pps de `on_packet_in` (~350) y el de `on_flow_stats`
(~350, de la regla que sigue viva un ciclo más) se **suman** en vez de
ser alternativos, dando ~700.

Confirmado con los contadores crudos: durante los picos, la entrada
`proto=0` (regla L3 genérica, prioridad 10, sin `ip_proto`) y la
`proto=6` (twin, prioridad 11 = `SYN_TWIN_PRIORITY`) crecen casi en
paralelo (contadores casi idénticos) — ambas reglas SÍ cuentan el mismo
tráfico de forma independiente y correcta por separado (esto es
esperado y no es un bug en sí), confirmando que el problema no está en
`FlowCollector` sino en que el canal `packet_in` se reactiva brevemente
y se suma al de `flow_stats` en el motor de detección.

## Por qué NO se implementó un fix para esto

El arreglo obvio (suprimir el conteo de `on_packet_in` cuando el par ya
tiene una entrada confirmada en `_flow_meta`) es **riesgoso**: la
ubicación de `dpid`/`in_port` confirmados se fija desde el *primer*
paquete del flujo (apenas se confirma el puerto físico de host), mucho
antes de que la regla twin exista. Suprimir `on_packet_in` basado en
esa señal **subcontaría el ataque durante toda la fase provisional
real** (los primeros ~2s, antes de que exista cualquier regla
flow-stats) — un modo de falla peor que el bug actual (perder una
detección real es más grave que sobre-contar brevemente).

No se encontró, en el tiempo disponible, una señal limpia dentro de
`OpenFlowAdapter` para distinguir "packet-in genuino de fase
provisional" de "packet-in de reinicio tras `hard_timeout` en un flujo
ya válido" sin acoplar el adaptador a `orchestration/controller.py`'s
`is_validated_flow()` (un cambio de mayor alcance, cruza capas).

## Impacto real — acotado

- El pico dura ~1 ciclo (`COLLECT_INTERVAL`=0,5s) cada ~10-15s — no es
  continuo.
- `ENTERPRISE_ACTIVATION_MIN_HITS`/`ENTERPRISE_ACTIVATION_WINDOW_S`
  (hysteresis de activación) ya exige múltiples hits dentro de una
  ventana — un solo ciclo anómalo, aislado, es exactamente el tipo de
  ruido que esa hysteresis existe para filtrar antes de una decisión
  real.
- La mediana de la ventana completa del ataque (349,85 pps) ya cumple
  el criterio ±15% contra lo planificado (364,9 pps) — el criterio de
  validación original que usó `max()` era el que estaba mal calibrado
  para esto, no la medición subyacente.

## Estado

**Confirmado y documentado, no corregido.** El fix de
`FlowCollector` (colisión de clave) se conserva porque es correcto y
gratuito, pero no es la causa de este pico — queda como salvaguarda
para un escenario relacionado (pero distinto) que sí podría ocurrir en
otras condiciones de carga/topología. La causa real (doble origen
packet_in + flow_stats durante la transición de `hard_timeout`) queda
documentada aquí para quien quiera intentar el fix de mayor alcance
(cruzando `OpenFlowAdapter` con el estado de validación de
`orchestration/controller.py`) en una tarea futura.
