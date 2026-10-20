# Bug: FlowCollector same-poll key collision (enterprise ~2x spike)

## Origen

`docs/ATTACK_PLAN_REGENERATION_VALIDATION.md` (traffic-generator-pucp)
reportó que `enterprise` mostraba un agregado SYN observado por el
controlador de ~1.9-2x la tasa de ataque real planificada/emitida, a
diferencia de `fixed` (que coincidía casi exacto). Se investigó con
instrumentación temporal (`SYN_ORIGIN_DEBUG`, removida en el commit de
este fix) en el laboratorio real.

## Hallazgo

**No es un sobreconteo sostenido.** En una corrida de 60s (116 muestras
de `on_flow_stats`), la mediana fue 349,85 pps (vs. 364,9 pps
planificados — dentro del ±15%), con solo 5-9 muestras anómalas
saltando a ~690-712 pps, recurriendo cada ~10-15s. Confirmado con un
solo `dpid` en todas las muestras (descarta doble conteo por dos
switches reportando el mismo flujo). El campo `packets` (contador
acumulado) en las muestras anómalas era implausiblemente bajo para
cuánto tiempo llevaba corriendo el flujo — consistente con una entrada
OpenFlow recién reinstalada.

## Causa

`forwarding/learning_switch.py` instala reglas con
`hard_timeout=VALIDATED_FLOW_HARD_TIMEOUT` (30s) — tanto la regla L3
genérica como su "twin" SYN. Al expirar, se reinstala una regla con el
**mismo OFPMatch exacto**. Durante esa transición, Open vSwitch puede
reportar, en un mismo `OFPFlowStatsReply`, tanto la entrada vieja (por
expirar, contador acumulado alto) como la nueva (recién instalada,
contador reseteado a ~0).

`collectors/flow_collector.py`'s `FlowCollector.process_stats()` indexa
`prev_flows` por `(dpid, src_ip, dst_ip, proto, dst_port)` — **sin**
incluir `priority` ni ningún identificador de instancia de la regla. Si
ambas entradas (vieja y nueva) aparecen en el mismo `body`, ambas
mapean a la **misma clave**. El código original procesaba el `body` en
un solo bucle, escribiendo `self.prev_flows[key]` inmediatamente tras
cada `stat` — así que el *segundo* `stat` de la misma clave se
comparaba contra el contador que el *primero* **acababa de escribir en
esa misma llamada**, no contra el valor real del ciclo anterior. Si el
orden era "nueva (bajo) luego vieja (alto)", el delta resultante era
enorme y positivo — el pico observado.

## Fix

`collectors/flow_collector.py`: el `body` ahora se agrupa por clave en
una primera pasada. Si una clave aparece más de una vez en el mismo
`body` (la colisión), **no se emite ninguna tasa ese ciclo** para esa
clave — se re-establece `prev_flows[key]` con el `stat` de mayor
`packet_count` (la entrada más "avanzada", probablemente la que
sigue viva), igual que los otros casos de "sin ciclo utilizable" ya
existentes (`dt` muy chico, delta negativo). El ciclo siguiente calcula
una tasa limpia contra esa base. La comparación de cada `stat` contra
`prev_flows` ahora usa una **copia (snapshot)** tomada al inicio de la
llamada, nunca el diccionario mutándose a mitad de bucle — así un
`stat` nunca ve el escrito-recién por otro `stat` del mismo `body`.

Pruebas nuevas: `collectors/test_flow_collector.py` (4 pruebas) —
reproduce la colisión exacta (dos `stat` con la misma clave en un
`body`), confirma que no emite pico espurio, que el ciclo siguiente
re-basa correctamente sobre el conteo mayor, y que el caso normal (sin
colisión) sigue calculando tasas limpias.

## Validación en vivo

Confirmado en el laboratorio real (composition1_enterprise, pipeline
suspendido, semilla 201): instrumentación `SYN_ORIGIN_DEBUG` mostró el
patrón de colisión exacto (contador bajo justo en los picos, un solo
`dpid`). El fix se probó localmente (4 pruebas nuevas + 184 de la suite
completa, todas pasan) — **no se volvió a correr el ataque en vivo con
el fix ya desplegado** porque la causa raíz quedó claramente establecida
por los datos crudos capturados; desplegar y volver a medir es un paso
adicional disponible si se quiere confirmar numéricamente el ±15% ya
cumplido.

## Supuestos

- El criterio de validación original (`ATTACK_PLAN_REGENERATION_VALIDATION.md`)
  tomaba el `max()` del agregado observado en toda la ventana del
  ataque — sensible a un solo pico transitorio. Con la mediana (o
  cualquier estadístico robusto a outliers), `enterprise` ya cumplía
  ±15% incluso ANTES de este fix. El fix elimina el pico en la fuente,
  no solo cambia cómo se mide.
- `MITIGATION_DROP_PRIORITY`/`SYN_TWIN_PRIORITY` no cambiaron; el fix es
  puramente de contabilidad interna de `FlowCollector`, no de
  clasificación ni de las reglas OpenFlow instaladas.
