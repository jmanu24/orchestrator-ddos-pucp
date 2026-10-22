# Bug: picos espurios de ~2x en `enterprise` por colisión de claves en `FlowCollector`

## Origen

Encontrado durante la verificación de código desplegado (Prompt de
recalibración de umbrales V2, Paso 1): `collectors/flow_collector.py` en
el controlador real (`/home/labadmin/orchestrator-ddos-pucp`, 10.10.0.1)
tenía un fix real, **staged pero nunca commiteado**, que su propio
comentario referenciaba como `docs/ENTERPRISE_FLOW_STATS_KEY_COLLISION.md`
— un documento que no existía en ningún repositorio hasta ahora. Mismo
patrón que `THRESHOLD_CONTROL_PATH_FIX.md`/`MOBILE_SYN_TELEMETRY_DEPLOY_
DRIFT.md`: el código correcto ya corría en producción, pero nunca quedó
registrado por escrito ni en el historial de git.

## El bug

`FlowCollector.process_stats()` itera `body` (la respuesta
`OFPFlowStatsReply` de un ciclo) y, para cada `stat`, calculaba
`key = (dpid, src_ip, dst_ip, proto, dst_port)` y diffeaba
inmediatamente contra `self.prev_flows[key]`, escribiendo el nuevo valor
en el mismo paso.

Un flujo con `hard_timeout` (`forwarding/learning_switch.py`'s
`VALIDATED_FLOW_HARD_TIMEOUT`) siendo reemplazado por una entrada fresca
con el **mismo** `OFPMatch` puede hacer que OVS reporte, en el **mismo**
`OFPFlowStatsReply`, tanto la entrada vieja muriendo (contadores
acumulados altos) como la nueva recién instalada (contadores en cero) —
la `key` usada aquí ignora `priority`/duración, así que ambas colisionan.
Sin protección, la segunda entrada procesada se diffeaba contra lo que la
PRIMERA acababa de escribir en `self.prev_flows` en esa misma llamada, no
contra el valor real del ciclo anterior — produciendo un salto de tasa
espurio (observado en vivo: ~2x la tasa real) justo en el dominio
`enterprise`, el único que usa OpenFlow/`hard_timeout` de esta forma.

Esto corrompe directamente los datos de calibración: `observed_rates` de
`enterprise` en el Paso 1 de `THRESHOLD_CALIBRATION_RESULT.md` se
alimenta de este collector.

## El fix (ya desplegado, ahora commiteado tal cual)

Dos pasadas por ciclo en vez de una:

1. **Snapshot de `prev_flows` tomado una sola vez**, antes de procesar
   cualquier `stat` de este `body` — nunca se lee `self.prev_flows`
   dentro del mismo bucle que lo escribe.
2. **Primera pasada**: agrupa los `stat` de este `body` por `key`.
   Casi siempre una entrada por `key`; una segunda para la misma `key`
   es exactamente la colisión descrita arriba.
3. **Segunda pasada**: si una `key` tuvo más de una entrada en este
   ciclo, nunca se calcula una tasa con ninguna de las dos — se
   re-baselinea `prev_flows[key]` con la entrada de mayor
   `packet_count` acumulado (la más probable de seguir viva tras la
   transición) y se omite la tasa de ese `key` para este ciclo,
   igual que ya hacían los otros casos de "no confiar en esta
   muestra" (`dt` muy chico, delta negativo).

Ninguna otra lógica de `process_stats()` cambió — mismo cálculo de tasa,
mismos campos devueltos, mismas exclusiones (`MITIGATION_DROP_PRIORITY`,
`exclude_flow`).

## Validación

`collectors/test_flow_collector.py` (3 pruebas nuevas, esta rama):

- `test_single_stat_per_key_computes_a_normal_rate`: el caso normal
  (una entrada por `key` por ciclo) sigue produciendo una tasa correcta.
- `test_duplicate_stat_for_same_key_in_one_body_never_diffs_against_itself`:
  **regresión directa del bug** — confirmado que esta prueba **falla**
  contra la versión del archivo anterior a este fix (`3e2610c`,
  reproducido explícitamente) y **pasa** contra la versión corregida.
- `test_duplicate_stat_rebaselines_on_the_larger_cumulative_count`:
  confirma que, tras la colisión, el ciclo siguiente calcula la tasa
  correcta desde el `prev_flows` re-baselineado.

Suite completa del repositorio (163 pruebas, excluyendo el
`ImportError` preexistente de Ryu/eventlet en
`controller/test_detection_log_lines.py`, no relacionado): **163
passed**.

## Hashes

- Archivo desplegado en el controlador (10.10.0.1,
  `/home/labadmin/orchestrator-ddos-pucp/collectors/flow_collector.py`,
  staged sin commitear al momento de la verificación):
  `9a7750ca2687ff50a8ba73b7a4ec5ed23dc6efddf4a6bf7e767f1cb6b385a90b`.
- Archivo en este repositorio tras este commit: idéntico,
  `9a7750ca2687ff50a8ba73b7a4ec5ed23dc6efddf4a6bf7e767f1cb6b385a90b`
  — se tomó el archivo REALMENTE desplegado como fuente, sin
  modificarlo, solo para dejarlo también en el repositorio.

## Supuestos

- No se tocó ningún otro comportamiento de `FlowCollector` — el único
  cambio de comportamiento real es que una colisión de claves dentro de
  un mismo ciclo ya no produce una tasa espuria; todo lo demás es
  exactamente el mismo código que ya corría en producción desde antes
  de esta verificación.
- No se investigó desde cuándo este fix está desplegado ni qué
  corridas de calibración anteriores pudieron verse afectadas por el
  bug (sin el fix) — está fuera del alcance de este prompt, que solo
  pide verificar y preservar el estado actual del laboratorio antes de
  recalibrar.
