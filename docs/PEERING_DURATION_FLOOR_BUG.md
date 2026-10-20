# Bug de piso de duración en el colector de peering (encontrado 2026-10-20)

## Síntoma

Durante la calibración de umbrales (Paso 1 instrumentó `observed_rates`
por ciclo), los ciclos benignos de `peering`/`bgp` mostraban tasas
agregadas absurdas: hasta **~29 000 "pps" de SYN**, ~9 700 de UDP y
~172 de ICMP — órdenes de magnitud por encima de lo que cualquier otro
dominio (`enterprise`, `fixed`, `mobile`) mostraba, y por encima incluso
de la capacidad de ataque real medida con `attack_runner` para ese mismo
dominio (~15 000 pps SYN, Paso 2 de la calibración).

## Causa raíz

`collectors/peering_flow_collector.py::PeeringFlowCollector._parse_csv()`
calculaba `pps = packets / duration_s` por cada registro NetFlow
individual, con `duration_s = max(nfdump_td, 0.001)`. `nfdump_td` es la
duración que el propio `nfdump` reporta para ESE flujo — para un flujo
corto (p. ej. un solo SYN, 1-3 paquetes), `td` suele venir como `0.000`.
Con el piso de 1 ms, un solo paquete se convertía en `pps≈1000`.

`telemetry/bgp_adapter.py` pasa ese `pps` directo a un `TelemetryEvent`
sin reagregar, y `correlation/correlator.py` +
`detection/engine.py::_classify()` **suman** el `pps` de todos los
eventos del ciclo. Varios flujos cortos benignos ordinarios dentro de un
mismo ciclo (algo normal en tráfico TCP real) sumaban a decenas de
miles de "pps" aparentes.

## Corrección

El piso ahora es `settings.COLLECT_INTERVAL` (0.5 s en este despliegue
— la granularidad real de muestreo del pipeline), no 1 ms arbitrario:
un paquete solitario contribuye como máximo
`paquetes/COLLECT_INTERVAL` a la tasa agregada de un ciclo, consistente
con la frecuencia real con que este pipeline observa el tráfico. Un
flujo cuya propia duración ya supera `COLLECT_INTERVAL` queda intacto
(el `max()` solo actúa en el caso de duración sospechosamente corta que
causaba el bug).

Esto es telemetría/instrumentación (etapa 1, recolección), no lógica de
detección/decisión/mitigación — no cambia qué protocolos se clasifican
ni los umbrales, solo corrige una tasa de entrada mal calculada.

## Validación

`collectors/test_peering_flow_collector.py` (4 pruebas nuevas): un flujo
casi instantáneo ya no se infla a ~1000 pps; varios flujos cortos en un
ciclo ya no suman a decenas de miles; un flujo con duración real más
larga no se ve afectado; el caso límite (`td == COLLECT_INTERVAL`) usa
su propio valor. Suite completa del repositorio: 166 passed (sin
regresiones).

## Impacto en la calibración de umbrales

Las 5 corridas de entrenamiento en modo M (semillas 101-105) se
repitieron contra el controlador con esta corrección desplegada, para
obtener una distribución benigna de `peering`/`bgp` por fin utilizable
en el Paso 4 de la calibración de umbrales — ver
`traffic-generator-pucp/docs/THRESHOLD_CALIBRATION_RESULT.md`.
