# LAB_AUDIT kind=cycle: observed_rates (Paso 1 de la calibración M)

## Por qué

Hasta ahora `LAB_AUDIT kind=detection` solo registraba una tasa cuando ya
había superado un umbral — calibrar umbrales nuevos con esos valores
sesga el resultado hacia arriba (todo lo que se observa ya es, por
definición, "suficientemente alto"). Para fijar umbrales a partir de la
distribución del tráfico benigno real hace falta la tasa agregada de
**cada** ciclo, haya o no cruzado ningún umbral.

## Qué se agregó

Cada registro `LAB_AUDIT kind=cycle` (`controller/ryu_controller_2.py`,
ambas ramas: `pipeline_active=true` y `pipeline_active=false` durante
calibración/baseline) ahora incluye `observed_rates`: una lista, una
entrada por grupo de correlación (`CorrelatedEvent`, es decir, por
`dst_ip` en modo M o por `(domain, dst_ip)` en modo I) con esta forma:

```json
{
  "dst_ip": "10.0.2.10",
  "domains": ["enterprise", "mobile"],
  "protocols": {
    "UDP": {
      "total_pps": 540.0,
      "non_mobile_pps": 40.0,
      "trigger_pps": 40.0,
      "by_domain": {"enterprise": 40.0, "mobile": 500.0}
    }
  }
}
```

- `total_pps`: suma de pps de ese protocolo, todos los dominios del grupo.
- `non_mobile_pps`: igual, excluyendo `mobile` — la misma exclusión que
  `detection/engine.py::DDoSDetectionEngine._classify()` ya aplica para
  UDP/ICMP (mobile es dirigido por KPM, no por pps de conntrack; ver el
  docstring de `_classify` para el razonamiento completo).
- `trigger_pps`: la tasa que el motor **realmente evalúa** contra el
  umbral de ese protocolo — `total_pps` para `TCP_SYN` (mobile SÍ cuenta
  ahí: un flood de SYN no satura el radio y el conteo de conntrack móvil
  es exacto, no subestimado), `non_mobile_pps` para `UDP`/`ICMP`. Es el
  valor que debe usarse para calibrar umbrales de esos dos protocolos.
- `by_domain`: desglose por dominio, sin exclusiones — para análisis por
  dominio (p. ej. umbrales independientes por dominio) y para la
  composición multidominio del Paso 4 del prompt de calibración.

Solo se reportan protocolos con al menos un evento en ese grupo; un grupo
sin eventos no genera entrada.

## Garantías (y cómo se probaron)

- **Observación pura, sin efectos secundarios.** `detection/engine.py`
  gana una función de módulo `observed_benign_rates(correlated)` y un
  método estático `DDoSDetectionEngine._protocol_rate()` — ambos son
  aritmética pura sobre la lista de `TelemetryEvent` ya correlacionados.
  Ninguno llama a `_classify()`, `_mobile_kpm_signal()` (que **sí** muta
  `_mobile_kpm_abuse_streak`, el contador de histéresis KPM por UE) ni
  `_activated()` (histéresis de activación). `_classify()` se refactorizó
  para llamar al mismo `_protocol_rate()` en vez de repetir la fórmula —
  mismo cálculo, una sola implementación, cero riesgo de que diverjan.
- **Nunca cambia detección ni decisión.** `detection/test_observed_
  benign_rates.py` prueba explícitamente que llamar
  `observed_benign_rates()` antes de (o entre) ciclos de `analyze()` deja
  resultados y estado de histéresis bit-a-bit idénticos a no llamarla
  nunca — incluida la histéresis de activación de `enterprise` a lo
  largo de varios ciclos (`test_calling_observed_benign_rates_never_
  changes_detection_output`) y el contador KPM móvil
  (`test_does_not_touch_mobile_kpm_abuse_streak`).
- **Mismo valor que evalúa el detector.** `test_matches_classifys_own_
  trigger_pps_below_threshold` confirma que `trigger_pps` reportado es
  exactamente el valor que `_classify()` comparó contra el umbral (no
  una aproximación recalculada por separado).

## Validación

`python3 -m pytest detection/ correlation/ controller/ orchestration/
telemetry/ forwarding/ -q` (excluyendo `controller/test_detection_log_
lines.py`, que falla por un `ImportError` de Ryu/eventlet preexistente en
este entorno, no relacionado con este cambio — confirmado con
`git stash`): **169 passed**, incluidas las 7 pruebas nuevas.

## Siguiente paso

Este documento cubre solo el Paso 1 (instrumentación, observación). Los
pasos 2-4 (medir capacidad de ataque alcanzable, ejecutar semillas de
calibración 101-110, y proponer/aplicar umbrales) requieren tocar el
laboratorio real y están pendientes de tu confirmación explícita —
ver el informe de la sesión.
