# Orchestrator DDoS PUCP

IDS/IPS multidominio del laboratorio DDoS PUCP. Recoge telemetría de cuatro dominios de red (Enterprise/OpenFlow, Mobile, Broadband y BGP Peering), la correlaciona por destino, detecta ataques DDoS, decide y aplica la mitigación en el dominio que corresponda.

La plataforma `benign-lab` permanece fuera de este repositorio: genera experimentos y evalúa resultados, mientras que este proyecto contiene únicamente el IDS/IPS.

## Dominios y mitigación

| Dominio (`TelemetryEvent.domain`) | Fuente de telemetría | Mitigación |
|---|---|---|
| `enterprise` (SDN/OpenFlow) | Contadores de flujos y packet-in del switch vía Ryu (`telemetry/openflow_adapter.py`) | Reglas *drop* OpenFlow de alta prioridad (`mitigation/openflow_mitigator.py`) |
| `mobile` (5G) | API de sidecar en `core5g` (`oran_bridge/ue_telemetry_api.py`) + KPM de O-RAN SC RIC (`oran_bridge/kpm_bridge_xapp.py`) | Estrangulamiento del UE vía E2SM-RC (`oran_bridge/rc_actuator_xapp.py`) |
| `broadband` (BNG/IPoE) | API de sidecar en `bng` basada en `conntrack` (`simulation/bng_flow_api.py`) | Parada de sesión del suscriptor en el BNG |
| `bgp` (External Peering) | Registros IPFIX (`softflowd` → `nfcapd` → `nfdump`) en `collectors/peering_flow_collector.py` | Ruta BGP FlowSpec *discard* vía `exabgp` hacia `flow` (`mitigation/peering_backend.py`) |

## Flujo operativo

```text
OpenFlow / KPM / BNG-IPoE / BGP
              |
          telemetry        -> TelemetryEvent (core/models.py)
              |
        correlation        -> CorrelatedEvent (agrupa por IP destino)
              |
         detection         -> DetectionResult
              |
          decision         -> Decision (puntaje ponderado vs. umbral)
              |
       orchestration       -> MitigationAction
              |
OpenFlow / Mobile RC / BNG / BGP FlowSpec
```

- **Telemetría** (`telemetry/`): un adaptador por dominio (`DomainAdapter`) normaliza todo a `TelemetryEvent` (pps, bps, protocolo, flags, y para mobile `imsi`/`kpm`).
- **Correlación** (`correlation/correlator.py`): agrupa eventos de todos los dominios por IP destino. Con `DETECTION_CROSS_DOMAIN_CORRELATION=false` cada dominio se analiza aislado (línea base A/B para medir el aporte de la correlación).
- **Detección** (`detection/engine.py`): umbrales por protocolo (`SYN_THRESHOLD`, `UDP_THRESHOLD`, `ICMP_THRESHOLD`), detección de ataques distribuidos (fuentes mínimas, entropía de Shannon, pps agregado), umbrales KPM para mobile y ventanas de activación por dominio. Un refuerzo multidominio sube la confianza cuando varios dominios reportan tráfico hacia el mismo destino.
- **Decisión** (`decision/engine.py`): el puntaje (pps / umbral) se pondera por tipo de ataque (`SYN_FLOOD` 1.0, `UDP_FLOOD` 0.9, `ICMP_FLOOD` 0.8, `DDOS_DISTRIBUTED` 1.3, `MULTIDOMAIN_DISTRIBUTED_ATTACK` 1.4) y se compara con `DECISION_THRESHOLD`.
- **Orquestación** (`orchestration/controller.py`): traduce decisiones a acciones (`block`, `rate_limit`, `bgp_flowspec_discard`), las despacha al dominio, publica los bloqueos activos en `ACTIVE_BLOCKS_STATE_PATH` y los libera con histéresis (contadores de reglas en OpenFlow, tiempos de silencio en Broadband y BGP).
- **Controlador Ryu** (`controller/ryu_controller_2.py`): ejecuta el ciclo completo recolectar → correlacionar → detectar → decidir → mitigar cada `COLLECT_INTERVAL` (0.5 s). Incluye el reenvío (`forwarding/learning_switch.py`, con reglas "SYN twin" para medir SYNs por flujo).

## Estructura del repositorio

```text
config/         settings.py (umbrales, puertos, IPs del laboratorio), baseline.py (modo línea base)
core/           modelos de datos, formato de logs, auditoría experimental
telemetry/      adaptadores por dominio: openflow, mobile, broadband, bgp
collectors/     contadores de flujos, packet-in y registros IPFIX/NetFlow
correlation/    correlador multidominio
detection/      motor de detección
decision/       motor de decisión
orchestration/  controlador de orquestación y ciclo de vida de bloqueos
mitigation/     backends OpenFlow y BGP FlowSpec
forwarding/     learning switch L3 y reglas SYN twin
controller/     aplicación Ryu que integra el pipeline
oran_bridge/    xApps KPM/RC y API de telemetría de UE (se ejecutan en el RIC / core5g)
simulation/     API de flujos BNG, agente de suscriptores y generador de inundaciones
docs/           peering-plan.md (FlowSpec con `flow`), ran-testing.md (pila RAN/KPM)
tests/          pruebas de peering asíncrono
```

Las pruebas unitarias (`test_*.py`) conviven con el módulo que verifican.

## Configuración

Casi toda la configuración vive en `config/settings.py` como constantes; las direcciones de la topología VM (BNG, `br`, RIC, `core5g`) son las del laboratorio. Variables de entorno:

| Variable | Por defecto | Efecto |
|---|---|---|
| `DETECTION_CROSS_DOMAIN_CORRELATION` | `true` | `false` = detección aislada por dominio (se aplica al reiniciar `ryu-manager`) |
| `LAB_CALIBRATION_MODE` | `false` | Modo temporal de medición de laboratorio |
| `LAB_AUDIT_ENABLED` | `false` | Emite registros estructurados de evidencia experimental (`core/experiment_audit.py`), incluyendo hash de umbrales e implementación |

**Modo baseline:** `config/baseline.py` lee un lease temporal en `/run/benign-baseline/lease.json`. Mientras esté vigente, el controlador libera los bloqueos activos y suspende la mitigación; al expirar se reanuda el pipeline normal. El estado se reporta en `/run/benign-baseline/status.json`.

## Entorno

Python 3.10. El controlador Ryu se instala antes de las dependencias generales (el orden importa por el pin obsoleto de `eventlet` en `faucetsdn/ryu`; ver comentarios en `requirements.txt`):

```bash
pip install 'ryu @ git+https://github.com/faucetsdn/ryu.git@d6cda4f427ff8de82b94c58aa826824a106014c2'
pip install -r requirements.txt
```

Dependencias del laboratorio fuera de pip: `nfdump`/`nfcapd` y `softflowd` (telemetría de peering), `exabgp` y `flow` (FlowSpec), `conntrack` y `accel-ppp` en el BNG, y el O-RAN SC RIC para las xApps de `oran_bridge/`.

## Ejecución

```bash
ryu-manager controller/ryu_controller_2.py
```

Se ejecuta desde la raíz del repositorio. El proceso necesita acceso a las rutas `/run/ddos-controller/`, `/run/exabgp/exabgp.in` y `/var/cache/nfcapd/r1` según los dominios activos. Los servicios auxiliares corren en sus propias VMs: `simulation/bng_flow_api.py` en `bng`, `oran_bridge/ue_telemetry_api.py` en `core5g` y las xApps en el contenedor del RIC.

## Pruebas

```bash
pytest
```

Cubren detección (activación, persistencia, refuerzo multidominio, SYN en mobile), correlación, histéresis de liberación (BGP y Broadband), bloqueos activos, adaptadores de telemetría, SYN twin, auditoría y la API de flujos BNG.

## Documentación adicional

- [`docs/peering-plan.md`](docs/peering-plan.md): instrumentación del dominio BGP; FRR descartado, FlowSpec con `flow` validado.
- [`docs/ran-testing.md`](docs/ran-testing.md): pila srsRAN Project, conectividad de UE y telemetría E2SM-KPM.
