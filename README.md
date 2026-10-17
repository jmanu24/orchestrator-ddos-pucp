# Orchestrator DDoS PUCP

Repositorio independiente del IDS/IPS multidominio del laboratorio DDoS PUCP.

## Flujo operativo

```text
OpenFlow / KPM / BNG-IPoE / BGP
              |
          telemetry
              |
         detection
              |
        correlation
              |
          decision
              |
       orchestration
              |
OpenFlow mitigation / BGP mitigation
```

`controller/ryu_controller_2.py` integra el ciclo de control Ryu. `orchestration/controller.py` aplica las decisiones, registra acciones y coordina su liberación. La configuración se mantiene en `config/settings.py` y el modo de referencia en `config/baseline.py`.

## Módulos

- `telemetry/`: adapta fuentes Mobile, Fixed, OpenFlow y Peering.
- `collectors/`: extrae contadores y flujos de red.
- `detection/`, `correlation/`, `decision/`: convierten telemetría en decisiones.
- `mitigation/`: ejecuta acciones OpenFlow y BGP.
- `oran_bridge/`: puente KPM/RC para O-RAN.
- `simulation/`: API y agente BNG/IPoE requeridos por el dominio Fixed.
- `core/`: modelos, registro y auditoría reproducible.

## Entorno

El controlador Ryu se instala antes de las dependencias generales:

```bash
pip install 'ryu @ git+https://github.com/faucetsdn/ryu.git@d6cda4f427ff8de82b94c58aa826824a106014c2'
pip install -r requirements.txt
```

Luego se ejecutan las pruebas relevantes con `pytest`. La plataforma `benign-lab` permanece fuera de este repositorio: genera experimentos y evalúa resultados, mientras que este proyecto contiene el IDS/IPS.
