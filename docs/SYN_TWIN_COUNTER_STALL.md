# La regla "twin" de SYN puede congelar su contador OpenFlow bajo una carrera real de OVS

## Origen

Encontrado durante `ATTACK_PLAN_V2_VALIDATION.md` (validación en vivo de la
composición 1 — `enterprise` — con las semillas de la calibración V2): el
agregado de `TCP_SYN` por dominio en `observed_rates` para `enterprise`
daba sistemáticamente ~0 pps durante varias corridas, pese a que
`attack_runner` confirmaba (`attack_pps_actual`, dentro de ±2% del
objetivo) que el flood SÍ se estaba enviando con normalidad.

## Diagnóstico (3 corridas de diagnóstico en vivo, pipeline suspendido)

1. **Confirmado que no es el bug de colisión de clave ya documentado**
   (`ENTERPRISE_FLOW_STATS_KEY_COLLISION.md`) — ese afecta a entradas
   duplicadas DENTRO de un mismo ciclo; acá hay una sola entrada por
   ciclo, consistentemente congelada.
2. **`ovs-ofctl -O OpenFlow13 dump-flows br-ent`** (lo que `FlowCollector`
   consulta) mostró la regla `priority=11` (la "twin", específica de SYN
   puro, `forwarding/syn_twin.py`) con `n_packets=2` **sin moverse en 3
   snapshots consecutivos** (duration 9.8s→12.1s→14.4s), mientras la
   regla `priority=10` (L3 general, mismo par src/dst) crecía con
   normalidad (20544→25344→30062 paquetes, ~5000/2.2s).
3. **`ovs-appctl dpctl/dump-flows`** (la caché del datapath de *kernel*,
   una capa de contabilidad separada de la tabla OpenFlow) mostró que el
   tráfico SYN puro del mismo par SÍ se estaba viendo y contando
   correctamente a nivel de kernel: 807→2008→3216→4408→5614 paquetes en
   ~12s, ≈400 pps — exactamente la tasa real del ataque.
4. **Sondeo rápido (cada ~0,5-1s)** sobre una tercera instalación de la
   misma regla mostró el patrón completo: tras reinstalarse (duration
   reseteado a 0,25s), el contador OpenFlow **esta vez sí** creció con
   total normalidad y en línea recta (0→45→228→598→...→5721 paquetes en
   22s) — la MISMA regla, reinstalada, contó perfectamente la segunda
   vez.

## Causa real

No es un bug determinista de lógica en `forwarding/learning_switch.py` —
es una **carrera intermitente, a nivel de OVS, entre el `flow_mod` que
instala la regla y los primeros paquetes que llegan casi
simultáneamente**: el datapath de kernel puede cachear una decisión de
clasificación tomada justo antes (o durante) de que el nuevo `flow_mod`
tome efecto, y servir todo el tráfico siguiente de ese 5-tupla desde esa
caché sin volver a consultar la tabla OpenFlow actualizada — dejando el
contador a nivel OpenFlow congelado en lo que sea que contara antes de
que la caché del kernel "se desconectara", mientras el kernel sigue
contando por su cuenta, en una estructura separada que nunca se
re-sincroniza con el contador de la regla OpenFlow mientras esa caché siga
vigente.

Confirmado que es **probabilístico, no determinista**: de 3 instalaciones
de la misma regla observadas en vivo, 2 se congelaron y 1 contó con
normalidad — ningún cambio de código entre medio.

## Por qué no se corrige en `forwarding/learning_switch.py` ni en OVS

Arreglar la carrera de verdad requeriría tocar la configuración del
demonio OVS en `pe` (p. ej. el intervalo del *revalidator* que resincroniza
las cachés de kernel con la tabla OpenFlow) — infraestructura, no lógica
de la aplicación, y fuera del alcance de este prompt (que prohíbe tocar
detección/decisión/mitigación salvo pedido explícito, y esto ni siquiera
es eso). `learning_switch.py` ya hace lo correcto (instala la regla de
mayor prioridad para contar SYN puro por separado); la carrera ocurre
*después* de que el `flow_mod` ya se envió correctamente.

## Mitigación aplicada (instrumentación, no cambia detección ni decisión)

`collectors/flow_collector.py`: cuando una entrada de la regla twin
(`syn_only`, `priority == SYN_TWIN_PRIORITY`) muestra **cero crecimiento
de paquetes durante `SYN_TWIN_STUCK_STREAK_THRESHOLD` (2) ciclos
consecutivos**, confirmado que es la **misma instancia de flujo** (su
propio `duration_sec` reportado por OVS creció, en vez de resetearse
cerca de 0 — lo que indicaría una reinstalación legítima, no un
atascamiento), el collector **deja de reportar una muestra para esa clave**
en vez de reportar con confianza una tasa de 0 pps que puede ser
simplemente incorrecta. Una sola muestra en 0 (el primer ciclo quieto)
sigue reportándose normalmente — es el comportamiento rutinario esperado
si el ataque hace una pausa real, no algo que descartar.

Solo afecta la extracción pura de la tasa (`collectors/flow_collector.py`,
usado por `telemetry/openflow_adapter.py` → `detection/engine.py`'s
`observed_benign_rates()`/`_classify()` reciben exactamente los mismos
eventos de antes, ninguno descartado que antes se contara bien) — **nunca
toca `_classify()`, `_mobile_kpm_signal()` ni ninguna decisión**: cuando
el contador SÍ crece con normalidad (la mayoría de las instalaciones,
según lo observado), el comportamiento es idéntico al de antes. 5 pruebas
nuevas en `collectors/test_flow_collector.py` (9/9 en total, archivo
completo). Suite completa: 172 passed.

## Impacto en la validación de ATTACK_PLAN_V2

El agregado de `enterprise` en `observed_rates` queda, a partir de este
fix, **ausente (sin muestra)** en vez de **presente mal (0 pps)** durante
los tramos afectados por la carrera — una mejora honesta, pero el
problema de fondo (la carrera de OVS) sigue sin resolverse: una corrida
afectada seguirá teniendo menos muestras de `enterprise` que `fixed`/
`mobile` durante la ventana de ataque. La validación de
`ATTACK_PLAN_V2_VALIDATION.md` para `enterprise` debe interpretarse con
esta limitación en mente — no es un problema del plan de ataque ni del
umbral calibrado, es una limitación conocida de la telemetría SYN de
`enterprise` bajo esta versión/configuración de OVS.

## Supuestos

- No se intentó reproducir ni cuantificar con qué frecuencia ocurre la
  carrera en condiciones distintas (tasas de ataque más bajas, menos
  fuentes concurrentes) — las 3 observaciones en vivo de este documento
  son la única evidencia disponible.
- `SYN_TWIN_STUCK_STREAK_THRESHOLD = 2` es un valor conservador elegido
  para no descartar una pausa real de 1 ciclo del propio plan de ataque;
  no se validó un valor óptimo distinto.
- La regla L3 general (`priority=10`) nunca mostró este problema en las
  observaciones — la mitigación se limita a flujos `syn_only` a propósito,
  consistente con la evidencia.
