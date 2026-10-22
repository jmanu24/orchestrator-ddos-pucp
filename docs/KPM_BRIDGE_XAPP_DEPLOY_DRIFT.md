# `kpm_bridge_xapp.py` desplegado en el RIC tenía resiliencia real que el repositorio no tenía

## Origen

Encontrado durante la verificación de código desplegado (Prompt de
recalibración de umbrales V2, Paso 1): el archivo realmente corriendo en
el nodo RIC (10.10.0.4,
`/home/labadmin/oran-sc-ric/xApps/python/kpm_bridge_xapp.py`, dentro del
contenedor `python_xapp_runner`, puerto 8767) **no coincidía con ninguna
versión del historial de git** de este repositorio — ni la actual
(`HEAD`, tras la limpieza de referencias a FlexRIC) ni la original
(`c37f96b`, la extracción inicial). Mismo patrón que
`MOBILE_SYN_TELEMETRY_DEPLOY_DRIFT.md`: el desplegado no es simplemente
más viejo, tiene su propia mejora real que el repositorio nunca tuvo.

## Qué tenía el desplegado que el repositorio no tenía

1. **Estado de diagnóstico/salud** (`_State`): `last_indication_at`,
   `indications` (contador total), `last_error`, `nodes_seen` (último
   timestamp visto por nodo DU) y `resubscriptions` (contador por nodo)
   — ninguno existía en el repositorio. `connected`/`node_count` pasan de
   ser un booleano/entero fijo a derivarse de `nodes_seen` realmente
   frescos (`bool(fresh)`, `len(fresh)`), con `expected_node_count` y
   `complete` como campos nuevos para distinguir "conectado a algo" de
   "conectado a TODOS los DUs esperados".
2. **Re-suscripción automática a DUs que dejaron de reportar**: un bucle
   que, cada cierto intervalo, revisa qué nodos no han mandado una
   indicación KPM en los últimos ~30s y, si no se intentó hace menos de
   ~60s, cancela la suscripción vieja de ese nodo y vuelve a suscribirse
   — el repositorio se suscribía una sola vez al arrancar y nunca se
   recuperaba de una DU que dejara de reportar sin reiniciar el proceso
   entero.
3. **Manejo de errores en el callback de indicación** (`_callback`):
   el repositorio no envolvía nada en `try/except` — un nodo con un
   `e2_agent_id` no reconocido, una indicación sin `measData`, o un valor
   no numérico/no finito simplemente lanzaba una excepción no capturada
   dentro del callback de `xAppBase`. El desplegado captura, registra en
   `state.last_error` y por stdout, y sigue corriendo.
4. **Extracción de la métrica**: el repositorio tomaba `value[0]` (el
   primer elemento) de una lista de medición Style-1; el desplegado toma
   `value[-1]` (el último) — un cambio de comportamiento real, no solo
   resiliencia. También agrega `granul_period_ms`/`throughput_unit`/
   `time_base` al payload que expone `update()`.
5. **Normalización de `e2_agent_id`**: `.rstrip('\x00').strip()` antes de
   usarlo como clave — protección contra padding de bytes nulos que el
   repositorio no tenía.

## Por qué importa para este prompt

El Paso 4 de la recalibración pide "extender el replay para que incluya
[...] el camino KPM del móvil" — ese camino depende enteramente de este
archivo (es la única fuente del KPM que `oran_bridge/ue_telemetry_api.py`
en core5g consulta vía `GET /kpm`, puerto 8767). Si alguien hubiera
copiado la versión del repositorio sobre el desplegado antes de este
prompt, se habría **revertido** toda esta resiliencia en producción
(incluida la diferencia real de `value[0]` vs `value[-1]`) sin que
ninguna prueba lo detectara, porque el repositorio no tenía pruebas de
este archivo.

## Qué se hizo

**Solo documentar y traer el archivo realmente desplegado al
repositorio, sin modificarlo.** No se fusionó con la versión del
repositorio (a diferencia de `MOBILE_SYN_TELEMETRY_DEPLOY_DRIFT.md`,
donde sí había que agregar algo que faltaba) — el desplegado ya contiene
todo lo que el repositorio tenía (los dos únicos cambios del repositorio
sobre la versión original eran renombrar "FlexRIC" en dos comentarios,
que no afectan comportamiento) más las 5 mejoras de arriba. Se tomó el
archivo desplegado tal cual, byte a byte, como la nueva versión del
repositorio.

**No se ejecutaron pruebas nuevas sobre este archivo** — a diferencia de
`flow_collector.py` (Paso 1, mismo prompt), esto no es lógica de
detección/decisión pura y testeable sin infraestructura E2/RMR real
(depende de `xAppBase`, `e2sm_kpm`, el `docker exec` al runner); replicar
ese entorno está fuera del alcance de este prompt. La validación es que
el archivo coincide byte a byte con lo que ya corre en producción
(mismo hash), no una prueba unitaria nueva.

## Hashes

- Archivo desplegado en el RIC (10.10.0.4,
  `/home/labadmin/oran-sc-ric/xApps/python/kpm_bridge_xapp.py`):
  `34420a34472a41b8bfa50528d197c834ea8844c5d60e1ca89d428df4f79498e9`.
- Archivo en este repositorio tras este commit: idéntico,
  `34420a34472a41b8bfa50528d197c834ea8844c5d60e1ca89d428df4f79498e9`.
- Versión anterior del repositorio (HEAD antes de este commit, tras la
  limpieza de FlexRIC, solo wording):
  `1a72c194510bba486c66d061b446accc569b7cfbdbc39b20affdaafa08a3cd63`.

## Pendiente

- `rc_actuator_xapp.py` en el mismo RIC **sí** coincide exactamente con
  el repositorio (`3ce5030686b9c12bddef30e2e3d6d68cee1f57f29a6761ec42e
  d7fb11407f8`) — sin divergencia, no requiere acción.
- A partir de ahora, ambos (desplegado y repositorio) deberían
  mantenerse sincronizados manualmente — no hay git ni CI en el nodo RIC
  para esto, igual que ya documentaba `MOBILE_SYN_TELEMETRY_DEPLOY_
  DRIFT.md` para core5g.
