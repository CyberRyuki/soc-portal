# Endurecimiento y puesta en producción

## Antes de producción
- [ ] Cambiar las contraseñas por defecto de MISP; `SHUFFLE_ENCRYPTION_MODIFIER` generado con `openssl rand -hex 32` (no cambiarlo después); confirmar que el Wazuh existente no usa las de fábrica.
- [ ] Certificados TLS internos válidos para Wiki.js, MISP, Shuffle y Wazuh; activar `*_VERIFY_TLS=true`.
- [ ] Reverse proxy (nginx/Traefik) con HTTPS delante de Wiki.js y Shuffle (3001); restringir el acceso a 3001 a la red del SOC y a la IP del servidor Wazuh.
- [ ] Firewall: aplicar solo las reglas de la tabla del README §1 (Wazuh→portal 3001,8443; portal→Wazuh 55000,9200).
- [ ] `soc-bridge` publicado únicamente en 127.0.0.1 (ya configurado).
- [ ] SSO (LDAP/AD o OIDC) en Wiki.js; grupo *SOC* con lectura de `soc/*` y grupo *SOC-Admin* con escritura.
- [ ] Token de Wiki.js para el bridge limitado a un grupo con `write:pages` solo sobre `soc/estado` y `soc/inventario` (Page Rules).
- [ ] Cuentas de servicio de solo lectura en MISP y un usuario Wazuh API con rol `readonly`.
- [ ] Shuffle monta `docker.sock` (equivale a root en el host): idealmente en una **VM dedicada**; restringir acceso a la UI, activar MFA y no instalar apps no revisadas.
- [ ] Fijar `SHUFFLE_REF`/`SHUFFLE_IMAGE_TAG`; probar cada actualización en laboratorio y exportar workflows antes de actualizar.
- [ ] El webhook de Shuffle no exige autenticación: mantener el ID en secreto y limitar el puerto 3001 por firewall.

## Copias de seguridad
| Componente | Qué respaldar |
|---|---|
| Wiki.js | Volumen `wiki-db-data` (`pg_dump`) o módulo *Storage → Git* |
| MISP | `misp-db-data` (`mysqldump`), `misp-files`, `misp-configs` |
| Shuffle | Workflows exportados (JSON en Git) + `shuffle/shuffle-core/shuffle-database` y `.env` |
| Wazuh (servidor existente) | `ossec.conf` (y `.bak-*`), `/var/ossec/etc/rules`, `/var/ossec/integrations/custom-misp.py` |

## Recuperación
Probar restauración trimestralmente en un entorno separado y documentarlo en la Wiki.
