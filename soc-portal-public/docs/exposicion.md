# Exposición y Shadow IT (v20)

Módulo **Exposición** del portal SOC: mide la superficie de ataque de ACME vista desde Internet y encuentra
lo que está publicado **sin estar en el inventario** (Shadow IT).

## Qué hace

| Fase | Pasivo | Activo |
|---|---|---|
| Subdominios en certificados públicos (crt.sh) | ✔ | ✔ |
| Resolución DNS y comparación con el inventario de Portales | ✔ | ✔ |
| Puertos y CVE conocidos según Shodan InternetDB (sin tocar los servidores) | ✔ | ✔ |
| Escaneo TCP de los rangos de IP propios (perfil estándar / amplio / completo) | — | ✔ |
| Banners, versión de software, certificado TLS de cada servicio | — | ✔ |
| Rutas sensibles en los servicios web (`/.git/HEAD`, `/.env`, backups, phpinfo, actuator, phpMyAdmin…) | — | ✔ |

Los resultados se clasifican como **hallazgos** (crítica / alta / media / baja) y **activos**:

- **Shadow IT**: subdominio o IP dentro del alcance que responde y no corresponde a ningún portal inventariado.
  Desde la pestaña *Shadow IT* se puede **añadir a Portales** (grupo «Shadow IT», queda vigilado contra desfiguración),
  **marcar como conocido** o **ignorar**.
- Los hallazgos críticos generan una **sugerencia de incidente** (no se crea solo: un analista la confirma).
- Un hallazgo que no vuelve a aparecer en el siguiente escaneo se marca como corregido automáticamente.

## Salvaguardas

- Solo se escanea lo definido en **Exposición › Alcance** (dominios raíz y rangos CIDR). Cada IP se comprueba dos veces
  contra el alcance y las exclusiones antes de conectarse.
- Máximo 65 536 direcciones (/16). Rangos privados rechazados (salvo `EXPOSURE_ALLOW_PRIVATE` en laboratorio).
- El **escaneo activo** exige una autorización registrada (quién autoriza, referencia del documento y fecha de vigencia);
  vencida la fecha, solo queda el pasivo. Solo un **administrador** puede cambiar el alcance y lanzar el activo.
- Ambos escaneos quedan en **Auditoría** (evento «Escaneo de exposición») con usuario, tipo y alcance.
- Un solo escaneo a la vez; se puede **detener** en cualquier momento.

## Perfiles y tiempos aproximados

Con la velocidad por defecto (400 conexiones/s):

| Perfil | Puertos | /24 (256 IP) | /23 (512 IP) |
|---|---|---|---|
| Estándar | ~70 puertos clave | < 1 min | ~1–2 min |
| Amplio | 1–1024 + comunes | ~11 min | ~23 min |
| Completo | 1–65 535 | ~12 h | ~23 h |

Recomendación: **estándar semanal** (Repetir cada 7 días) y **completo** solo puntualmente, fuera de horario.

## Antes del primer escaneo activo

1. Avisa al **equipo de red / NOC**: el FortiGate, el FortiWeb y Wazuh lo detectarán como escaneo de puertos.
   Si hace falta, añade la IP pública de salida del servidor SOC a una lista de excepción **solo durante la ventana**.
2. Si algún rango pertenece a un proveedor (hosting, nube), confirma que el contrato permite escanearlo.
3. Pon en *Excluir* los equipos frágiles (centralitas, SCADA, impresoras publicadas…).

## Integración con Portales (desfiguración)

Además de la comparación de texto y de la captura visual, cada portal se vigila ahora en:

- Redirección a otro dominio, aparición de un formulario de contraseña (phishing).
- Cabeceras de seguridad retiradas (HSTS, CSP…), cambio de servidor web o nuevo `X-Powered-By`.
- Certificado que pasa a autofirmado o cambia de emisor.
- **IP del dominio fuera de los rangos de ACME** → posible secuestro de DNS (usa el alcance de este módulo).
- Huella sha256 de los `.js`/`.css` propios: un script modificado sin despliegue general → sospecha de inyección.
