# Seguridad del Detector de dispositivos (v0.7.0)

Este documento describe **de qué se protege el programa, cómo y qué queda
fuera de su alcance**. Está pensado para quien lo instala en una empresa y
para quien revise el código.

## 1. Qué se protege

| Activo | Por qué importa |
|---|---|
| Inventario e historial (IP, MAC, nombres) | Revelan qué equipos tiene la red y cuándo se usan; en una empresa pueden ser datos personales (Ley 1581 de 2012) |
| La interfaz web | Desde ella se puede borrar el historial, dar de baja equipos y cambiar la configuración |
| La contraseña de acceso remoto | Da acceso a todo lo anterior desde otros equipos |
| El propio PC | El programa no debe convertirse en una puerta de entrada |

## 2. Atacantes considerados

1. **Una página web maliciosa** abierta en el navegador del mismo PC, que
   intenta enviar órdenes al Detector (CSRF, DNS rebinding).
2. **Un equipo de la misma red local** que intenta entrar a la interfaz,
   adivinar la contraseña, saturar el servidor o espiar el tráfico.
3. **Un equipo que se anuncia con datos maliciosos** por mDNS, SSDP o NetBIOS
   (nombres con código, millones de anuncios falsos).
4. **Un archivo de datos alterado** a mano o dañado.
5. **Un ejecutable falsificado** distribuido haciéndose pasar por el original.

**Fuera de alcance:** alguien que ya controla el PC con permisos de
administrador. Esa persona puede leer o modificar cualquier archivo del
equipo, y ningún programa común puede impedirlo.

## 3. Controles implementados

### Acceso a la interfaz
- **Solo local por defecto:** el servidor escucha en `127.0.0.1`; ningún otro
  equipo puede conectarse. En el propio PC no se pide contraseña, salvo que
  se active *Pedir contraseña también en este PC* (pensado para PC
  compartidos). Esa opción protege la interfaz, no los archivos: quien use
  la misma cuenta de Windows puede abrir la carpeta de datos o ejecutar
  `--restablecer-clave`, que borra la contraseña si se olvidó.
- **Acceso remoto opcional** y siempre con contraseña:
  - Contraseña cifrada con **PBKDF2-HMAC-SHA256, 600 000 iteraciones** y sal
    aleatoria (recomendación vigente de OWASP). Las contraseñas de versiones
    anteriores (200 000 iteraciones) se vuelven a cifrar solas al iniciar
    sesión.
  - **Política de contraseña:** mínimo 10 caracteres, no solo números, no
    repetitiva y no incluida en una lista de contraseñas comunes.
  - **Límite de intentos:** 10 fallidos por IP y 30 en total cada 10 minutos
    (este último frena a un atacante que pruebe desde varias IP), con 1
    segundo de espera por intento fallido.
  - **Sesiones:** cookie `HttpOnly`, `SameSite=Strict` y `Secure` (con
    HTTPS); se cierran tras 30 minutos sin uso o 12 horas en total; botón
    *Cerrar sesión*; cambiar la contraseña cierra todas las sesiones.
  - Un equipo remoto **no puede** cambiar la seguridad, ni la contraseña, ni
    cerrar el programa.
- **HTTPS opcional** (sección 5) con TLS 1.2 como mínimo y HSTS. Si el acceso
  remoto está activo sin HTTPS, la página muestra una advertencia permanente.

### Ataques desde el navegador
- **CSRF:** toda acción exige la cabecera `X-Token` con un valor aleatorio
  por ejecución que solo conoce la página servida, y el cuerpo debe ser
  `application/json` (un formulario HTML de otro sitio no puede enviarlo).
- **DNS rebinding:** desde el propio PC solo se aceptan peticiones dirigidas
  a `127.0.0.1` o `localhost`.
- **XSS:** la página inserta todos los datos con `textContent`, nunca como
  HTML. Además, la **CSP con nonce** solo deja ejecutar el script de la
  propia página: aunque se lograra inyectar código, el navegador lo
  bloquearía. Verificado renombrando un equipo con
  `<img src=x onerror=...>`: se muestra como texto y no se ejecuta.
- **Cabeceras:** `X-Frame-Options: DENY` y `frame-ancestors 'none'` (contra
  clickjacking), `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
  `Permissions-Policy` (sin cámara, micrófono ni ubicación),
  `Cross-Origin-Opener-Policy` y `Cross-Origin-Resource-Policy`.

### Denegación de servicio
- **Tiempo máximo de 15 s por conexión** inactiva (ataque *slowloris*).
- **Máximo 32 peticiones simultáneas** y **6 por cada equipo remoto**: un
  equipo de la red que abra cientos de conexiones recibe "503" y el usuario
  del PC sigue atendido.
- **Content-Length estricto:** valores negativos, no numéricos o mayores de
  100 KB se rechazan al instante. *(Antes, un valor negativo dejaba un hilo
  del servidor colgado para siempre; era una vulnerabilidad real, corregida
  en esta versión.)*

### Datos que llegan de la red
- **Saneamiento de textos:** a los nombres anunciados por mDNS, NetBIOS, DNS
  y SSDP se les quitan los caracteres de control (códigos de escape que
  alteran la terminal), los invisibles y los de dirección de texto (U+202E,
  usado para disfrazar nombres), y se limita su largo.
- **Nombres de servicio** validados con el formato de la RFC 6335.
- **Topes** por equipo en servicios, instancias y tipos anunciados, para que
  un equipo no pueda llenar la memoria con anuncios falsos.
- El analizador DNS detecta bucles de punteros y paquetes cortados.

### Datos guardados
- Escritura **atómica** (no quedan archivos a medio escribir).
- **Bloqueo** para que dos instancias no se pisen.
- En Linux/macOS los archivos son legibles **solo por el dueño** (permisos
  600); en Windows viven en `%APPDATA%`, privado por usuario.
- **Validación de tipos al cargar:** un archivo alterado a mano (IP que no es
  texto, listas que no son listas, fechas falsas) no rompe el programa.
- **Respaldo automático** antes de cada borrado manual (historial, bajas) en
  la carpeta `respaldos/`; se conservan las 5 últimas copias.
- Las **exportaciones CSV** neutralizan la inyección de fórmulas de Excel
  (celdas que empiezan con `=`, `+`, `-`, `@`).
- La descarga de la lista de fabricantes usa solo HTTPS con verificación de
  certificado y tiene un tope de 30 MB.

### Auditoría
Todo queda en `registro.log`, con la IP de quien lo hizo: inicios de sesión
(correctos, fallidos y bloqueados), cierres de sesión, cambios de
configuración y de contraseña, activación del acceso remoto, borrados del
historial, bajas y cierre del programa.

### Distribución
- **Sin dependencias externas:** solo la librería estándar de Python. No hay
  paquetes de terceros que puedan venir comprometidos.
- **Sin actualizaciones automáticas:** no hay un canal de actualización que
  un atacante pueda suplantar.
- **No requiere permisos de administrador** (salvo para crear la regla del
  firewall, una sola vez).
- Cada versión publicada incluye la **huella SHA-256** de cada ejecutable
  (sección 6).
- La compilación en GitHub corre con permisos mínimos (solo lectura, excepto
  el paso que publica).

## 4. Riesgos que quedan (y qué hacer)

| Riesgo | Mitigación disponible |
|---|---|
| Acceso remoto sin HTTPS: en una red compartida, alguien que espíe el tráfico podría ver la contraseña | Configurar HTTPS (sección 5) o usar el acceso remoto solo en redes de confianza |
| Certificado autofirmado: el navegador muestra una advertencia la primera vez | Instalar el certificado como de confianza en los equipos que acceden, o usar `mkcert` |
| Un equipo de la red puede saturar sus propios 6 cupos | Solo se afecta a sí mismo; el resto sigue funcionando |
| El ejecutable no está firmado digitalmente | Verificar la huella SHA-256; la firma queda para la salida al mercado |
| Alguien con administrador en el PC | Fuera de alcance de cualquier aplicación |

## 5. Activar HTTPS para el acceso remoto

Se necesita un certificado y su clave en formato `.pem`.

**Opción A — `mkcert`** (herramienta libre, crea certificados de confianza
local; ver su documentación oficial para instalarla):

```bash
mkcert -install
mkcert -cert-file cert.pem -key-file clave.pem 192.168.1.21 localhost 127.0.0.1
```

**Opción B — OpenSSL** (incluido, por ejemplo, con Git para Windows):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout clave.pem -out cert.pem -days 825 \
  -subj "/CN=detector-red" -addext "subjectAltName=IP:192.168.1.21,IP:127.0.0.1"
```

Cambie `192.168.1.21` por la IP del PC donde corre el Detector. Luego, en
`config.json` (carpeta de datos):

```json
"web_certificado": "C:\\ruta\\cert.pem",
"web_clave_tls": "C:\\ruta\\clave.pem"
```

Al reiniciar, la interfaz abre en `https://`. Proteja `clave.pem`: quien la
tenga puede suplantar al servidor.

## 6. Verificar que el ejecutable es original

Junto a cada versión publicada hay un archivo `.sha256`. Compare:

```bat
certutil -hashfile DetectorRed-Windows.exe SHA256
```

```bash
sha256sum -c DetectorRed-Linux.sha256
```

Si el valor no coincide, **no ejecute el archivo**.

## 7. Pruebas de seguridad

`tests/test_basico.py` incluye pruebas automáticas de: Content-Length
negativo, tipo de contenido obligatorio, CSP con nonce, cierre de
conexiones inactivas, política de contraseña, migración de contraseñas
antiguas, expiración y cierre de sesiones, límite global de intentos,
saneamiento de nombres, inyección de fórmulas en CSV, archivos alterados y
respaldos. Además se ejecutaron ataques manuales (slowloris, inundación
desde la red, fuerza bruta de contraseña, CSRF, DNS rebinding, XSS) antes y
después de los cambios.

## 8. Reportar una vulnerabilidad

Ver `SECURITY.md` en la raíz del proyecto.
