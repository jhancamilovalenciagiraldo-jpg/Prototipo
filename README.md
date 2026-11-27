# Detector de dispositivos en red local

Prototipo de código abierto que hace un inventario de los equipos conectados a
una red (Wi-Fi o cable) usando ARP. Funciona en Windows, Linux y macOS, **sin
instalar librerías** y **sin permisos de administrador**, desde un router
doméstico económico hasta una red de empresa.

## Qué hace

- Detecta sola la IP, la máscara real de la red (/24, /23, /22…) y el router.
- Consulta **todas** las IPs de la red en lotes y en varias rondas, y lee la
  tabla ARP para obtener la MAC de cada equipo.
- Ajusta la velocidad según el router (perfil `auto`, `baja`, `media` o `alta`).
- Escucha los anuncios de los equipos (**mDNS**, **SSDP/UPnP**) y pregunta
  nombres **NetBIOS**: encuentra equipos que no contestaron el ARP y obtiene su
  nombre real y su tipo probable (impresora, TV, iPhone, router...).
- Muestra el **fabricante** a partir de la lista oficial OUI de IEEE.
- Lee la **tabla de vecinos IPv6** de la interfaz de red correcta: confirma
  celulares que no contestaron el ARP y encuentra equipos que solo usan IPv6.
- **Modo validación:** se pega la lista de clientes del router y el programa
  calcula, MAC por MAC, el porcentaje real de detección (exportable a Excel).
- Identifica cada equipo por su **MAC**, así no se duplica cuando el router le
  cambia la IP; reconoce celulares con MAC rotativa y repetidores Wi-Fi.
- **Alertas de seguridad:** si la MAC del router cambia (posible suplantación
  ARP) o una MAC responde por varias IPs.
- Guarda un historial que solo registra **cambios**: nuevo, se desconectó,
  volvió, cambió de IP, dado de baja.
- Mantenimiento del historial: retención por días, tope de eventos, baja de
  equipos que ya no aparecen (con copia en `bajas.json`) y equipos protegidos.

## Uso rápido (desde el código fuente)

Al abrir el programa se inicia una **interfaz web local** y el navegador se abre
solo en `http://127.0.0.1:8765/`. Muestra un mapa de la red (un cuadro por cada
IP), la lista de equipos, el historial, el mantenimiento y la configuración.
La ventana negra que queda abierta es el servidor: al cerrarla (o con el botón
*Cerrar programa* de la página) el programa se detiene.

```bash
python lanzador.py              # interfaz web (se abre el navegador)
python lanzador.py --consola    # menú de texto clásico
python lanzador.py --sin-navegador --puerto 9000   # servidor sin abrir navegador
python lanzador.py --escanear   # un escaneo y termina (para tareas programadas)
python lanzador.py --listar     # muestra el inventario
python lanzador.py --escanear --perfil baja --red 192.168.0.0/22
python lanzador.py --actualizar-fabricantes   # descarga la lista oficial de IEEE
```

La primera vez se muestra un aviso de uso y privacidad que hay que aceptar.
Para instalaciones desatendidas: `--escanear --acepto-aviso`.

Códigos de salida: `0` bien, `1` error, `2` aviso no aceptado, `3` datos en uso
por otra instancia. Los escaneos quedan anotados en `registro.log`.

## Apariencia

El botón de la barra superior cambia entre **tema automático** (sigue la
configuración de Windows o del celular), **modo oscuro** y **modo claro**.
Cada navegador recuerda su elección.

## Seguridad

- Por defecto la interfaz **solo se abre desde el mismo PC** (127.0.0.1) y
  ahí no pide contraseña. Para un PC compartido, active *Pedir contraseña
  también en este PC* (Configuración). Si la olvida:
  `DetectorRed.exe --restablecer-clave`.
- El acceso desde el celular u otro PC es opcional (*Configuración → Acceso
  desde otros equipos*): exige contraseña fuerte (mínimo 10 caracteres,
  cifrada con PBKDF2 de 600 000 iteraciones), limita los intentos, cierra
  sesiones inactivas y admite **HTTPS**.
- Protegido contra CSRF, DNS rebinding, XSS (CSP con nonce), clickjacking,
  denegación de servicio (tiempo máximo por conexión y topes por equipo) y
  nombres maliciosos anunciados por la red.
- Respaldo automático antes de cada borrado y registro de auditoría en
  `registro.log`.
- Cada versión publicada trae la huella **SHA-256** de los ejecutables.

Modelo de amenazas completo, cómo activar HTTPS y cómo verificar el
ejecutable: [`docs/SEGURIDAD.md`](docs/SEGURIDAD.md). Para reportar una
vulnerabilidad: [`SECURITY.md`](SECURITY.md).

## Borrar datos

Pestaña **Mantenimiento** (o la opción 8 del menú de consola):

- **Borrar solo el historial:** los dispositivos guardados se conservan.
- **Borrar historial y dispositivos:** deja el programa como recién
  instalado. Con la casilla *Conservar los dispositivos protegidos* se
  mantienen los equipos marcados como protegidos.
- **Eliminar un dispositivo:** desde su panel en la pestaña Dispositivos.

Antes de cada borrado se guarda una copia en la carpeta `respaldos` (las 5
últimas por archivo).

## Armar el ejecutable desde la interfaz

Pestaña **Ejecutable**:

1. Si falta, *Instalar PyInstaller* (necesita internet).
2. *Armar ejecutable*: genera `dist/DetectorRed.exe` en Windows (o el
   binario de Linux/macOS en esos sistemas) y muestra su huella SHA-256.
3. *Descargar* y copiarlo al PC donde se vaya a usar.

Si Inno Setup está instalado, aparece también *Armar instalador*. Cuando el
programa ya se está usando como ejecutable, la pestaña ofrece descargar una
copia de sí mismo para instalarla en otro PC.

## Validar la precisión (para la investigación)

Pestaña **Validación**:

1. Escanee la red.
2. Abra la página del router, busque la lista de clientes DHCP o dispositivos
   conectados y copie todo el texto.
3. Péguelo y presione *Comparar con el último escaneo*.

El programa extrae las MAC del texto y calcula la **exhaustividad**: cuántos
de los equipos del router encontró. También lista los que faltaron (para
analizar por qué) y los que vio de más (IP fija, el propio router...). Si el
router no muestra MAC, se puede escribir solo la cantidad (resultado
aproximado).

Cada escaneo además guarda sus estadísticas (perfil, pérdida y latencia del
router, equipos por ronda, respuestas mDNS/SSDP, IPv6). Las dos tablas se
descargan en CSV y se abren directamente en Excel: con ellas se calibran los
perfiles del router con datos reales.

## Firewall de Windows

El Firewall de Windows puede bloquear las respuestas mDNS, SSDP y NetBIOS.
Si después de escanear ningún equipo respondió a esos protocolos, el programa
lo avisa. Solución (una sola vez, como administrador):

```bat
DetectorRed.exe --configurar-firewall
```

La regla permite solo respuestas **UDP**, solo a **este programa** y solo en
redes **privadas**. Se quita con `--quitar-firewall`. El instalador la crea
automáticamente cuando se instala como administrador y la elimina al
desinstalar.

## Perfiles de router

| Perfil | Para | Consultas a la vez | Rondas |
|---|---|---|---|
| `baja` | router económico o red saturada | 24 | 3 |
| `media` | router doméstico normal | 64 | 2 |
| `alta` | router empresarial / mesh | 128 | 2 |
| `auto` | mide pérdida y latencia del router y elige | — | — |

Los valores se ajustan en `detector_red/config.py` (`PERFILES`).

## Dónde se guardan los datos

| Sistema | Carpeta |
|---|---|
| Windows | `%APPDATA%\DetectorRed` |
| Linux | `~/.local/share/DetectorRed` |
| macOS | `~/Library/Application Support/DetectorRed` |

- **Modo portable** (USB): cree una carpeta `datos` junto al programa y se
  usará esa.
- También se puede forzar con la variable de entorno `DETECTOR_RED_DATOS`.
- La primera vez se importan `inventario.json` e `historial.json` de la
  versión anterior si están en la carpeta actual.

## Instalación

### Opción 1 — Ejecutable de Windows (usuarios finales, sin Python)

```bat
instalador\construir_windows.bat
```

Genera `dist\DetectorRed.exe`. Ese único archivo se copia a cualquier PC con
Windows y funciona sin Python.

Para un instalador con asistente (menú Inicio, desinstalador), abra
`instalador\detector_red.iss` con [Inno Setup](https://jrsoftware.org/isinfo.php)
y presione *Compile*.

### Opción 2 — Con pip (usuarios con Python, cualquier sistema)

```bash
pip install .                         # desde la carpeta del proyecto
pip install git+https://github.com/USUARIO/detector-red.git   # desde GitHub
detector-red                          # el comando queda disponible
```

### Opción 3 — Automática con GitHub

El archivo `.github/workflows/compilar.yml` compila los ejecutables de
Windows, Linux y macOS, prueba que cada uno abra la interfaz y los adjunta a
la versión publicada:

1. En el repositorio, **Releases → Create a new release**.
2. En *Choose a tag*, escriba la versión (por ejemplo `v0.8.0`) y elija
   *Create new tag on publish*.
3. Ponga un título y presione **Publish release**.

En unos minutos los ejecutables y sus huellas `.sha256` aparecen en esa
versión, listos para descargar. Para compilar sin publicar: pestaña
**Actions → Compilar ejecutables → Run workflow** (los archivos quedan en el
resumen de esa ejecución).

## Escaneo periódico (empresas)

Windows (cada hora con el Programador de tareas):

```bat
schtasks /create /tn "DetectorRed" /sc hourly /tr "\"C:\ruta\DetectorRed.exe\" --escanear"
```

Linux (cron): `0 * * * * detector-red --escanear`

Si el menú y la tarea programada coinciden, no se pisan los datos: las
escrituras se protegen con un archivo de bloqueo.

Con `limpieza_automatica` activa, cada escaneo borra los eventos más viejos
que `retencion_historial_dias` y mantiene el historial por debajo de
`max_eventos_historial`.

## Límites conocidos

- **ARP solo ve la red local** (mismo segmento). Equipos en otra VLAN o
  subred no aparecen.
- **Aislamiento de clientes / AP isolation** (común en redes de invitados y en
  muchos routers empresariales): el router impide que los equipos Wi-Fi se
  vean entre sí. En ese caso solo se detectará el router.
- **Celulares dormidos**: en ahorro de energía pueden no responder; por eso
  hay varias rondas. Un escaneo cada cierto tiempo los termina detectando.
- **MAC aleatoria** (dirección privada de Android/iPhone): el celular puede
  cambiar de MAC y aparecer como equipo nuevo. Se marcan con `*` y se dan de
  baja antes (`dias_para_baja_mac_aleatoria`).

## Justificación técnica

Por qué se eligió cada protocolo, su viabilidad a largo plazo con fuentes
oficiales y la lista de falencias corregidas: ver
[`docs/JUSTIFICACION.md`](docs/JUSTIFICACION.md).

## Pruebas

```bash
python -m unittest discover tests -v
```

## Estructura

```
detector_red/
  config.py          perfiles y opciones por defecto, carpeta de datos
  escaner.py         detección de red, sondeo, lectura de tabla ARP
  descubrimiento.py  mDNS, SSDP y NetBIOS; tipo probable del equipo
  fabricantes.py     fabricante por OUI (lista oficial IEEE)
  validacion.py      comparación contra la lista del router y CSV
  empaquetado.py     armado del ejecutable y del instalador desde la interfaz
  inventario.py      actualizar inventario, eventos, búsquedas
  mantenimiento.py   limpieza del historial y bajas
  almacenamiento.py  lectura/escritura segura de JSON
  servicio.py        escaneo completo (lo usan la web y la consola)
  web.py             servidor web local y API
  web/index.html     la página de la interfaz
  main.py            menú de consola y línea de comandos
lanzador.py          punto de entrada (y el que usa PyInstaller)
instalador/          script del .exe, instalador de Windows y sumas SHA-256
tests/               pruebas automáticas
```

## Licencia

MIT — ver `LICENSE`.
