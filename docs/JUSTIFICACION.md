# Justificación técnica — Detector de dispositivos v0.6.0

Este documento explica **por qué** se eligió cada técnica, qué tan viable es a
largo plazo y qué falencias tenía el prototipo con su corrección. Cada
afirmación sobre protocolos o sistemas operativos se apoya en una fuente
oficial (al final). Fecha de revisión: noviembre de 2026.

> Nota de honestidad: ninguna fuente puede garantizar el futuro. Lo que sí se
> puede asegurar es que cada técnica se apoya en un **estándar publicado** o en
> **documentación oficial del fabricante** vigente a la fecha, y se indica el
> nivel de certeza de cada conclusión.

---

## 1. Técnicas de detección y su viabilidad a largo plazo

| Técnica | Base | Viabilidad | Certeza |
|---|---|---|---|
| ARP | RFC 826 (1982), base de IPv4 en Ethernet/Wi-Fi | Alta mientras exista IPv4 en redes locales | Alta |
| mDNS / DNS-SD | RFC 6762 y RFC 6763 (IETF, Standards Track, 2013) | **Alta y creciente** | Alta |
| SSDP / UPnP | ISO/IEC 29341 (UPnP Device Architecture) | Media | Media |
| NetBIOS | RFC 1001/1002 (1987) | **Baja: en retirada** | Alta |
| Fabricante (OUI) | Registro público IEEE Registration Authority | Alta para MAC de fábrica, nula para MAC aleatorias | Alta |
| MAC como identificador | — | **En descenso** por la privacidad de los celulares | Alta |

### ARP
Toda comunicación IPv4 dentro de una misma red local necesita ARP para
traducir IP → MAC; por eso no depende de que el equipo "quiera" responder
ping. Es la técnica principal y seguirá funcionando mientras las redes locales
usen IPv4, que hoy es la norma en hogares y empresas (casi siempre en
convivencia con IPv6). **Límite real:** solo ve el mismo segmento de red y no
atraviesa el aislamiento de clientes (AP isolation).

### mDNS / DNS-SD — la apuesta más fuerte
- Es un estándar de la IETF (RFC 6762), publicado en el *Standards Track*.
- Microsoft lo declaró el estándar moderno de descubrimiento por multicast y
  está retirando sus alternativas (NetBIOS y LLMNR) para quedarse con mDNS.
- Apple (Bonjour), Android, Chromecast, impresoras (AirPrint/IPP) y la
  mayoría de domótica lo usan.
- El programa usa consultas *legacy unicast* (RFC 6762 §6.7): se pregunta
  desde un puerto distinto de 5353 y el equipo responde directo a ese puerto.
  Así no se compite con el servicio mDNS del propio sistema y no requiere
  permisos de administrador.

**Conclusión:** es la técnica con mejor proyección; todo indica que su uso
seguirá creciendo.

### SSDP / UPnP
Estándar internacional (ISO/IEC 29341) y muy común en routers domésticos,
Smart TV y consolas. Sin embargo, muchas empresas lo **desactivan** por
seguridad (UPnP permite abrir puertos en el router). Por eso se usa como
complemento: si está, aporta; si no, no se pierde nada.

### NetBIOS — se mantiene solo como complemento
Microsoft anunció en 2022 que está "rampando hacia abajo" la resolución de
nombres NetBIOS y LLMNR, con la meta de que mDNS sea el único protocolo de
descubrimiento activo por defecto. Se conserva porque todavía responde en
Windows antiguos y NAS con Samba, pero **se puede desactivar** desde
Configuración y el programa no depende de él.

### La MAC como identificador está perdiendo fuerza
- **Android 10 y posteriores** usan MAC aleatoria por defecto; desde
  **Android 12** algunas redes usan aleatorización *no persistente* (cambia
  en cada conexión).
- **iOS 18 / macOS 15** ofrecen tres modos por red: *Desactivado*, *Fija* y
  *Rotativa* (cambia periódicamente). En redes WPA2/WPA3 el valor por defecto
  es *Fija*.

**Consecuencia para el proyecto:** en una red con contraseña (lo normal), la
mayoría de celulares mantiene una MAC estable para esa red, así que el
inventario sigue siendo útil. Pero **no se puede prometer identidad 100 %
exacta** para celulares: por eso el programa (a) marca las MAC aleatorias,
(b) les aplica un plazo de baja más corto y (c) reconoce un cambio de MAC
cuando el nombre del equipo es el mismo y no es genérico.

**Mejora a futuro con mayor certeza:** en empresas, la identidad fiable viene
de autenticación 802.1X o de la tabla DHCP del router (vía SNMP o API), no de
la MAC. Es el siguiente paso natural para la versión empresarial.

---

## 2. Falencias encontradas y corrección

| # | Falencia | Impacto | Corrección | Justificación |
|---|---|---|---|---|
| 1 | Un celular dormido que no responde **un** escaneo se marcaba "desconectado" y al siguiente "reconectado" | Historial lleno de eventos falsos (el problema de saturación) | Se exige `fallos_para_inactivo` (2) escaneos **seguidos** sin verlo | Los equipos Wi-Fi en ahorro de energía pierden respuestas de forma intermitente; un solo fallo no es evidencia de desconexión |
| 2 | Un **repetidor Wi-Fi** responde con su MAC por todos sus clientes: el mismo registro saltaba de IP en IP | Eventos "cambio de IP" en cada escaneo e inventario incorrecto | Se agrupan las IP por MAC, se conserva una y las demás van a `ips_extra`; se alerta una sola vez | Muchos repetidores en modo "universal" traducen las MAC de sus clientes a la suya propia (MAC-NAT); varía según el fabricante |
| 3 | Si la MAC del **router** cambiaba, no se notaba | No se detectaba una suplantación ARP (ataque "hombre en el medio") | Alerta `alerta_router` en pantalla, historial y registro | Es la firma clásica del *ARP spoofing*; también aparece al cambiar de router (por eso es alerta, no bloqueo) |
| 4 | **MAC rotativa** de iOS 18 / Android 12+ creaba un equipo nuevo cada vez | Duplicados y "fantasmas" | Si la MAC nueva es aleatoria y el nombre coincide (no genérico), se reutiliza el registro y se guarda `macs_anteriores` | Documentación oficial de Apple y Android sobre aleatorización |
| 5 | Dos instancias (tarea programada + menú) podían escribir a la vez | Una borraba los cambios de la otra | Archivo `.bloqueo` creado de forma atómica (`O_EXCL`) y vencimiento de 120 s | El escaneo largo se hace **fuera** del bloqueo; solo la lectura-modificación-escritura se protege |
| 6 | Los escaneos programados no dejaban rastro | Imposible diagnosticar fallos sin pantalla | `registro.log` rotativo (1 MB × 3) | Práctica estándar de servicios desatendidos |
| 7 | El programa siempre terminaba con código 0 | El Programador de tareas no podía detectar errores | Códigos: 0 bien, 1 error, 2 aviso no aceptado, 3 datos ocupados | Convención de sistemas operativos |
| 8 | No había aviso de privacidad | Riesgo legal en uso institucional | Aviso que se acepta una vez; en modo desatendido se exige `--acepto-aviso` | Ley 1581 de 2012 (ver sección 3) |
| 9 | En Linux/macOS los datos quedaban legibles por otros usuarios | Exposición de MAC y nombres | Permisos `600` (solo el dueño) | Principio de mínimo privilegio |
| 10 | `bajas.json` crecía sin límite | Mismo problema de saturación, desplazado | Tope `max_bajas_archivadas` (2000) | Coherencia con el tope del historial |
| 11 | Equipos que no contestan ARP a tiempo se perdían | Menos dispositivos detectados | mDNS + SSDP encuentran IPs extra y se completa su MAC | Ver sección 1 |
| 12 | El perfil `auto` puede equivocarse (la señal Wi-Fi afecta la latencia) | Escaneo agresivo en router débil | Sugerencia automática: si la 2.ª ronda halla muchos equipos que la 1.ª no vio, se recomienda un perfil más suave | Es evidencia directa de pérdida de respuestas, más confiable que la latencia |
| 13 | `--perfil` y `--red` se ignoraban en modo menú | Confusión | Se aplican también al menú | — |

### Falencias que siguen abiertas (no se pueden resolver solo con software local)
- **Aislamiento de clientes (AP isolation) y VLAN:** ARP y multicast no
  cruzan esa barrera. Solución futura: leer la tabla DHCP/ARP del router
  (SNMP, API del fabricante, OpenWrt).
- **IPv6 puro:** hoy no se leen vecinos IPv6 (NDP). En redes locales actuales
  los equipos casi siempre tienen también IPv4, pero es una línea de trabajo
  futura.
- **Windows sin probar en esta revisión:** la función `SendARP` se validó por
  diseño, no en un equipo Windows real. Debe probarse antes de publicar.
- **El tipo de equipo es una inferencia** (a partir de los servicios
  anunciados), no una certeza; el programa lo presenta como "probable".

---

### Interfaz web local (v0.4.0)

**Por qué web local y no ventana de escritorio:** la misma página funciona en
Windows, Linux y macOS, se puede abrir desde el celular y no agrega
dependencias (servidor de la librería estándar de Python). Además, si el
motor se rehace en otro lenguaje (por ejemplo Go), la interfaz HTML se
reutiliza tal cual.

Riesgos que trae un servidor web y cómo se cubren:

| Riesgo | Corrección |
|---|---|
| Otro equipo de la red abre el inventario | Por defecto solo escucha en 127.0.0.1; el acceso remoto exige contraseña (PBKDF2, 200 000 iteraciones) y sesión con cookie HttpOnly + SameSite=Strict |
| Una página web maliciosa abierta en el mismo navegador ordena "borrar todo" (CSRF) | Toda acción exige la cabecera `X-Token` con un valor aleatorio que solo conoce la página servida |
| *DNS rebinding* (un dominio externo que apunta a 127.0.0.1) | Desde el propio PC solo se aceptan peticiones con Host 127.0.0.1 o localhost |
| Un equipo se pone de nombre código HTML/JavaScript (los nombres llegan por mDNS/NetBIOS, son datos no confiables) | La página inserta todo con `textContent`, nunca como HTML; además hay política CSP |
| Adivinar la contraseña | Máximo 10 intentos fallidos cada 10 minutos por IP y 1 s de espera por intento |
| Un equipo remoto cambia la seguridad o apaga el programa | Esas acciones solo se aceptan desde el propio PC |

Falencia encontrada al probar la interfaz: cuando el router le asignaba la IP
de un equipo ausente a otro equipo, el registro viejo seguía "conectado"
durante el margen de tolerancia y aparecían dos equipos en la misma IP. Ahora,
si la IP de un equipo la ocupa otra MAC, el anterior pasa a desconectado de
inmediato.

### Versión 0.5.0: correcciones dentro del código

| Problema | Solución aplicada | Justificación |
|---|---|---|
| No había forma de medir la precisión del escaneo | **Modo validación**: compara MAC por MAC contra la lista DHCP del router y calcula la exhaustividad (equipos del router encontrados / equipos del router) | El router es la fuente más cercana a la "verdad" en una red doméstica. Comparar por MAC (y no solo por cantidad) evita que un equipo de más compense uno de menos |
| El perfil `auto` usaba umbrales elegidos a criterio | Cada escaneo guarda pérdida, latencia, equipos por ronda y respuestas por protocolo en `estadisticas.json` (exportable a CSV) | Con validaciones y estadísticas de varias redes, los umbrales se ajustan con evidencia en vez de suposiciones |
| Equipos que solo usan IPv6 no aparecían, y los celulares que no respondían ARP pero sí estaban presentes se marcaban desconectados | Lectura de la tabla de vecinos IPv6 (NDP), **filtrada por la interfaz de la red escaneada** | IPv6 no se puede barrer como IPv4 (2^64 direcciones por red), pero el sistema ya conoce a sus vecinos recientes. Filtrar por interfaz evita mezclar redes virtuales (VirtualBox, VPN) |
| El tipo de equipo inferido podía ser incorrecto | El usuario lo corrige en el panel y el escaneo **no lo sobrescribe** | La inferencia por servicios es probabilística; la corrección humana es la fuente más confiable |
| El Firewall de Windows puede bloquear respuestas mDNS/SSDP/NetBIOS | Comando `--configurar-firewall`, regla automática en el instalador (modo administrador) y aviso cuando ningún equipo respondió a esos protocolos | La regla es mínima: solo UDP, solo este programa, solo redes privadas |

Error encontrado por las pruebas automáticas: en macOS la tabla `ndp` tiene
una columna de estado y otra de banderas; la letra **R** significa
"alcanzable" en la primera y "es router" en la segunda. El código leía la
columna equivocada. Corregido y cubierto por una prueba.

### Versión 0.6.0: endurecimiento de seguridad

Se hizo una auditoría atacando el programa antes y después de los cambios.
Vulnerabilidades reales encontradas y corregidas:

| Vulnerabilidad | Prueba de ataque | Corrección |
|---|---|---|
| Un `Content-Length` negativo dejaba un hilo del servidor colgado para siempre (denegación de servicio) | Pedido con `Content-Length: -1`: sin respuesta | Validación estricta: responde 400 al instante |
| Conexiones abiertas sin enviar datos nunca se cerraban (*slowloris*) | 50 conexiones mudas: ninguna cerrada | Tiempo máximo de 15 s, tope de 32 simultáneas y 6 por equipo remoto: bajo una inundación desde la red, el usuario local sigue atendido |
| Nombres con caracteres de control anunciados por la red se guardaban tal cual | Nombre con códigos de escape de terminal | Saneamiento de todo texto que llega de la red |
| Contraseña cifrada con 200 000 iteraciones | — | 600 000 (OWASP 2023), con migración automática |
| Sesiones remotas sin cierre, sin expiración por inactividad, válidas tras cambiar la contraseña | — | Cierre de sesión, 30 min de inactividad, invalidación al cambiar la contraseña |
| CSP permitía cualquier script incrustado | — | CSP con *nonce* aleatorio por página |

Detalle completo del modelo de amenazas y de los controles en
`docs/SEGURIDAD.md`.

### Lo que queda para la salida al mercado (trámites, no código)

- Firma digital del ejecutable (quita advertencias del antivirus y SmartScreen).
- Integración con routers por SNMP / OpenWrt / API de fabricantes (requiere
  acceso administrativo a cada router).
- Sensores por VLAN y servidor central (versión empresarial).
- Plantilla de autorización de tratamiento de datos para empresas.

## 3. Marco legal (Colombia)

- La **Ley Estatutaria 1581 de 2012** define *dato personal* como cualquier
  información que pueda asociarse a personas naturales determinadas o
  determinables. Una MAC o un nombre como "iPhone-de-Ana" en una empresa
  puede asociarse a una persona.
- La misma ley define la *autorización* como el consentimiento previo,
  expreso e informado del titular.
- La ley **no aplica** a bases de datos mantenidas en un ámbito
  exclusivamente personal o doméstico (art. 2, literal a).

**Conclusión práctica:** en casa se puede usar libremente; en una empresa o
institución se debe informar a los usuarios y obtener la autorización
correspondiente. *Esto es orientación general, no asesoría jurídica.*

---

## 4. Fuentes

- RFC 6762, Multicast DNS — https://www.rfc-editor.org/rfc/rfc6762
- Microsoft, *Aligning on mDNS: ramping down NetBIOS name resolution and LLMNR* (2022) — https://techcommunity.microsoft.com/blog/networkingblog/aligning-on-mdns-ramping-down-netbios-name-resolution-and-llmnr/3290816
- Android, *MAC randomization behavior* — https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior
- Apple, *Wi-Fi privacy* (Platform Security Guide) — https://support.apple.com/guide/security/sec31e483abf/web
- Apple, *Use private Wi-Fi addresses on Apple devices* — https://support.apple.com/en-us/102509
- UPnP Device Architecture 1.1 (Open Connectivity Foundation) — https://openconnectivity.org/wp-content/uploads/2015/11/UPnP-arch-DeviceArchitecture-v1.1.pdf
- IEEE Registration Authority, listado público OUI — https://standards-oui.ieee.org/oui/oui.csv
- Ley 1581 de 2012, Función Pública — https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=49981
