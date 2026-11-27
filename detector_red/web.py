"""Interfaz web local: servidor HTTP de la librería estándar y API JSON.

Escucha solo en 127.0.0.1 salvo que se active el acceso remoto (con
contraseña). Protecciones y modelo de amenazas: docs/SEGURIDAD.md."""

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import ssl
import threading
import time
import urllib.request
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from detector_red import (__version__, almacenamiento, config, empaquetado, escaner, fabricantes,
                          inventario as inv, mantenimiento, servicio, validacion)

registro = logging.getLogger("detector_red")
CARPETA_WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
DURACION_SESION = 12 * 3600       # duración máxima de una sesión remota
INACTIVIDAD_SESION = 30 * 60      # se cierra tras 30 min sin uso
MAX_SESIONES = 50
ITERACIONES_CLAVE = 600_000       # recomendación OWASP para PBKDF2-HMAC-SHA256
TIEMPO_ESPERA = 15                # segundos máximos esperando datos de un cliente
MAX_CONEXIONES = 32               # peticiones atendidas al mismo tiempo
MAX_POR_IP_REMOTA = 6             # cupos que puede ocupar un solo equipo remoto
MAX_CUERPO = 100_000              # bytes máximos de una petición
INTENTOS_POR_IP = 10              # contraseñas fallidas por IP cada 10 min
INTENTOS_GLOBALES = 30            # fallidas en total (ataque desde varias IP)
CLAVES_COMUNES = {
    "12345678", "123456789", "1234567890", "password", "contraseña", "contrasena",
    "qwerty123", "11111111", "00000000", "administrador", "admin1234", "detector",
    "iloveyou", "colombia", "12345678910", "abcdefgh", "abc12345",
}

# Opciones que se pueden cambiar desde la página y cómo validarlas
CONFIG_EDITABLE = {
    "perfil_router": lambda v: v if v in ("auto", *config.PERFILES) else None,
    "red_manual": lambda v: "" if not v else str(ipaddress.IPv4Network(v, strict=False)),
    "resolver_nombres": bool, "descubrimiento_mdns": bool, "descubrimiento_ssdp": bool,
    "netbios": bool, "vecinos_ipv6": bool, "limpieza_automatica": bool, "baja_automatica": bool,
    "archivar_bajas": bool,
    "fallos_para_inactivo": lambda v: max(1, min(10, int(v))),
    "retencion_historial_dias": lambda v: max(1, int(v)),
    "max_eventos_historial": lambda v: max(100, int(v)),
    "dias_para_baja": lambda v: max(1, int(v)),
    "dias_para_baja_mac_aleatoria": lambda v: max(1, int(v)),
}


def cifrar_clave(clave, sal=None, iteraciones=ITERACIONES_CLAVE):
    sal = sal or secrets.token_bytes(16)
    resumen = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), sal, iteraciones)
    return f"pbkdf2${iteraciones}${sal.hex()}${resumen.hex()}"


def verificar_clave(clave, guardada):
    try:
        _, iteraciones, sal, resumen = guardada.split("$")
        calculado = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"),
                                        bytes.fromhex(sal), int(iteraciones))
        return hmac.compare_digest(calculado.hex(), resumen)
    except (ValueError, AttributeError):
        return False


def necesita_actualizar(guardada):
    """True si la contraseña se cifró con menos iteraciones de las actuales
    (versiones anteriores usaban 200 000). Se re-cifra al iniciar sesión."""
    try:
        return int(guardada.split("$")[1]) < ITERACIONES_CLAVE
    except (IndexError, ValueError, AttributeError):
        return False


def problema_clave(clave):
    """Devuelve un mensaje si la contraseña es débil, o None si es aceptable."""
    if len(clave) < 10:
        return "La contraseña debe tener al menos 10 caracteres."
    if len(clave) > 128:
        return "La contraseña es demasiado larga (máximo 128 caracteres)."
    if clave.isdigit():
        return "La contraseña no puede ser solo números."
    if len(set(clave)) < 4:
        return "La contraseña repite demasiado los mismos caracteres."
    if clave.lower() in CLAVES_COMUNES or any(c in clave.lower() for c in ("123456", "qwerty", "password")):
        return "Esa contraseña es muy común. Use una frase o combine palabras y números."
    return None


class Aplicacion:
    def __init__(self, cfg, puerto, acceso_red, tls=False):
        self.cfg = cfg
        self.puerto = puerto
        self.acceso_red = acceso_red
        self.tls = tls
        self.token = secrets.token_urlsafe(32)
        self.sesiones = {}
        self.intentos_fallidos = {}
        self.fallos_globales = []
        self.cupos = threading.BoundedSemaphore(MAX_CONEXIONES)
        self.conexiones_por_ip = {}
        self._candado_conexiones = threading.Lock()
        self._candado_sesiones = threading.Lock()
        self.escaneo = {"en_curso": False, "lineas": [], "resultado": None, "inicio": None}
        self._candado_escaneo = threading.Lock()
        self.empaque = {"en_curso": False, "accion": None, "lineas": [], "resultado": None}
        self._candado_empaque = threading.Lock()
        self.red_detectada = None

    def iniciar_escaneo(self):
        if not self._candado_escaneo.acquire(blocking=False):
            return False
        self.escaneo = {"en_curso": True, "lineas": [], "resultado": None, "inicio": time.time()}

        def mostrar(texto):
            lineas = self.escaneo["lineas"]
            lineas.append(texto.strip())
            del lineas[:-200]

        def tarea():
            try:
                self.escaneo["resultado"] = servicio.escanear(self.cfg, mostrar=mostrar)
            except almacenamiento.ArchivoOcupado as error:
                self.escaneo["resultado"] = {"ok": False, "error": str(error)}
            except Exception as error:
                registro.exception("Error en escaneo web")
                self.escaneo["resultado"] = {"ok": False, "error": f"Error inesperado: {error}"}
            finally:
                self.escaneo["en_curso"] = False
                self._candado_escaneo.release()

        threading.Thread(target=tarea, daemon=True).start()
        return True

    def iniciar_empaquetado(self, accion, funcion):
        if not self._candado_empaque.acquire(blocking=False):
            return False
        self.empaque = {"en_curso": True, "accion": accion, "lineas": [], "resultado": None}

        def mostrar(texto):
            self.empaque["lineas"].append(texto.strip()[:300])
            del self.empaque["lineas"][:-300]

        def tarea():
            try:
                self.empaque["resultado"] = funcion(mostrar)
            except Exception as error:
                registro.exception("Error al armar el ejecutable")
                self.empaque["resultado"] = {"ok": False, "error": f"Error inesperado: {error}"}
            finally:
                self.empaque["en_curso"] = False
                self._candado_empaque.release()

        threading.Thread(target=tarea, daemon=True).start()
        return True

    def crear_sesion(self):
        token = secrets.token_urlsafe(32)
        ahora = time.time()
        with self._candado_sesiones:
            self._limpiar_sesiones(ahora)
            if len(self.sesiones) >= MAX_SESIONES:      # descarta la usada hace más tiempo
                del self.sesiones[min(self.sesiones, key=lambda t: self.sesiones[t]["ultimo"])]
            self.sesiones[token] = {"vence": ahora + DURACION_SESION, "ultimo": ahora}
        return token

    def _limpiar_sesiones(self, ahora):
        for token in [t for t, s in self.sesiones.items()
                      if s["vence"] < ahora or ahora - s["ultimo"] > INACTIVIDAD_SESION]:
            del self.sesiones[token]

    def sesion_valida(self, token):
        ahora = time.time()
        with self._candado_sesiones:
            self._limpiar_sesiones(ahora)
            sesion = self.sesiones.get(token or "")
            if sesion is None:
                return False
            sesion["ultimo"] = ahora
            return True

    def cerrar_sesion(self, token):
        with self._candado_sesiones:
            self.sesiones.pop(token or "", None)

    def cerrar_todas_las_sesiones(self):
        with self._candado_sesiones:
            self.sesiones.clear()

    def puede_intentar(self, ip):
        ahora = time.time()
        self.fallos_globales = [t for t in self.fallos_globales if ahora - t < 600]
        for clave in list(self.intentos_fallidos):           # evita que el diccionario crezca sin fin
            self.intentos_fallidos[clave] = [t for t in self.intentos_fallidos[clave] if ahora - t < 600]
            if not self.intentos_fallidos[clave]:
                del self.intentos_fallidos[clave]
        return (len(self.intentos_fallidos.get(ip, [])) < INTENTOS_POR_IP
                and len(self.fallos_globales) < INTENTOS_GLOBALES)

    def registrar_fallo(self, ip):
        ahora = time.time()
        self.intentos_fallidos.setdefault(ip, []).append(ahora)
        self.fallos_globales.append(ahora)


class Manejador(BaseHTTPRequestHandler):
    server_version = "DetectorRed"
    sys_version = ""
    # Corta conexiones que no envían nada (slowloris) en vez de ocupar un hilo
    timeout = TIEMPO_ESPERA

    def _rechazar_ocupado(self):
        try:
            self.connection.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                    b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass

    def handle(self):
        """Tope de peticiones simultáneas, total y por equipo remoto: quien inunde
        el servidor recibe 503 sin dejar sin atención al usuario de este PC."""
        app = self.server.app
        ip = self.client_address[0]
        remoto = ip not in ("127.0.0.1", "::1")
        if remoto:
            with app._candado_conexiones:
                if app.conexiones_por_ip.get(ip, 0) >= MAX_POR_IP_REMOTA:
                    return self._rechazar_ocupado()
                app.conexiones_por_ip[ip] = app.conexiones_por_ip.get(ip, 0) + 1
        try:
            if not app.cupos.acquire(blocking=False):
                return self._rechazar_ocupado()
            try:
                super().handle()
            finally:
                app.cupos.release()
        finally:
            if remoto:
                with app._candado_conexiones:
                    app.conexiones_por_ip[ip] -= 1
                    if app.conexiones_por_ip[ip] <= 0:
                        del app.conexiones_por_ip[ip]

    def _auditar(self, accion, detalle=""):
        registro.info("AUDITORIA %s desde %s %s", accion, self.client_address[0], detalle)

    @property
    def app(self):
        return self.server.app

    def log_message(self, formato, *args):
        registro.debug("web %s - %s", self.client_address[0], formato % args)

    def _cliente_local(self):
        return self.client_address[0] in ("127.0.0.1", "::1")

    def _host_permitido(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if self._cliente_local():
            return host in ("127.0.0.1", "localhost", "::1")
        return self.app.acceso_red

    def _sesion(self):
        cookie = SimpleCookie(self.headers.get("Cookie") or "")
        return cookie["sesion"].value if "sesion" in cookie else None

    def _bloqueo_local(self):
        return bool(self.app.cfg.get("web_bloqueo_local") and self.app.cfg.get("web_clave"))

    def _autorizado(self):
        if self._cliente_local() and not self._bloqueo_local():
            return True
        return self.app.sesion_valida(self._sesion())

    def _cookie_sesion(self, token):
        seguro = "; Secure" if self.app.tls else ""
        return f"sesion={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={DURACION_SESION}{seguro}"

    def _responder(self, codigo, cuerpo, tipo="application/json; charset=utf-8", cabeceras=None,
                   csp="default-src 'none'; frame-ancestors 'none'"):
        datos = cuerpo if isinstance(cuerpo, bytes) else json.dumps(cuerpo, ensure_ascii=False).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if self.app.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for clave, valor in (cabeceras or {}).items():
            self.send_header(clave, valor)
        self.end_headers()
        self.wfile.write(datos)

    def _error(self, codigo, mensaje):
        self._responder(codigo, {"ok": False, "error": mensaje})

    def _leer_json(self):
        # Un Content-Length negativo dejaría el hilo esperando datos para siempre
        texto = (self.headers.get("Content-Length") or "0").strip()
        if not texto.isdigit():
            raise ValueError("Content-Length inválido.")
        largo = int(texto)
        if largo > MAX_CUERPO:
            raise ValueError("Petición demasiado grande.")
        if not largo:
            return {}
        if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
            raise ValueError("Tipo de contenido no permitido.")
        datos = json.loads(self.rfile.read(largo).decode("utf-8"))
        if not isinstance(datos, dict):
            raise ValueError("Formato inválido.")
        return datos

    def do_GET(self):
        if not self._host_permitido():
            return self._error(403, "Host no permitido.")
        ruta = urlparse(self.path)
        if ruta.path in ("/", "/index.html"):
            return self._pagina()
        if ruta.path == "/api/ping":
            return self._responder(200, {"app": "detector-red", "version": __version__})
        if not self._autorizado():
            return self._error(401, "Inicie sesión.")
        rutas = {
            "/api/estado": self._api_estado,
            "/api/dispositivos": self._api_dispositivos,
            "/api/historial": lambda: self._api_historial(parse_qs(ruta.query)),
            "/api/progreso": lambda: self._responder(200, self.app.escaneo),
            "/api/mantenimiento": lambda: self._api_mantenimiento(parse_qs(ruta.query)),
            "/api/config": self._api_config,
            "/api/validaciones": self._api_validaciones,
            "/api/empaquetado": lambda: self._responder(200, dict(
                empaquetado.estado(), tarea=self.app.empaque, es_local=self._cliente_local())),
            "/api/descargar": lambda: self._api_descargar(parse_qs(ruta.query)),
            "/api/validaciones.csv": lambda: self._descargar(
                "validaciones.csv", validacion.a_csv(validacion.cargar())),
            "/api/estadisticas.csv": lambda: self._descargar(
                "estadisticas_escaneo.csv", validacion.estadisticas_a_csv(
                    almacenamiento.leer_json(servicio.ARCHIVO_ESTADISTICAS, []))),
        }
        if ruta.path in rutas:
            return rutas[ruta.path]()
        return self._error(404, "No existe.")

    def _pagina(self):
        with open(os.path.join(CARPETA_WEB, "index.html"), "r", encoding="utf-8") as f:
            html = f.read()
        nonce = secrets.token_urlsafe(16)
        html = (html.replace("__TOKEN__", self.app.token).replace("__VERSION__", __version__)
                .replace("<script>", f'<script nonce="{nonce}">'))
        # Solo se ejecuta el script con este nonce: código inyectado quedaría bloqueado
        csp = ("default-src 'none'; "
               f"script-src 'nonce-{nonce}'; "
               "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
               "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self._responder(200, html.encode("utf-8"), "text/html; charset=utf-8", csp=csp)

    def _api_estado(self):
        cfg = self.app.cfg
        inventario, historial = servicio.cargar_todo()
        activos, inactivos = inv.contar_estados(inventario)
        ultimo = servicio.ultimo_escaneo()
        if not ultimo.get("red"):
            if self.app.red_detectada is None:
                ip_local = escaner.obtener_ip_local()
                self.app.red_detectada = {}
                if not ip_local.startswith("127."):
                    datos = escaner.detectar_red(ip_local, cfg["max_hosts"], cfg["red_manual"])
                    self.app.red_detectada = {"red": str(datos["red"]), "gateway": datos["gateway"],
                                              "ip_local": ip_local}
            ultimo = self.app.red_detectada
        alertas = [e for e in historial if str(e.get("evento", "")).startswith("alerta")][-10:]
        self._responder(200, {
            "version": __version__, "aviso_aceptado": cfg["aviso_aceptado"],
            "activos": activos, "inactivos": inactivos, "total": len(inventario),
            "ultimo": ultimo, "alertas": alertas, "en_curso": self.app.escaneo["en_curso"],
            "fabricantes": fabricantes.disponible(), "carpeta": config.carpeta_datos(),
            "es_local": self._cliente_local(),
            "remoto_sin_cifrar": self.app.acceso_red and not self.app.tls,
            "bloqueo_local": self._bloqueo_local(),
        })

    def _api_dispositivos(self):
        inventario, _ = servicio.cargar_todo()
        for d in inventario:
            d["clave"] = d["mac"] or d["ip"]
        self._responder(200, inv.ordenar(inventario))

    def _api_historial(self, consulta):
        try:
            cantidad = max(1, min(2000, int(consulta.get("n", ["300"])[0])))
        except ValueError:
            cantidad = 300
        historial = almacenamiento.cargar_historial()
        self._responder(200, {"total": len(historial), "eventos": historial[-cantidad:][::-1]})

    def _api_mantenimiento(self, consulta):
        cfg = self.app.cfg
        try:
            dias = max(1, int(consulta.get("dias", [cfg["dias_para_baja"]])[0]))
        except ValueError:
            dias = cfg["dias_para_baja"]
        inventario, historial = servicio.cargar_todo()
        estado = mantenimiento.estado(inventario, historial, cfg,
                                      almacenamiento.tamano_archivo(config.ARCHIVO_HISTORIAL))
        candidatos = mantenimiento.candidatos_baja(inventario, dias, cfg["dias_para_baja_mac_aleatoria"])
        estado["lista_candidatos"] = [{"nombre": d["nombre"], "ip": d["ip"], "mac": d["mac"],
                                       "ultima_vez": d["ultima_vez"]} for d in candidatos]
        self._responder(200, estado)

    def _api_descargar(self, consulta):
        tipo = consulta.get("tipo", [""])[0]
        ruta_archivo = empaquetado.archivo_para_descargar(tipo)
        if not ruta_archivo or not os.path.isfile(ruta_archivo):
            return self._error(404, "Ese archivo todavía no existe. Ármelo primero.")
        self._auditar("descarga del ejecutable", os.path.basename(ruta_archivo))
        tamano = os.path.getsize(ruta_archivo)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(tamano))
        self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(ruta_archivo)}"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with open(ruta_archivo, "rb") as f:
            for bloque in iter(lambda: f.read(256 * 1024), b""):
                self.wfile.write(bloque)

    def _descargar(self, nombre, texto):
        self._responder(200, texto.encode("utf-8"), "text/csv; charset=utf-8",
                        {"Content-Disposition": f'attachment; filename="{nombre}"'})

    def _api_validaciones(self):
        lista = validacion.cargar()
        ultimo = servicio.ultimo_escaneo()
        self._responder(200, {
            "lista": lista[-50:][::-1],
            "resumen": validacion.resumen_por_perfil(lista),
            "ultimo": {k: ultimo.get(k) for k in ("fecha", "red", "perfil", "activos", "duracion")},
            "puede_validar": bool(ultimo.get("macs")),
        })

    def _api_config(self):
        datos = {k: v for k, v in self.app.cfg.items() if k != "web_clave"}
        datos["tiene_clave"] = bool(self.app.cfg.get("web_clave"))
        datos["acceso_red_activo"] = self.app.acceso_red
        datos["perfiles"] = ["auto", *config.PERFILES]
        self._responder(200, datos)

    def do_POST(self):
        if not self._host_permitido():
            return self._error(403, "Host no permitido.")
        if not hmac.compare_digest(self.headers.get("X-Token", ""), self.app.token):
            return self._error(403, "Token inválido. Recargue la página.")
        ruta = urlparse(self.path).path
        try:
            datos = self._leer_json()
        except (ValueError, UnicodeDecodeError) as error:
            return self._error(400, f"Petición inválida: {error}")
        if ruta == "/api/login":
            return self._api_login(datos)
        if ruta == "/api/logout":
            self.app.cerrar_sesion(self._sesion())
            self._auditar("cierre de sesión")
            return self._responder(200, {"ok": True}, cabeceras={
                "Set-Cookie": "sesion=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
        if not self._autorizado():
            return self._error(401, "Inicie sesión.")
        if ruta == "/api/aviso" and datos.get("acepto") is True:
            self.app.cfg["aviso_aceptado"] = True
            almacenamiento.guardar_config(self.app.cfg)
            return self._responder(200, {"ok": True})
        acciones = {
            "/api/escanear": self._accion_escanear,
            "/api/dispositivo/renombrar": self._accion_renombrar,
            "/api/dispositivo/proteger": self._accion_proteger,
            "/api/dispositivo/agregar": self._accion_agregar,
            "/api/dispositivo/borrar-historial": self._accion_borrar_historial_disp,
            "/api/dispositivo/tipo": self._accion_tipo,
            "/api/dispositivo/eliminar": self._accion_eliminar,
            "/api/validar": self._accion_validar,
            "/api/mantenimiento/purgar": self._accion_purgar,
            "/api/mantenimiento/baja": self._accion_baja,
            "/api/mantenimiento/borrar-todo": self._accion_borrar_todo,
            "/api/config": self._accion_config,
            "/api/fabricantes": self._accion_fabricantes,
            "/api/empaquetado/pyinstaller": lambda _: self._accion_empaquetar(
                "pyinstaller", empaquetado.instalar_pyinstaller),
            "/api/empaquetado/construir": lambda _: self._accion_empaquetar(
                "ejecutable", empaquetado.construir),
            "/api/empaquetado/instalador": lambda _: self._accion_empaquetar(
                "instalador", empaquetado.construir_instalador),
            "/api/apagar": self._accion_apagar,
        }
        if ruta not in acciones:
            return self._error(404, "No existe.")
        try:
            return acciones[ruta](datos)
        except almacenamiento.ArchivoOcupado as error:
            return self._error(409, str(error))
        except (ValueError, TypeError, KeyError) as error:
            return self._error(400, f"Dato inválido: {error}")

    def _api_login(self, datos):
        ip = self.client_address[0]
        if not self.app.puede_intentar(ip):
            registro.warning("AUDITORIA inicio de sesión bloqueado por exceso de intentos desde %s", ip)
            return self._error(429, "Demasiados intentos. Espere 10 minutos.")
        clave = str(datos.get("clave", ""))[:128]
        guardada = self.app.cfg.get("web_clave", "")
        if guardada and verificar_clave(clave, guardada):
            if necesita_actualizar(guardada):        # migra contraseñas de versiones anteriores
                self.app.cfg["web_clave"] = cifrar_clave(clave)
                almacenamiento.guardar_config(self.app.cfg)
            self._auditar("inicio de sesión correcto")
            return self._responder(200, {"ok": True},
                                   cabeceras={"Set-Cookie": self._cookie_sesion(self.app.crear_sesion())})
        self.app.registrar_fallo(ip)
        registro.warning("AUDITORIA contraseña incorrecta desde %s", ip)
        time.sleep(1)
        return self._error(403, "Contraseña incorrecta.")

    def _accion_escanear(self, _):
        if not self.app.cfg["aviso_aceptado"]:
            return self._error(403, "Acepte primero el aviso de uso.")
        if not self.app.iniciar_escaneo():
            return self._error(409, "Ya hay un escaneo en curso.")
        return self._responder(200, {"ok": True})

    def _modificar_dispositivo(self, clave, cambio):
        with almacenamiento.bloqueo():
            inventario, historial = servicio.cargar_todo()
            d = inv.buscar(inventario, str(clave))
            if not d:
                return None
            cambio(d, historial)
            servicio.guardar_todo(inventario, historial)
            return d

    def _accion_renombrar(self, datos):
        nuevo = escaner.limpiar_texto(datos.get("nombre"), 60)
        if not nuevo:
            return self._error(400, "Escriba un nombre.")

        def cambio(d, historial):
            inv.registrar_evento(historial, "renombrado", d, f"{d['nombre']} -> {nuevo}")
            d["nombre"], d["nombre_auto"] = nuevo, False
        d = self._modificar_dispositivo(datos.get("clave"), cambio)
        return self._responder(200, {"ok": True}) if d else self._error(404, "Dispositivo no encontrado.")

    def _accion_proteger(self, datos):
        def cambio(d, _):
            d["protegido"] = bool(datos.get("protegido"))
        d = self._modificar_dispositivo(datos.get("clave"), cambio)
        return self._responder(200, {"ok": True}) if d else self._error(404, "Dispositivo no encontrado.")

    def _accion_tipo(self, datos):
        tipo = escaner.limpiar_texto(datos.get("tipo"), 40) or ""

        def cambio(d, _):
            # Vacío = volver a la detección automática
            d["tipo"], d["tipo_manual"] = (tipo or None), bool(tipo)
        d = self._modificar_dispositivo(datos.get("clave"), cambio)
        return self._responder(200, {"ok": True}) if d else self._error(404, "Dispositivo no encontrado.")

    def _accion_validar(self, datos):
        ultimo = servicio.ultimo_escaneo()
        if not ultimo.get("macs"):
            return self._error(400, "Primero escanee la red: la validación compara contra el último escaneo.")
        macs_router = validacion.extraer_macs(str(datos.get("texto", ""))[:200_000])
        if macs_router:
            resultado = validacion.comparar(macs_router, ultimo["macs"])
        elif datos.get("cantidad"):
            resultado = validacion.comparar_conteo(datos["cantidad"], len(ultimo["macs"]))
        else:
            return self._error(400, "No se encontraron direcciones MAC en el texto. Pegue la lista de "
                                    "clientes del router o escriba la cantidad de equipos que reporta.")
        inventario, _ = servicio.cargar_todo()
        nombres = {d["mac"]: d["nombre"] for d in inventario if d["mac"]}
        guardado = validacion.registrar(resultado, ultimo, datos.get("nota"), nombres)
        registro.info("Validación: %s%% (%s de %s, método %s)", guardado["porcentaje"],
                      guardado["coinciden"], guardado["en_router"], guardado["metodo"])
        return self._responder(200, {"ok": True, "validacion": guardado})

    def _accion_agregar(self, datos):
        nombre = escaner.limpiar_texto(datos.get("nombre"), 60) or ""
        ip = str(datos.get("ip", "")).strip()
        mac = str(datos.get("mac", "")).strip()
        if not nombre or not inv.validar_ip(ip):
            return self._error(400, "Escriba un nombre y una IP válida (ej. 192.168.1.20).")
        with almacenamiento.bloqueo():
            inventario, historial = servicio.cargar_todo()
            ok, mensaje = inv.agregar_manual(inventario, historial, nombre, ip, mac)
            if ok:
                servicio.guardar_todo(inventario, historial)
        return self._responder(200 if ok else 400, {"ok": ok, "mensaje" if ok else "error": mensaje})

    def _accion_borrar_historial_disp(self, datos):
        with almacenamiento.bloqueo():
            inventario, historial = servicio.cargar_todo()
            d = inv.buscar(inventario, str(datos.get("clave")))
            if not d or not d["mac"]:
                return self._error(404, "Dispositivo no encontrado o sin MAC.")
            almacenamiento.respaldar(config.ARCHIVO_HISTORIAL)
            nuevo, n = mantenimiento.borrar_historial_dispositivo(historial, d["mac"])
            almacenamiento.guardar_historial(nuevo)
        self._auditar("borrar historial de dispositivo", f"{d['mac']} ({n} eventos)")
        return self._responder(200, {"ok": True, "borrados": n})

    def _accion_purgar(self, datos):
        dias = max(1, int(datos.get("dias")))
        with almacenamiento.bloqueo():
            almacenamiento.respaldar(config.ARCHIVO_HISTORIAL)
            nuevo, n = mantenimiento.purgar_eventos_antiguos(almacenamiento.cargar_historial(), dias)
            almacenamiento.guardar_historial(nuevo)
        self._auditar("borrar eventos antiguos", f"más de {dias} días ({n} eventos)")
        return self._responder(200, {"ok": True, "borrados": n})

    def _accion_baja(self, datos):
        cfg = self.app.cfg
        dias = max(1, int(datos.get("dias", cfg["dias_para_baja"])))
        with almacenamiento.bloqueo():
            almacenamiento.respaldar(config.ARCHIVO_INVENTARIO)
            almacenamiento.respaldar(config.ARCHIVO_HISTORIAL)
            inventario, historial = servicio.cargar_todo()
            candidatos = mantenimiento.candidatos_baja(inventario, dias, cfg["dias_para_baja_mac_aleatoria"])
            bajas = almacenamiento.cargar_bajas()
            inventario, historial = mantenimiento.dar_de_baja(
                inventario, historial, candidatos, bajas if cfg["archivar_bajas"] else None,
                max_bajas=cfg["max_bajas_archivadas"])
            servicio.guardar_todo(inventario, historial)
            if cfg["archivar_bajas"]:
                almacenamiento.guardar_bajas(bajas)
        self._auditar("dar de baja", f"{len(candidatos)} dispositivos sin ver hace más de {dias} días")
        return self._responder(200, {"ok": True, "bajas": len(candidatos)})

    def _accion_borrar_todo(self, datos):
        if datos.get("confirmacion") != "BORRAR":
            return self._error(400, "Escriba BORRAR para confirmar.")
        incluir = bool(datos.get("incluir_dispositivos"))
        conservar = bool(datos.get("conservar_protegidos", True))
        borrados = servicio.borrar_datos(incluir, conservar)
        self._auditar("borrar historial y dispositivos" if incluir else "borrar todo el historial",
                      f"({borrados} dispositivos, protegidos {'conservados' if conservar else 'borrados'})"
                      if incluir else "")
        return self._responder(200, {"ok": True, "dispositivos_borrados": borrados})

    def _accion_eliminar(self, datos):
        d = servicio.eliminar_dispositivo(datos.get("clave"))
        if d is None:
            return self._error(404, "Dispositivo no encontrado.")
        self._auditar("eliminar dispositivo", f"{d['nombre']} {d['mac'] or d['ip']}")
        return self._responder(200, {"ok": True})

    def _accion_config(self, datos):
        cfg = self.app.cfg
        nuevos = {}
        for clave, validar in CONFIG_EDITABLE.items():
            if clave in datos:
                try:
                    valor = validar(datos[clave])
                except (ValueError, TypeError):
                    valor = None
                if valor is None:
                    return self._error(400, f"Valor no válido en '{clave}': {datos[clave]}")
                nuevos[clave] = valor
        cfg.update(nuevos)     # solo se aplica si TODOS los valores son válidos
        aviso = None
        cabeceras = {}
        # La seguridad solo se cambia desde este mismo PC
        if self._cliente_local():
            if datos.get("nueva_clave"):
                clave = str(datos["nueva_clave"])
                problema = problema_clave(clave)
                if problema:
                    return self._error(400, problema)
                cfg["web_clave"] = cifrar_clave(clave)
                self.app.cerrar_todas_las_sesiones()
                # Quien cambió la contraseña sigue dentro; las demás sesiones se cierran
                cabeceras["Set-Cookie"] = self._cookie_sesion(self.app.crear_sesion())
                self._auditar("cambio de contraseña web (sesiones cerradas)")
            if "web_acceso_red" in datos:
                quiere = bool(datos["web_acceso_red"])
                if quiere and not cfg.get("web_clave"):
                    return self._error(400, "Defina una contraseña antes de permitir el acceso desde la red.")
                if quiere != cfg["web_acceso_red"]:
                    cfg["web_acceso_red"] = quiere
                    self._auditar("acceso desde la red", "activado" if quiere else "desactivado")
                    aviso = "Reinicie el programa para aplicar el cambio de acceso desde la red."
            if "web_bloqueo_local" in datos:
                quiere = bool(datos["web_bloqueo_local"])
                if quiere and not cfg.get("web_clave"):
                    return self._error(400, "Defina una contraseña antes de pedirla en este PC.")
                if quiere != cfg.get("web_bloqueo_local", False):
                    cfg["web_bloqueo_local"] = quiere
                    self._auditar("contraseña en este PC", "activada" if quiere else "desactivada")
                    if quiere and "Set-Cookie" not in cabeceras:
                        cabeceras["Set-Cookie"] = self._cookie_sesion(self.app.crear_sesion())
        if nuevos:
            self._auditar("cambio de configuración", ", ".join(sorted(nuevos)))
        almacenamiento.guardar_config(cfg)
        return self._responder(200, {"ok": True, "aviso": aviso}, cabeceras=cabeceras)

    def _accion_empaquetar(self, accion, funcion):
        # Ejecuta programas en este PC: solo se permite desde el propio PC
        if not self._cliente_local():
            return self._error(403, "Solo se puede armar el ejecutable desde este PC.")
        if empaquetado.congelado():
            return self._error(400, "Este programa ya es el ejecutable; descargue una copia.")
        if not self.app.iniciar_empaquetado(accion, funcion):
            return self._error(409, "Ya se está armando algo. Espere a que termine.")
        self._auditar("armar", accion)
        return self._responder(200, {"ok": True})

    def _accion_fabricantes(self, _):
        try:
            cantidad = fabricantes.actualizar()
        except Exception as error:      # sin internet, proxy, sitio bloqueado...
            return self._error(502, f"No se pudo descargar la lista ({error}). Puede bajarla con el "
                                    f"navegador desde {fabricantes.URL_OUI} y guardarla como "
                                    f"{config.ruta_archivo(fabricantes.ARCHIVO_OUI)}")
        return self._responder(200, {"ok": True, "cantidad": cantidad})

    def _accion_apagar(self, _):
        if not self._cliente_local():
            return self._error(403, "Solo se puede cerrar desde este PC.")
        self._auditar("cierre del programa")
        self._responder(200, {"ok": True})
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def instancia_existente(puerto):
    """¿Ya hay un Detector abierto en ese puerto? Devuelve "http", "https" o None."""
    for esquema in ("http", "https"):
        contexto = None
        if esquema == "https":
            # Solo consulta a este mismo programa en 127.0.0.1 (certificado autofirmado)
            contexto = ssl.create_default_context()
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(f"{esquema}://127.0.0.1:{puerto}/api/ping",
                                        timeout=1, context=contexto) as r:
                if json.loads(r.read().decode()).get("app") == "detector-red":
                    return esquema
        except (OSError, ValueError):
            continue
    return None


def contexto_tls(cfg):
    """Contexto TLS si config.json indica web_certificado y web_clave_tls; si no, None."""
    certificado, clave = cfg.get("web_certificado"), cfg.get("web_clave_tls")
    if not (certificado and clave):
        return None
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.load_cert_chain(certificado, clave)
    return contexto


def iniciar(cfg, abrir_navegador=True, puerto=None):
    puerto = puerto or cfg["web_puerto"]
    esquema = instancia_existente(puerto)
    if esquema:
        print(f" El programa ya está abierto en {esquema}://127.0.0.1:{puerto}/")
        if abrir_navegador:
            webbrowser.open(f"{esquema}://127.0.0.1:{puerto}/")
        return 0

    try:
        tls = contexto_tls(cfg)
    except (OSError, ssl.SSLError) as error:
        print(f" ❌ No se pudo cargar el certificado HTTPS ({error}). Revise web_certificado y web_clave_tls.")
        return 1

    acceso_red = bool(cfg.get("web_acceso_red") and cfg.get("web_clave"))
    direccion = "0.0.0.0" if acceso_red else "127.0.0.1"
    servidor = None
    for intento in range(puerto, puerto + 10):     # si el puerto está ocupado, prueba el siguiente
        try:
            servidor = ThreadingHTTPServer((direccion, intento), Manejador)
            puerto = intento
            break
        except OSError:
            continue
    if servidor is None:
        print(" ❌ No se encontró un puerto libre para la interfaz web. Use --consola.")
        return 1

    servidor.daemon_threads = True
    if tls:
        servidor.socket = tls.wrap_socket(servidor.socket, server_side=True)
    servidor.app = Aplicacion(cfg, puerto, acceso_red, tls=bool(tls))
    esquema = "https" if tls else "http"
    url = f"{esquema}://127.0.0.1:{puerto}/"
    print(f"\n 🌐 Interfaz abierta en {url}")
    if acceso_red:
        print(f"    Desde otros equipos: {esquema}://{escaner.obtener_ip_local()}:{puerto}/ (pide contraseña)")
        if not tls:
            print("    ⚠️ El acceso remoto va SIN CIFRAR: en una red compartida alguien podría ver la")
            print("       contraseña. Configure HTTPS (docs/SEGURIDAD.md) o úselo solo en redes de confianza.")
    print("    Cierre esta ventana o use 'Cerrar programa' en la página para salir.\n")
    registro.info("Interfaz web en %s:%d (acceso red=%s, https=%s)", direccion, puerto, acceso_red, bool(tls))
    if abrir_navegador:
        threading.Timer(0.7, webbrowser.open, [url]).start()
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        servidor.server_close()
    print(" Programa cerrado.")
    return 0
