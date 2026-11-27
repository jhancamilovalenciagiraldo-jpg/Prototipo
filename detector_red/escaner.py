"""Escaneo de la red local: subred, sondeo de cada IP y lectura de la tabla ARP.

Funciona en Windows, Linux y macOS sin dependencias ni permisos de
administrador. arp -a solo lista equipos que hablaron hace poco con el PC,
por eso antes de leerla se consulta cada IP de la subred."""

import concurrent.futures as cf
import ipaddress
import math
import os
import platform
import re
import socket
import statistics
import subprocess
import time
import unicodedata
import uuid

from detector_red.config import PERFILES

SISTEMA = platform.system()
ES_WINDOWS = SISTEMA == "Windows"
ES_MAC = SISTEMA == "Darwin"

# Evita que se abran ventanas negras de consola en el .exe de Windows
_SIN_VENTANA = getattr(subprocess, "CREATE_NO_WINDOW", 0) if ES_WINDOWS else 0

PATRON_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
PATRON_MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{1,2}[:-]){5}[0-9A-Fa-f]{1,2}(?![0-9A-Fa-f:-])")


def _ejecutar(comando, timeout=8):
    """Ejecuta un comando del sistema y devuelve (codigo, texto). Nunca lanza error."""
    try:
        r = subprocess.run(comando, capture_output=True, text=True, errors="replace",
                           timeout=timeout, creationflags=_SIN_VENTANA)
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError):
        return -1, ""


def normalizar_mac(mac):
    """Normaliza a 'AA:BB:CC:DD:EE:FF'. None si no es un equipo real
    (broadcast, multicast, ceros o texto inválido)."""
    if not mac:
        return None
    partes = re.split(r"[:-]", str(mac).strip())
    if len(partes) != 6:
        return None
    try:
        octetos = [int(p, 16) for p in partes]
    except ValueError:
        return None
    if any(o > 255 for o in octetos) or all(o == 0 for o in octetos):
        return None
    if octetos[0] & 1:          # bit de multicast/broadcast encendido
        return None
    return ":".join(f"{o:02X}" for o in octetos)


def es_mac_aleatoria(mac):
    """MAC privada de celulares: segundo carácter 2, 6, A o E (bit "local")."""
    mac = normalizar_mac(mac)
    return bool(mac) and bool(int(mac[:2], 16) & 2)


def limpiar_texto(texto, maximo=63):
    """Sanea texto llegado de la red: quita caracteres de control (escapes de
    terminal), invisibles y de dirección (U+202E) y limita el largo."""
    if texto is None:
        return None
    limpio = "".join(" " if unicodedata.category(c).startswith("C") else c for c in str(texto))
    limpio = " ".join(limpio.split())[:maximo].strip()
    return limpio or None


def _ips_en(texto):
    return PATRON_IP.findall(texto)


def obtener_ip_local():
    """IP de la interfaz con salida a internet. gethostbyname(hostname) puede
    devolver 127.0.1.1 o un adaptador virtual; el socket UDP no envía nada."""
    ip = None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except OSError:
        pass
    finally:
        s.close()
    if not ip or ip.startswith("127."):
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = "127.0.0.1"
    return ip


def _bloque_de_interfaz(texto, ip_local):
    """Bloque del adaptador que tiene la IP local en ipconfig /all, ip addr o
    ifconfig (cada bloque empieza en una línea sin sangría; vale en cualquier idioma)."""
    bloques, actual = [], []
    for linea in texto.splitlines():
        if linea and not linea[0].isspace() and actual:
            bloques.append(actual)
            actual = []
        actual.append(linea)
    if actual:
        bloques.append(actual)
    for bloque in bloques:
        for linea in bloque:
            if ip_local in _ips_en(linea):
                return bloque
    return []


def interpretar_ipconfig(texto, ip_local):
    """Windows (ipconfig /all, en cualquier idioma) -> (prefijo, gateway, mac)."""
    bloque = _bloque_de_interfaz(texto, ip_local)
    prefijo = gateway = mac = None
    visto_ip = False
    for linea in bloque:
        if mac is None:
            m = PATRON_MAC.search(linea)
            if m and len(re.split(r"[:-]", m.group())) == 6 and not visto_ip:
                mac = normalizar_mac(m.group())
        ips = _ips_en(linea)
        if ip_local in ips:
            visto_ip = True
            continue
        if not visto_ip:
            continue
        for ip in ips:
            if prefijo is None and ip.startswith("255."):
                try:
                    prefijo = ipaddress.IPv4Network(f"0.0.0.0/{ip}").prefixlen
                except ValueError:
                    pass
            elif prefijo is not None and gateway is None:
                gateway = ip
    return prefijo, gateway, mac


def interpretar_ip_addr(texto, ip_local):
    """Linux (ip addr show) -> (prefijo, mac)."""
    bloque = _bloque_de_interfaz(texto, ip_local)
    prefijo = mac = None
    for linea in bloque:
        m = re.search(r"inet\s+" + re.escape(ip_local) + r"/(\d+)", linea)
        if m:
            prefijo = int(m.group(1))
        m = re.search(r"link/ether\s+(\S+)", linea)
        if m:
            mac = normalizar_mac(m.group(1))
    return prefijo, mac


def interpretar_ifconfig(texto, ip_local):
    """macOS (ifconfig) -> (prefijo, mac)."""
    bloque = _bloque_de_interfaz(texto, ip_local)
    prefijo = mac = None
    for linea in bloque:
        m = re.search(r"inet\s+" + re.escape(ip_local) + r"\s+netmask\s+(0x[0-9a-fA-F]+|\S+)", linea)
        if m:
            mascara = m.group(1)
            if mascara.startswith("0x"):
                prefijo = bin(int(mascara, 16)).count("1")
            else:
                prefijo = ipaddress.IPv4Network(f"0.0.0.0/{mascara}").prefixlen
        m = re.search(r"\bether\s+(\S+)", linea)
        if m:
            mac = normalizar_mac(m.group(1))
    return prefijo, mac


def detectar_red(ip_local, max_hosts=1024, red_manual=""):
    """Devuelve un diccionario con la red a escanear, el gateway y la MAC propia."""
    prefijo = gateway = mac_propia = None

    if ES_WINDOWS:
        _, salida = _ejecutar(["ipconfig", "/all"])
        prefijo, gateway, mac_propia = interpretar_ipconfig(salida, ip_local)
        interfaz = nombre_interfaz(salida, ip_local, "windows")
    elif ES_MAC:
        _, salida = _ejecutar(["ifconfig"])
        prefijo, mac_propia = interpretar_ifconfig(salida, ip_local)
        interfaz = nombre_interfaz(salida, ip_local, "mac")
        _, salida = _ejecutar(["route", "-n", "get", "default"])
        m = re.search(r"gateway:\s*(\S+)", salida)
        gateway = m.group(1) if m else None
    else:
        _, salida = _ejecutar(["ip", "addr", "show"])
        prefijo, mac_propia = interpretar_ip_addr(salida, ip_local)
        interfaz = nombre_interfaz(salida, ip_local, "linux")
        _, salida = _ejecutar(["ip", "route", "show", "default"])
        m = re.search(r"default via (\S+)", salida)
        gateway = m.group(1) if m else _gateway_proc_route()

    aviso = None
    if red_manual:
        red = ipaddress.IPv4Network(red_manual, strict=False)
    else:
        if prefijo is None or not 8 <= prefijo <= 30:
            prefijo = 24
            aviso = "No se pudo leer la máscara de red; se asume /24."
        red = ipaddress.IPv4Network(f"{ip_local}/{prefijo}", strict=False)

    # Redes enormes (/16 = 65 534 IPs) tardarían horas: se acota alrededor de la IP local
    if red.num_addresses - 2 > max_hosts:
        nuevo_prefijo = 32 - math.ceil(math.log2(max_hosts + 2))
        original = red
        red = ipaddress.IPv4Network(f"{ip_local}/{nuevo_prefijo}", strict=False)
        aviso = (f"La red {original} es muy grande; se escanea solo {red}. "
                 f"Para otra cosa, configure 'red manual'.")

    if gateway:
        try:
            if ipaddress.IPv4Address(gateway) not in red:
                gateway = None
        except ValueError:
            gateway = None

    return {"red": red, "gateway": gateway, "mac_propia": mac_propia or _mac_por_uuid(),
            "aviso": aviso, "interfaz": interfaz}


def nombre_interfaz(texto, ip_local, formato):
    """Nombre del adaptador con la IP local, tomado de la primera línea de su bloque."""
    bloque = _bloque_de_interfaz(texto, ip_local)
    if not bloque:
        return None
    cabecera = bloque[0].strip()
    if formato == "windows":
        return cabecera.rstrip(":").strip() or None
    if formato == "linux":
        m = re.match(r"\d+:\s*([^:@\s]+)", cabecera)
        return m.group(1) if m else None
    return cabecera.split(":")[0] or None


def _gateway_proc_route():
    """Linux sin el comando 'ip': la ruta por defecto está en /proc/net/route."""
    try:
        with open("/proc/net/route") as f:
            for linea in f.readlines()[1:]:
                campos = linea.split()
                if len(campos) > 2 and campos[1] == "00000000":
                    return socket.inet_ntoa(int(campos[2], 16).to_bytes(4, "little"))
    except (OSError, ValueError):
        pass
    return None


def _mac_por_uuid():
    nodo = uuid.getnode()
    if (nodo >> 40) & 1:      # uuid inventó una MAC al azar: no sirve
        return None
    return normalizar_mac(":".join(f"{(nodo >> s) & 0xFF:02X}" for s in range(40, -1, -8)))


_sendarp = None


def _preparar_sendarp():
    """SendARP (Windows) pregunta la MAC directamente: funciona aunque el equipo
    bloquee el ping y no abre procesos."""
    global _sendarp
    if _sendarp is None:
        try:
            import ctypes
            funcion = ctypes.windll.iphlpapi.SendARP
            funcion.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_ulong)]
            funcion.restype = ctypes.c_ulong
            _sendarp = (ctypes, funcion)
        except (ImportError, AttributeError, OSError):
            _sendarp = False
    return _sendarp


def _sondear_windows(ip):
    preparado = _preparar_sendarp()
    if not preparado:
        return _sondear_udp(ip)
    ctypes, funcion = preparado
    destino = int.from_bytes(socket.inet_aton(ip), "little")
    buffer = (ctypes.c_ubyte * 8)()
    largo = ctypes.c_ulong(8)
    if funcion(destino, 0, buffer, ctypes.byref(largo)) == 0 and largo.value >= 6:
        return normalizar_mac("-".join(f"{b:02X}" for b in bytes(buffer)[:6]))
    return None


def _sondear_udp(ip):
    """Un datagrama UDP vacío obliga al sistema a resolver la MAC por ARP; es más
    liviano que abrir un proceso de ping por IP y no requiere administrador."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b"", (ip, 9))      # puerto 9 = "discard"
        finally:
            s.close()
    except OSError:
        pass
    return None


def sondear(ip):
    return _sondear_windows(ip) if ES_WINDOWS else _sondear_udp(ip)


def interpretar_tabla_arp(texto, red):
    """Sirve para 'arp -a' (Windows), /proc/net/arp, 'ip neigh' (Linux) y
    'arp -an' (macOS). Devuelve {ip: mac} solo de dispositivos reales de la red."""
    encontrados = {}
    for linea in texto.splitlines():
        ips = _ips_en(linea)
        m = PATRON_MAC.search(linea)
        if not ips or not m:
            continue
        ip = ips[0]
        try:
            direccion = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if direccion not in red or direccion in (red.network_address, red.broadcast_address):
            continue
        if "FAILED" in linea or "INCOMPLETE" in linea.upper():
            continue
        mac = normalizar_mac(m.group())
        if mac:
            encontrados[ip] = mac
    return encontrados


def leer_tabla_arp(red):
    if ES_WINDOWS:
        _, texto = _ejecutar(["arp", "-a"])
    elif ES_MAC:
        _, texto = _ejecutar(["arp", "-an"])
    else:
        try:
            with open("/proc/net/arp", "r") as f:
                texto = f.read()
        except OSError:
            _, texto = _ejecutar(["ip", "neigh"])
    return interpretar_tabla_arp(texto, red)


# IPv6 no se puede barrer (2^64 direcciones por red): solo se lee la tabla de
# vecinos que el sistema ya conoce.

# Estados que indican actividad reciente (inglés y español de Windows)
ESTADOS_RECIENTES = {"reachable", "delay", "probe", "accesible", "retraso", "sondeo"}
ESTADOS_INVALIDOS = {"unreachable", "inaccesible", "incomplete", "incompleto", "failed", "noarp", "no"}


def interpretar_vecinos_ipv6(texto, interfaz=None, formato="linux"):
    """{mac: {"ipv6": set, "reciente": bool}} desde netsh (windows), ip -6 neigh
    (linux) o ndp -an (mac). Con 'interfaz' se ignoran VPN y adaptadores virtuales."""
    resultado = {}
    bloque_valido = interfaz is None or formato != "windows"
    for linea in texto.splitlines():
        partes = linea.split()
        if not partes:
            continue
        try:
            direccion = ipaddress.IPv6Address(partes[0].split("%")[0])
        except ValueError:
            if formato == "windows":
                m = re.search(r"\s(\d+):\s+(.+?)\s*$", linea)     # "Interfaz 12: Wi-Fi"
                if m:
                    nombre = m.group(2)
                    bloque_valido = interfaz is None or interfaz == nombre or interfaz.endswith(" " + nombre)
            continue
        if not bloque_valido or direccion.is_multicast or direccion.is_unspecified:
            continue
        if formato == "mac" and interfaz and (len(partes) < 3 or partes[2] != interfaz):
            continue
        m = PATRON_MAC.search(" ".join(partes[1:]))
        mac = normalizar_mac(m.group()) if m else None
        if not mac:
            continue
        palabras = {p.strip("()").lower() for p in partes[1:]}
        if palabras & ESTADOS_INVALIDOS:
            continue
        if formato == "mac":
            # ndp: la columna 5 es el estado; la R de "Banderas" significa "es router"
            reciente = len(partes) > 4 and partes[4] in ("R", "D", "P")
        else:
            reciente = bool(palabras & ESTADOS_RECIENTES)
        info = resultado.setdefault(mac, {"ipv6": set(), "reciente": False})
        info["ipv6"].add(str(direccion))
        info["reciente"] = info["reciente"] or reciente
    return resultado


def leer_vecinos_ipv6(interfaz=None):
    if ES_WINDOWS:
        _, texto = _ejecutar(["netsh", "interface", "ipv6", "show", "neighbors"])
        formato = "windows"
    elif ES_MAC:
        _, texto = _ejecutar(["ndp", "-an"])
        formato = "mac"
    else:
        _, texto = _ejecutar(["ip", "-6", "neigh", "show"] + (["dev", interfaz] if interfaz else []))
        formato = "linux"
    return interpretar_vecinos_ipv6(texto, interfaz, formato)


def _ping(ip, timeout_ms=1000):
    if ES_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif ES_MAC:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]
    inicio = time.perf_counter()
    codigo, _ = _ejecutar(cmd, timeout=timeout_ms / 1000 + 2)
    return codigo == 0, time.perf_counter() - inicio


def medir_router(gateway, intentos=8):
    """(pérdida 0-1, latencia ms) o None. Se resta el tiempo de un ping a
    127.0.0.1 para no medir lo que tarda en abrirse el proceso."""
    base = [t for ok, t in (_ping("127.0.0.1") for _ in range(3)) if ok]
    if not base:
        return None                       # no hay comando ping disponible
    costo_proceso = statistics.median(base)
    tiempos, perdidos = [], 0
    for _ in range(intentos):
        ok, t = _ping(gateway)
        if ok:
            tiempos.append(max(0.0, t - costo_proceso) * 1000)
        else:
            perdidos += 1
    if not tiempos:
        return None                       # el router no responde ping
    return perdidos / intentos, statistics.median(tiempos)


def elegir_perfil(gateway):
    """(perfil, detalle, medida). Heurística: la señal Wi-Fi también influye en la
    latencia, por eso el perfil se puede fijar a mano."""
    if not gateway:
        return "media", "sin gateway detectado", None
    medida = medir_router(gateway)
    if medida is None:
        return "media", "el router no respondió al ping", None
    perdida, latencia = medida
    detalle = f"pérdida {perdida:.0%}, latencia {latencia:.0f} ms"
    datos = {"perdida": round(perdida, 3), "latencia_ms": round(latencia, 1)}
    if perdida >= 0.25 or latencia > 30:
        return "baja", detalle, datos
    if perdida > 0 or latencia > 8:
        return "media", detalle, datos
    return "alta", detalle, datos


def escanear(red, perfil, excluir=(), mostrar=print, estadisticas=None):
    """Escanea la red con el perfil dado y devuelve {ip: mac}. En 'estadisticas'
    agrega cuántos equipos aparecieron en cada ronda."""
    p = PERFILES[perfil]
    todas = [str(h) for h in red.hosts() if str(h) not in excluir]
    encontrados = {}
    pendientes = list(todas)

    with cf.ThreadPoolExecutor(max_workers=p["hilos"]) as pool:
        for ronda in range(1, p["rondas"] + 1):
            if not pendientes:
                break
            if ronda > 1:
                time.sleep(p["espera_ronda"])
            mostrar(f"   Ronda {ronda}/{p['rondas']}: consultando {len(pendientes)} IPs...")
            antes = len(encontrados)
            for i in range(0, len(pendientes), p["lote"]):
                lote = pendientes[i:i + p["lote"]]
                for ip, mac in zip(lote, pool.map(sondear, lote)):
                    if mac:
                        encontrados[ip] = mac
                time.sleep(p["espera_arp"])
                # Se lee tras cada lote porque en redes grandes el sistema
                # descarta entradas viejas cuando la tabla se llena
                encontrados.update(leer_tabla_arp(red))
                time.sleep(p["pausa_lote"])
            pendientes = [ip for ip in todas if ip not in encontrados]
            mostrar(f"   → {len(encontrados) - antes} nuevos en esta ronda (total {len(encontrados)})")
            if estadisticas is not None:
                estadisticas.append(len(encontrados) - antes)

    encontrados.update(leer_tabla_arp(red))
    return encontrados


def completar_macs(ips, red, espera=1.0):
    """Para IPs halladas por mDNS/SSDP que no estaban en la tabla ARP:
    se vuelven a consultar para obtener su MAC. Devuelve {ip: mac}."""
    resultado = {}
    if not ips:
        return resultado
    with cf.ThreadPoolExecutor(max_workers=min(32, len(ips))) as pool:
        for ip, mac in zip(ips, pool.map(sondear, ips)):
            if mac:
                resultado[ip] = mac
    time.sleep(espera)
    tabla = leer_tabla_arp(red)
    for ip in ips:
        if ip in tabla:
            resultado[ip] = tabla[ip]
    return resultado


def sugerir_perfil(perfil, estadisticas):
    """Si la 2.ª ronda encontró muchos equipos que la 1.ª no vio, la red está
    perdiendo respuestas: conviene un perfil más suave."""
    if len(estadisticas) < 2 or perfil == "baja":
        return None
    primera, segunda = estadisticas[0], estadisticas[1]
    if segunda >= 3 and segunda > 0.15 * max(primera, 1):
        return "baja" if perfil == "media" else "media"
    return None


def resolver_nombres(ips, timeout=4.0):
    """Intenta obtener el nombre de cada equipo (muchos routers lo informan).
    Si alguno tarda más que 'timeout' simplemente se deja sin nombre."""
    if not ips:
        return {}

    def nombre(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return None

    pool = cf.ThreadPoolExecutor(max_workers=min(32, len(ips)))
    futuros = {pool.submit(nombre, ip): ip for ip in ips}
    hechos, _ = cf.wait(futuros, timeout=timeout)
    pool.shutdown(wait=False, cancel_futures=True)
    resultado = {}
    for futuro in hechos:
        valor = futuro.result()
        if valor and not PATRON_IP.fullmatch(valor):
            nombre = limpiar_texto(valor.split(".")[0])
            if nombre:
                resultado[futuros[futuro]] = nombre
    return resultado
