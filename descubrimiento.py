"""Descubrimiento complementario al ARP: mDNS, SSDP y NetBIOS.

Encuentra equipos que no contestaron el ARP y obtiene su nombre y tipo.
mDNS usa consultas "legacy unicast" (RFC 6762 §6.7): se pregunta desde un
puerto distinto de 5353 y el equipo responde directo, sin competir con el
servicio mDNS del sistema. NetBIOS está en retirada y es solo complemento."""

import ipaddress
import random
import re
import select
import socket
import struct
import time

from detector_red.escaner import limpiar_texto

# Topes: un equipo malicioso en la red podría enviar miles de anuncios falsos
MAX_SERVICIOS = 40
MAX_INSTANCIAS = 20
MAX_TIPOS_VISTOS = 100
MAX_TIPOS_SSDP = 20

GRUPO_MDNS = ("224.0.0.251", 5353)
GRUPO_SSDP = ("239.255.255.250", 1900)
META_CONSULTA = "_services._dns-sd._udp.local"

TIPO_A, TIPO_PTR, TIPO_SRV = 1, 12, 33


def _codificar_nombre(nombre):
    salida = b""
    for etiqueta in nombre.strip(".").split("."):
        datos = etiqueta.encode("utf-8")
        salida += bytes([len(datos)]) + datos
    return salida + b"\x00"


def consulta_dns(nombre, tipo=TIPO_PTR, unicast=True, ident=None):
    """Arma un paquete de consulta DNS. 'unicast' enciende el bit QU (RFC 6762 §5.4)."""
    ident = random.randint(1, 0xFFFF) if ident is None else ident
    cabecera = struct.pack(">HHHHHH", ident, 0, 1, 0, 0, 0)
    clase = 0x8001 if unicast else 0x0001
    return cabecera + _codificar_nombre(nombre) + struct.pack(">HH", tipo, clase)


def _leer_nombre(datos, pos):
    """Lee un nombre DNS con soporte de compresión (punteros 0xC0)."""
    etiquetas, fin, saltos = [], None, 0
    while True:
        if pos >= len(datos):
            raise ValueError("nombre cortado")
        largo = datos[pos]
        if largo == 0:
            pos += 1
            break
        if largo & 0xC0 == 0xC0:
            if pos + 1 >= len(datos):
                raise ValueError("puntero cortado")
            if fin is None:
                fin = pos + 2
            pos = ((largo & 0x3F) << 8) | datos[pos + 1]
            saltos += 1
            if saltos > 30:
                raise ValueError("bucle de punteros")
            continue
        pos += 1
        etiquetas.append(datos[pos:pos + largo].decode("utf-8", "replace"))
        pos += largo
    return ".".join(etiquetas), (fin if fin is not None else pos)


def interpretar_dns(datos):
    """Devuelve (es_respuesta, [(nombre, tipo, valor), ...])."""
    if len(datos) < 12:
        raise ValueError("paquete corto")
    _, banderas, n_preg, n_resp, n_aut, n_adic = struct.unpack(">HHHHHH", datos[:12])
    pos = 12
    for _ in range(n_preg):
        _, pos = _leer_nombre(datos, pos)
        pos += 4
    registros = []
    for _ in range(n_resp + n_aut + n_adic):
        nombre, pos = _leer_nombre(datos, pos)
        if pos + 10 > len(datos):
            break
        tipo, _, _, largo = struct.unpack(">HHIH", datos[pos:pos + 10])
        pos += 10
        inicio = pos
        pos += largo
        valor = None
        if tipo == TIPO_A and largo == 4:
            valor = socket.inet_ntoa(datos[inicio:inicio + 4])
        elif tipo == TIPO_PTR:
            valor, _ = _leer_nombre(datos, inicio)
        elif tipo == TIPO_SRV and largo > 6:
            valor, _ = _leer_nombre(datos, inicio + 6)
        registros.append((nombre, tipo, valor))
    return bool(banderas & 0x8000), registros


def _servicio_corto(nombre):
    """'_ipp._tcp.local' -> 'ipp'. Solo acepta nombres de servicio válidos
    (letras, números y guiones, máx. 30), como define la RFC 6335."""
    partes = nombre.split(".")
    if not partes or not partes[0].startswith("_"):
        return None
    corto = partes[0].lstrip("_").lower()
    return corto if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,29}", corto) else None


def _sin_local(nombre):
    nombre = nombre[:-6] if nombre.lower().endswith(".local") else nombre
    return limpiar_texto(nombre)


def _socket_envio(ip_local):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.bind(("", 0))
    try:   # salir por la interfaz correcta si hay varias (Wi-Fi, cable, VPN)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip_local))
    except OSError:
        pass
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.setblocking(False)
    return s


def _socket_oyente_mdns(ip_local):
    """Escucha también en el 5353 compartido (algunos equipos responden solo por
    multicast). Si el sistema no lo permite, se sigue sin él."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s.bind(("", 5353))
        mreq = socket.inet_aton(GRUPO_MDNS[0]) + socket.inet_aton(ip_local)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.setblocking(False)
        return s
    except OSError:
        return None


def _en_red(ip, red):
    try:
        return ipaddress.IPv4Address(ip) in red
    except ValueError:
        return False


def descubrir_mdns(ip_local, red, duracion=3.0, max_tipos=30):
    """Devuelve {ip: {"nombre": str|None, "servicios": set, "instancias": set}}."""
    resultados = {}
    envio = _socket_envio(ip_local)
    oyente = _socket_oyente_mdns(ip_local)
    sockets = [s for s in (envio, oyente) if s]
    tipos_vistos, tipos_consultados = set(), set()

    def info(ip):
        return resultados.setdefault(ip, {"nombre": None, "servicios": set(), "instancias": set()})

    try:
        envio.sendto(consulta_dns(META_CONSULTA), GRUPO_MDNS)
        fin = time.time() + duracion
        segunda_fase = time.time() + duracion / 3
        while True:
            ahora = time.time()
            if ahora >= fin:
                break
            # Segunda fase: por cada tipo de servicio, sus instancias y nombres
            if ahora >= segunda_fase:
                for tipo in list(tipos_vistos - tipos_consultados)[:max_tipos]:
                    tipos_consultados.add(tipo)
                    try:
                        envio.sendto(consulta_dns(tipo), GRUPO_MDNS)
                    except OSError:
                        pass
            listos, _, _ = select.select(sockets, [], [], min(0.2, fin - ahora))
            for s in listos:
                try:
                    datos, (ip, _) = s.recvfrom(9000)
                except OSError:
                    continue
                if ip == ip_local or not _en_red(ip, red):
                    continue
                try:
                    es_respuesta, registros = interpretar_dns(datos)
                except (ValueError, struct.error, IndexError):
                    continue
                if not es_respuesta:
                    continue
                for nombre, tipo, valor in registros:
                    if not valor:
                        continue
                    if tipo == TIPO_PTR and nombre.lower() == META_CONSULTA:
                        corto = _servicio_corto(valor)
                        if corto and len(tipos_vistos) < MAX_TIPOS_VISTOS:
                            tipos_vistos.add(valor)
                        if corto and len(info(ip)["servicios"]) < MAX_SERVICIOS:
                            info(ip)["servicios"].add(corto)
                    elif tipo == TIPO_PTR:
                        corto = _servicio_corto(nombre)
                        if corto and len(info(ip)["servicios"]) < MAX_SERVICIOS:
                            info(ip)["servicios"].add(corto)
                        instancia = limpiar_texto(valor.split("._")[0])
                        if instancia and len(info(ip)["instancias"]) < MAX_INSTANCIAS:
                            info(ip)["instancias"].add(instancia)
                    elif tipo == TIPO_A and _en_red(valor, red) and valor != ip_local:
                        info(valor)["nombre"] = _sin_local(nombre)
                    elif tipo == TIPO_SRV:
                        info(ip).setdefault("_srv", _sin_local(valor))
    finally:
        for s in sockets:
            s.close()

    for datos in resultados.values():
        if not datos["nombre"]:
            datos["nombre"] = datos.pop("_srv", None) or next(iter(sorted(datos["instancias"])), None)
        datos.pop("_srv", None)
    return resultados


M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode("ascii")


def interpretar_ssdp(texto):
    cabeceras = {}
    for linea in texto.splitlines()[1:]:
        if ":" in linea:
            clave, valor = linea.split(":", 1)
            cabeceras[clave.strip().lower()] = valor.strip()
    return cabeceras


def descubrir_ssdp(ip_local, red, duracion=3.0):
    """Devuelve {ip: {"servidor": str, "tipos": set}}."""
    resultados = {}
    s = _socket_envio(ip_local)
    try:
        s.sendto(M_SEARCH, GRUPO_SSDP)
        reenviado = False
        fin = time.time() + duracion
        while time.time() < fin:
            if not reenviado and time.time() > fin - duracion / 2:
                s.sendto(M_SEARCH, GRUPO_SSDP)       # UDP puede perderse: segundo intento
                reenviado = True
            listos, _, _ = select.select([s], [], [], 0.2)
            if not listos:
                continue
            try:
                datos, (ip, _) = s.recvfrom(4096)
            except OSError:
                continue
            if ip == ip_local or not _en_red(ip, red):
                continue
            cab = interpretar_ssdp(datos.decode("utf-8", "replace"))
            info = resultados.setdefault(ip, {"servidor": "", "tipos": set()})
            if cab.get("server"):
                info["servidor"] = limpiar_texto(cab["server"], 120) or ""
            if cab.get("st") and len(info["tipos"]) < MAX_TIPOS_SSDP:
                tipo_ssdp = limpiar_texto(cab["st"], 120)
                if tipo_ssdp:
                    info["tipos"].add(tipo_ssdp)
    finally:
        s.close()
    return resultados


def consulta_nbstat(ident):
    nombre = b"*" + b"\x00" * 15
    codificado = bytes(c for b in nombre for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    return (struct.pack(">HHHHHH", ident, 0, 1, 0, 0, 0)
            + b"\x20" + codificado + b"\x00" + struct.pack(">HH", 0x21, 0x01))


def interpretar_nbstat(datos):
    """Devuelve el nombre del equipo (sufijo 0x00, nombre único) o None."""
    pos = 12
    if datos[pos] & 0xC0 == 0xC0:
        pos += 2
    else:
        _, pos = _leer_nombre(datos, pos)
    tipo, _, _, _ = struct.unpack(">HHIH", datos[pos:pos + 10])
    pos += 10
    if tipo != 0x21:
        return None
    cantidad = datos[pos]
    pos += 1
    for i in range(cantidad):
        entrada = datos[pos + 18 * i: pos + 18 * (i + 1)]
        if len(entrada) < 18:
            break
        nombre = limpiar_texto(entrada[:15].decode("ascii", "replace"), 15)
        sufijo = entrada[15]
        banderas = struct.unpack(">H", entrada[16:18])[0]
        if sufijo == 0x00 and not banderas & 0x8000 and nombre:
            return nombre
    return None


def nombres_netbios(ips, duracion=1.5):
    """Pregunta su nombre NetBIOS a cada IP. Devuelve {ip: nombre}."""
    if not ips:
        return {}
    resultados = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    try:
        for i, ip in enumerate(ips):
            try:
                s.sendto(consulta_nbstat(i + 1), (ip, 137))
            except OSError:
                pass
        fin = time.time() + duracion
        while time.time() < fin and len(resultados) < len(ips):
            listos, _, _ = select.select([s], [], [], 0.2)
            if not listos:
                continue
            try:
                datos, (ip, _) = s.recvfrom(2048)
                nombre = interpretar_nbstat(datos)
            except (OSError, ValueError, struct.error, IndexError):
                continue
            if nombre and ip in ips:
                resultados[ip] = nombre
    finally:
        s.close()
    return resultados


_PISTAS_SERVICIO = [
    ({"ipp", "ipps", "printer", "pdl-datastream", "scanner", "uscan"}, "Impresora"),
    ({"googlecast"}, "TV / Chromecast"),
    ({"airplay", "raop"}, "Apple TV / AirPlay"),
    ({"companion-link", "apple-mobdev2", "rdlink"}, "iPhone / iPad"),
    ({"hap", "homekit"}, "Domótica"),
    ({"spotify-connect", "sonos"}, "Parlante"),
    ({"smb", "afpovertcp", "nfs"}, "PC / NAS"),
    ({"rfb", "ssh", "sftp-ssh", "workstation"}, "Computador"),
]

_PISTAS_SSDP = [
    ("internetgatewaydevice", "Router"),
    ("mediarenderer", "TV / Multimedia"),
    ("roku", "TV / Roku"),
    ("printer", "Impresora"),
    ("dial", "TV / Smart TV"),
    ("camera", "Cámara"),
]


def inferir_tipo(servicios=(), ssdp=None, es_gateway=False):
    """Devuelve un tipo PROBABLE (es una pista, no una certeza)."""
    if es_gateway:
        return "Router"
    servicios = {s.lower() for s in servicios}
    for claves, tipo in _PISTAS_SERVICIO:
        if servicios & claves:
            return tipo
    if ssdp:
        texto = (ssdp.get("servidor", "") + " " + " ".join(ssdp.get("tipos", ()))).lower()
        for clave, tipo in _PISTAS_SSDP:
            if clave in texto:
                return tipo
    return None
