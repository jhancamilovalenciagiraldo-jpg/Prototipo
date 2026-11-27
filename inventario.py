"""Inventario de dispositivos (identificados por MAC) y registro de eventos.

El historial solo guarda cambios (nuevo, desconectado, cambio de IP, alertas),
no una línea por escaneo."""

import ipaddress
from datetime import datetime

from detector_red.config import FORMATO_FECHA
from detector_red.escaner import es_mac_aleatoria, limpiar_texto, normalizar_mac

ACTIVO = "activo"
INACTIVO = "inactivo"

# Nombres que comparten miles de equipos: no sirven para reconocer a un
# celular que cambió de MAC aleatoria.
NOMBRES_GENERICOS = {
    "android", "iphone", "ipad", "localhost", "unknown", "espressif", "esp32",
    "esp8266", "galaxy", "samsung", "xiaomi", "redmi", "huawei", "dispositivo",
    "desktop", "laptop", "pc", "tv", "chromecast", "amazon", "echo",
}


def ahora_texto(ahora=None):
    return (ahora or datetime.now()).strftime(FORMATO_FECHA)


def leer_fecha(texto):
    try:
        return datetime.strptime(texto, FORMATO_FECHA)
    except (TypeError, ValueError):
        return None


def _ip_num(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 0


CAMPOS_POR_DEFECTO = {
    "hostname": None, "red": None, "fabricante": None, "tipo": None,
    "servicios": [], "ips_extra": [], "macs_anteriores": [], "fallos": 0, "ipv6": [],
    "tipo_manual": False,
    "protegido": False, "es_gateway": False, "origen": "escaneo",
}


def normalizar_dispositivo(d, ahora=None):
    """Completa campos faltantes y valida tipos. None si no es un equipo real
    (p. ej. la dirección de broadcast .255 con MAC FF-FF-FF-FF-FF-FF)."""
    if not isinstance(d, dict) or not (d.get("ip") or d.get("ipv6")):
        return None
    if d.get("ip") and not isinstance(d["ip"], str):
        return None
    mac_texto = str(d.get("mac") or "")
    mac = normalizar_mac(mac_texto)
    if mac is None and mac_texto and "X" not in mac_texto.upper():
        return None                  # broadcast / multicast: no es un equipo
    fecha = ahora_texto(ahora)
    estado = str(d.get("estado", INACTIVO)).lower()
    n = {k: (list(v) if isinstance(v, list) else v) for k, v in CAMPOS_POR_DEFECTO.items()}
    n.update({k: d[k] for k in CAMPOS_POR_DEFECTO if k in d})
    # Pueden venir de la red o de un archivo editado a mano
    for campo, maximo in (("hostname", 63), ("tipo", 40), ("fabricante", 80), ("red", 43)):
        n[campo] = limpiar_texto(n[campo], maximo) if n[campo] is not None else None
    for campo in ("servicios", "ips_extra", "macs_anteriores", "ipv6"):
        valor = n[campo] if isinstance(n[campo], list) else []
        n[campo] = [x for x in (limpiar_texto(v, 45) for v in valor[:20]) if x]
    n["fallos"] = n["fallos"] if isinstance(n["fallos"], int) else 0
    n.update({
        "nombre": limpiar_texto(d.get("nombre"), 60) or f"Dispositivo_{(d.get('ip') or 'IPv6').split('.')[-1]}",
        "nombre_auto": d.get("nombre_auto", str(d.get("nombre", "")).startswith("Dispositivo_")),
        "ip": d.get("ip") or "",
        "mac": mac,
        "estado": estado if estado in (ACTIVO, INACTIVO) else INACTIVO,
        "primera_vez": d.get("primera_vez") if leer_fecha(d.get("primera_vez")) else fecha,
        "ultima_vez": d.get("ultima_vez") if leer_fecha(d.get("ultima_vez")) else fecha,
        "mac_aleatoria": es_mac_aleatoria(mac) if mac else False,
        "protegido": bool(d.get("protegido", False)),
    })
    return n


def normalizar_inventario(lista, ahora=None):
    resultado, vistos = [], set()
    for d in lista:
        n = normalizar_dispositivo(d, ahora)
        if n is None:
            continue
        clave = n["mac"] or ("ip", n["ip"] or tuple(n["ipv6"]))
        if clave in vistos:
            continue
        vistos.add(clave)
        resultado.append(n)
    return resultado


def registrar_evento(historial, evento, dispositivo, detalle="", ahora=None):
    historial.append({
        "fecha": ahora_texto(ahora),
        "evento": evento,
        "nombre": dispositivo.get("nombre"),
        "ip": dispositivo.get("ip"),
        "mac": dispositivo.get("mac"),
        "detalle": detalle,
    })


def _pertenece(dispositivo, red):
    if dispositivo.get("red"):
        return dispositivo["red"] == str(red)
    try:
        return ipaddress.IPv4Address(dispositivo["ip"]) in red
    except ValueError:
        return False


def _nombre_automatico(ip, red, hostname):
    if hostname:
        return hostname
    octetos = ip.split(".")
    sufijo = octetos[-1] if red.prefixlen >= 24 else "_".join(octetos[-2:])
    return f"Dispositivo_{sufijo}"


def _nombre_util(nombre):
    if not nombre:
        return False
    base = nombre.lower().split(".")[0]
    return len(base) >= 4 and base not in NOMBRES_GENERICOS


def actualizar_con_escaneo(inventario, historial, encontrados, red, nombres=None,
                           ahora=None, ip_local=None, detalles=None, gateway=None,
                           fallos_para_inactivo=2, vecinos6=None, crear_solo_ipv6=False):
    """Mezcla el escaneo {ip: mac} con el inventario y devuelve un resumen de cambios.

    nombres {ip: nombre}, detalles {ip: {tipo, fabricante, servicios}},
    vecinos6 {mac: {ipv6, reciente}}. crear_solo_ipv6 solo debe ser True si la
    tabla IPv6 es de la interfaz escaneada."""
    nombres = nombres or {}
    detalles = detalles or {}
    fecha = ahora_texto(ahora)
    resumen = {"nuevos": 0, "reconectados": 0, "desconectados": 0,
               "cambios_ip": 0, "cambios_mac": 0, "sin_cambios": 0, "alertas": [],
               "solo_ipv6": 0, "vistos_ipv6": 0}
    por_mac = {d["mac"]: d for d in inventario if d["mac"]}
    vistos = set()

    # Un repetidor en modo "universal" responde con su propia MAC por todos sus
    # clientes: el registro conserva una IP y las demás van a ips_extra.
    ips_por_mac = {}
    for ip, mac in encontrados.items():
        ips_por_mac.setdefault(mac, []).append(ip)

    # Si la MAC del router cambia: router nuevo o suplantación ARP
    if gateway and gateway in encontrados:
        mac_gw = encontrados[gateway]
        anterior = next((d for d in inventario if d.get("es_gateway") and _pertenece(d, red)), None)
        if anterior and anterior["mac"] and anterior["mac"] != mac_gw:
            texto = f"La MAC del router cambió: {anterior['mac']} -> {mac_gw}"
            registrar_evento(historial, "alerta_router", anterior, texto, ahora=ahora)
            resumen["alertas"].append(texto + " (¿router nuevo o suplantación ARP?)")
            anterior["es_gateway"] = False

    for mac, ips in sorted(ips_por_mac.items(), key=lambda par: min(_ip_num(i) for i in par[1])):
        ips.sort(key=_ip_num)
        d = por_mac.get(mac)
        ip = d["ip"] if d is not None and d["ip"] in ips else ips[0]
        extra = [i for i in ips if i != ip]
        hostname = nombres.get(ip)
        info = detalles.get(ip, {})

        if d is None:
            # ¿Un registro viejo sin MAC (XX:XX...) con esa misma IP? Se completa.
            d = next((x for x in inventario if not x["mac"] and x["ip"] == ip), None)
            if d is not None:
                d["mac"], d["mac_aleatoria"] = mac, es_mac_aleatoria(mac)
                por_mac[mac] = d

        if d is None and es_mac_aleatoria(mac) and _nombre_util(hostname):
            # MAC privada rotativa (iOS 18 / Android 12+): mismo nombre, otra MAC
            d = next((x for x in inventario
                      if x.get("mac_aleatoria") and id(x) not in vistos
                      and x["mac"] not in ips_por_mac and x.get("hostname") and x["hostname"].lower() == hostname.lower()), None)
            if d is not None:
                registrar_evento(historial, "cambio_mac", d, f"{d['mac']} -> {mac}", ahora=ahora)
                d["macs_anteriores"] = (d.get("macs_anteriores") or [])[-9:] + [d["mac"]]
                por_mac.pop(d["mac"], None)
                d["mac"] = mac
                por_mac[mac] = d
                resumen["cambios_mac"] += 1

        if d is None:
            d = normalizar_dispositivo({
                "nombre": "Este equipo" if ip == ip_local else _nombre_automatico(ip, red, hostname),
                "nombre_auto": ip != ip_local, "ip": ip, "mac": mac, "estado": ACTIVO,
                "red": str(red), "primera_vez": fecha, "ultima_vez": fecha,
            }, ahora)
            inventario.append(d)
            por_mac[mac] = d
            registrar_evento(historial, "nuevo", d, ahora=ahora)
            resumen["nuevos"] += 1
        else:
            cambio = False
            if d["ip"] != ip:
                registrar_evento(historial, "cambio_ip", d, f"{d['ip']} -> {ip}", ahora=ahora)
                d["ip"] = ip
                resumen["cambios_ip"] += 1
                cambio = True
            if d["estado"] != ACTIVO:
                d["estado"] = ACTIVO
                registrar_evento(historial, "reconectado", d, ahora=ahora)
                resumen["reconectados"] += 1
                cambio = True
            if not cambio:
                resumen["sin_cambios"] += 1

        if extra and not d.get("ips_extra"):
            texto = f"{mac} responde por {len(ips)} IPs ({', '.join(ips[:5])})"
            registrar_evento(historial, "alerta_misma_mac", d, texto, ahora=ahora)
            resumen["alertas"].append(texto + " (¿repetidor Wi-Fi o suplantación ARP?)")
        d["ips_extra"] = extra
        d["fallos"] = 0
        d["red"] = str(red)
        d["ultima_vez"] = fecha
        if hostname:
            d["hostname"] = hostname
            if d.get("nombre_auto"):
                d["nombre"] = hostname
        for campo in ("tipo", "fabricante"):
            # Un tipo corregido a mano por el usuario nunca se sobrescribe
            if info.get(campo) and not (campo == "tipo" and d.get("tipo_manual")):
                d[campo] = info[campo]
        if info.get("servicios"):
            d["servicios"] = sorted(info["servicios"])[:15]
        if gateway and ip == gateway:
            d["es_gateway"] = True
            d["tipo"] = d.get("tipo") or "Router"
            if d.get("nombre_auto") and not hostname:
                d["nombre"] = "Router"
        vistos.add(id(d))

    for mac, info6 in (vecinos6 or {}).items():
        d = por_mac.get(mac)
        if d is not None:
            d["ipv6"] = sorted(set(d.get("ipv6") or []) | set(info6["ipv6"]))[:8]
        if not info6.get("reciente") or (d is not None and id(d) in vistos):
            continue
        if d is None:
            if not crear_solo_ipv6:
                continue
            d = normalizar_dispositivo({
                "nombre": f"Dispositivo_IPv6_{mac[-5:].replace(':', '')}", "nombre_auto": True,
                "ip": "", "ipv6": sorted(info6["ipv6"])[:8], "mac": mac, "estado": ACTIVO,
                "red": str(red), "primera_vez": fecha, "ultima_vez": fecha,
            }, ahora)
            inventario.append(d)
            por_mac[mac] = d
            registrar_evento(historial, "nuevo", d, "visto solo por IPv6", ahora=ahora)
            resumen["nuevos"] += 1
            resumen["solo_ipv6"] += 1
        else:
            # Presente por IPv6 aunque no contestó el ARP
            if d["ip"] and encontrados.get(d["ip"]) not in (None, mac):
                d["ip"] = ""          # su IPv4 anterior ya la tiene otro equipo
            if d["estado"] != ACTIVO:
                d["estado"] = ACTIVO
                registrar_evento(historial, "reconectado", d, "visto por IPv6", ahora=ahora)
                resumen["reconectados"] += 1
            d["fallos"] = 0
            d["red"] = str(red)
            d["ultima_vez"] = fecha
            resumen["vistos_ipv6"] += 1
        vistos.add(id(d))

    # Inactivo tras N escaneos seguidos sin verse (evita que un celular dormido
    # parpadee en el historial), o de inmediato si otro equipo ya usa su IP.
    for d in inventario:
        if id(d) in vistos or d["estado"] != ACTIVO or not _pertenece(d, red):
            continue
        d["fallos"] = d.get("fallos", 0) + 1
        ip_ocupada = bool(d["ip"]) and d["ip"] in encontrados
        if ip_ocupada or d["fallos"] >= max(1, fallos_para_inactivo):
            d["estado"] = INACTIVO
            detalle = "su IP ahora la usa otro equipo" if ip_ocupada else ""
            registrar_evento(historial, "desconectado", d, detalle, ahora=ahora)
            resumen["desconectados"] += 1

    return resumen


def validar_ip(ip):
    try:
        ipaddress.IPv4Address(ip.strip())
        return True
    except ValueError:
        return False


def validar_mac(mac):
    return normalizar_mac(mac) is not None


def agregar_manual(inventario, historial, nombre, ip, mac, ahora=None):
    """Devuelve (ok, mensaje)."""
    mac_n = normalizar_mac(mac) if mac else None
    if mac and not mac_n:
        return False, "MAC no válida."
    for d in inventario:
        if d["nombre"].lower() == nombre.lower():
            return False, f"Ya existe un dispositivo llamado '{nombre}'."
        if mac_n and d["mac"] == mac_n:
            return False, f"Esa MAC ya está registrada como '{d['nombre']}'."
    fecha = ahora_texto(ahora)
    d = normalizar_dispositivo({
        "nombre": nombre, "nombre_auto": False, "ip": ip.strip(), "mac": mac_n or "",
        "estado": INACTIVO, "primera_vez": fecha, "ultima_vez": fecha, "origen": "manual",
    }, ahora)
    inventario.append(d)
    registrar_evento(historial, "agregado_manual", d, ahora=ahora)
    return True, f"'{nombre}' agregado. Su estado se actualizará en el próximo escaneo."


def buscar_por_mac(inventario, mac):
    mac_n = normalizar_mac(mac)
    if not mac_n:
        return None
    return next((d for d in inventario if d["mac"] == mac_n), None)


def buscar(inventario, texto):
    """Busca por MAC, IP o nombre."""
    encontrado = buscar_por_mac(inventario, texto or "")
    if encontrado:
        return encontrado
    texto = (texto or "").strip().lower()
    for d in inventario:
        if (d["ip"] and d["ip"] == texto) or d["nombre"].lower() == texto \
                or texto in (d.get("ipv6") or []):
            return d
    return None


def contar_estados(inventario):
    activos = sum(1 for d in inventario if d["estado"] == ACTIVO)
    return activos, len(inventario) - activos


def ordenar(inventario):
    def clave(d):
        try:
            return (0, int(ipaddress.IPv4Address(d["ip"])))
        except ValueError:
            return (1, 0)
    return sorted(inventario, key=clave)
