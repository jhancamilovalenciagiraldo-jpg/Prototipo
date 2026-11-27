"""Lógica del escaneo completo, compartida por la consola y la interfaz web."""

import concurrent.futures as cf
import ipaddress
import logging
import platform
import time

from detector_red import (almacenamiento, config, descubrimiento, escaner, fabricantes,
                          inventario as inv, mantenimiento)
from detector_red.inventario import ahora_texto

registro = logging.getLogger("detector_red")
ARCHIVO_ESTADO = "estado.json"
ARCHIVO_ESTADISTICAS = "estadisticas.json"
MAX_ESTADISTICAS = 1000


def cargar_todo():
    return (inv.normalizar_inventario(almacenamiento.cargar_inventario_crudo()),
            almacenamiento.cargar_historial())


def guardar_todo(inventario, historial):
    almacenamiento.guardar_inventario(inventario)
    almacenamiento.guardar_historial(historial)


def ultimo_escaneo():
    """Datos del último escaneo (red, router, fecha...) o {}."""
    datos = almacenamiento.leer_json(ARCHIVO_ESTADO, {})
    return datos if isinstance(datos, dict) else {}


def _descubrir(ip_local, red, cfg):
    """mDNS y SSDP en paralelo (cada uno escucha ~3 s)."""
    tareas = {}
    with cf.ThreadPoolExecutor(max_workers=2) as pool:
        if cfg["descubrimiento_mdns"]:
            tareas["mdns"] = pool.submit(descubrimiento.descubrir_mdns, ip_local, red)
        if cfg["descubrimiento_ssdp"]:
            tareas["ssdp"] = pool.submit(descubrimiento.descubrir_ssdp, ip_local, red)
    resultados = {}
    for nombre, futuro in tareas.items():
        try:
            resultados[nombre] = futuro.result()
        except OSError as error:          # p. ej. multicast bloqueado por un firewall
            registro.warning("Descubrimiento %s falló: %s", nombre, error)
            resultados[nombre] = {}
    return resultados.get("mdns", {}), resultados.get("ssdp", {})


def escanear(cfg, perfil_forzado=None, red_forzada=None, mostrar=print):
    """Escaneo completo: ARP + mDNS/SSDP + nombres + actualización del inventario.

    'mostrar' recibe cada línea de progreso (print en consola, una lista en la web).
    Devuelve un diccionario con el resultado; si falla, {"ok": False, "error": ...}."""
    ip_local = escaner.obtener_ip_local()
    if ip_local.startswith("127."):
        registro.error("Sin conexión de red activa")
        return {"ok": False, "error": "No se encontró una conexión de red activa."}
    info = escaner.detectar_red(ip_local, cfg["max_hosts"], red_forzada or cfg["red_manual"])
    red, gateway = info["red"], info["gateway"]

    mostrar(f"Tu IP local: {ip_local}")
    mostrar(f"Red: {red} ({red.num_addresses - 2} IPs posibles)")
    mostrar(f"Router: {gateway or 'no detectado'}")
    if info["aviso"]:
        mostrar(f"⚠️ {info['aviso']}")

    perfil = perfil_forzado or cfg["perfil_router"]
    modo_perfil, medida = "manual", None
    if perfil == "auto":
        mostrar("Midiendo el router para elegir el perfil...")
        perfil, detalle, medida = escaner.elegir_perfil(gateway)
        modo_perfil = "auto"
        mostrar(f"Perfil automático: {perfil} ({detalle})")
    else:
        mostrar(f"Perfil: {perfil}")

    inicio = time.time()
    mostrar("[1/3] Escaneo ARP...")
    rondas = []
    encontrados = escaner.escanear(red, perfil, excluir={ip_local}, mostrar=mostrar,
                                   estadisticas=rondas)
    if info["mac_propia"]:
        encontrados[ip_local] = info["mac_propia"]

    mostrar("[2/3] Escuchando anuncios de los equipos (mDNS / SSDP)...")
    mdns, ssdp = _descubrir(ip_local, red, cfg)
    faltantes = sorted((set(mdns) | set(ssdp)) - set(encontrados) - {ip_local},
                       key=lambda i: int(ipaddress.IPv4Address(i)))
    extra = escaner.completar_macs(faltantes, red)
    encontrados.update(extra)
    if extra:
        mostrar(f"   → {len(extra)} equipos extra que no contestaron el ARP")

    vecinos6 = {}
    if cfg["vecinos_ipv6"]:
        vecinos6 = escaner.leer_vecinos_ipv6(info["interfaz"])
        nuevos6 = [m for m, v in vecinos6.items() if v["reciente"] and m not in encontrados.values()]
        if nuevos6:
            mostrar(f"   → {len(nuevos6)} equipos presentes por IPv6 que no contestaron el ARP")

    # Si hay varios equipos pero NINGUNO respondió mDNS ni SSDP, lo más probable
    # en Windows es que el firewall esté bloqueando las respuestas.
    aviso_firewall = (escaner.ES_WINDOWS and len(encontrados) >= 5 and cfg["descubrimiento_mdns"]
                      and cfg["descubrimiento_ssdp"] and not mdns and not ssdp)
    if aviso_firewall:
        mostrar("⚠️ Ningún equipo respondió a mDNS ni SSDP: puede ser el Firewall de Windows.")

    mostrar("[3/3] Obteniendo nombres y fabricantes...")
    nombres = {}
    if cfg["resolver_nombres"]:
        nombres.update(escaner.resolver_nombres(list(encontrados)))
    if cfg["netbios"]:
        nombres.update(descubrimiento.nombres_netbios([i for i in encontrados if i != ip_local]))
    # mDNS es la fuente más confiable de nombre: tiene prioridad
    nombres.update({ip: d["nombre"] for ip, d in mdns.items() if d.get("nombre")})

    detalles = {}
    for ip, mac in encontrados.items():
        servicios = mdns.get(ip, {}).get("servicios", set())
        detalles[ip] = {
            "servicios": servicios,
            "fabricante": fabricantes.buscar(mac),
            "tipo": descubrimiento.inferir_tipo(servicios, ssdp.get(ip), ip == gateway),
        }

    with almacenamiento.bloqueo():
        inventario, historial = cargar_todo()
        resumen = inv.actualizar_con_escaneo(
            inventario, historial, encontrados, red, nombres, ip_local=ip_local,
            detalles=detalles, gateway=gateway, fallos_para_inactivo=cfg["fallos_para_inactivo"],
            vecinos6=vecinos6, crear_solo_ipv6=bool(info["interfaz"]))
        limpieza = None
        if cfg["limpieza_automatica"]:
            bajas = almacenamiento.cargar_bajas()
            n_bajas = len(bajas)
            inventario, historial, limpieza = mantenimiento.limpieza_automatica(
                inventario, historial, bajas, cfg)
            if len(bajas) != n_bajas:
                almacenamiento.guardar_bajas(bajas)
        guardar_todo(inventario, historial)

    duracion = time.time() - inicio
    macs = sorted(set(encontrados.values())
                  | {m for m, v in vecinos6.items() if v["reciente"]} if info["interfaz"]
                  else set(encontrados.values()))
    resultado = {
        "ok": True, "fecha": ahora_texto(), "ip_local": ip_local, "red": str(red),
        "gateway": gateway, "perfil": perfil, "activos": len(macs),
        "duracion": round(duracion), "resumen": resumen, "limpieza": limpieza,
        "sugerencia": escaner.sugerir_perfil(perfil, rondas),
        "rondas": rondas, "fabricantes_disponible": fabricantes.disponible(),
        "aviso_firewall": aviso_firewall,
    }
    almacenamiento.escribir_json(ARCHIVO_ESTADO, dict(
        {k: resultado[k] for k in ("fecha", "ip_local", "red", "gateway", "perfil", "activos", "duracion")},
        macs=macs))

    # Sirven para calibrar los umbrales del perfil automático con datos reales
    estadisticas = almacenamiento.leer_json(ARCHIVO_ESTADISTICAS, [])
    if not isinstance(estadisticas, list):
        estadisticas = []
    estadisticas.append({
        "fecha": resultado["fecha"], "red": str(red), "sistema": platform.system(),
        "perfil": perfil, "modo_perfil": modo_perfil,
        "perdida": (medida or {}).get("perdida"), "latencia_ms": (medida or {}).get("latencia_ms"),
        "rondas": rondas, "activos": len(macs), "por_descubrimiento": len(extra),
        "respondieron_mdns": len(mdns), "respondieron_ssdp": len(ssdp),
        "vistos_ipv6": resumen["vistos_ipv6"], "solo_ipv6": resumen["solo_ipv6"],
        "duracion": round(duracion, 1),
    })
    almacenamiento.escribir_json(ARCHIVO_ESTADISTICAS, estadisticas[-MAX_ESTADISTICAS:])

    registro.info("Escaneo %s perfil=%s activos=%d nuevos=%d desconectados=%d alertas=%d %.0fs",
                  red, perfil, len(encontrados), resumen["nuevos"], resumen["desconectados"],
                  len(resumen["alertas"]), duracion)
    for alerta in resumen["alertas"]:
        registro.warning("ALERTA %s", alerta)
    return resultado


def borrar_datos(incluir_dispositivos, conservar_protegidos=True):
    """Borra el historial y, si se pide, también los dispositivos guardados y el
    archivo de bajas. Antes deja una copia en 'respaldos'."""
    with almacenamiento.bloqueo():
        archivos = [config.ARCHIVO_HISTORIAL]
        if incluir_dispositivos:
            archivos += [config.ARCHIVO_INVENTARIO, config.ARCHIVO_BAJAS]
        for nombre in archivos:
            almacenamiento.respaldar(nombre)
        inventario, _ = cargar_todo()
        borrados = 0
        if incluir_dispositivos:
            conservados, _ = mantenimiento.borrar_todo(inventario, conservar_protegidos)
            borrados = len(inventario) - len(conservados)
            almacenamiento.guardar_inventario(conservados)
            almacenamiento.guardar_bajas([])
        almacenamiento.guardar_historial([])
    return borrados


def eliminar_dispositivo(clave):
    """Elimina un dispositivo (buscado por MAC, IP o nombre) y sus eventos.
    Devuelve el dispositivo eliminado o None si no existe."""
    with almacenamiento.bloqueo():
        inventario, historial = cargar_todo()
        d = inv.buscar(inventario, str(clave))
        if d is None:
            return None
        almacenamiento.respaldar(config.ARCHIVO_INVENTARIO)
        almacenamiento.respaldar(config.ARCHIVO_HISTORIAL)
        inventario, historial = mantenimiento.eliminar_dispositivos(inventario, historial, [d])
        guardar_todo(inventario, historial)
    return d
