"""Validación del escaneo contra la lista de clientes del router.

Compara MAC por MAC y calcula la exhaustividad (equipos del router que el
programa encontró / equipos del router). Método completo en el README."""

import csv
import io

from detector_red import almacenamiento
from detector_red.escaner import PATRON_MAC, normalizar_mac
from detector_red.inventario import ahora_texto

ARCHIVO_VALIDACIONES = "validaciones.json"
MAX_VALIDACIONES = 1000


def extraer_macs(texto):
    macs = set()
    for coincidencia in PATRON_MAC.finditer(texto or ""):
        mac = normalizar_mac(coincidencia.group())
        if mac:
            macs.add(mac)
    return macs


def comparar(macs_router, macs_detectadas):
    router, detectadas = set(macs_router), set(macs_detectadas)
    coinciden = router & detectadas
    return {
        "metodo": "mac",
        "en_router": len(router),
        "detectados": len(detectadas),
        "coinciden": len(coinciden),
        "porcentaje": round(100 * len(coinciden) / len(router), 1) if router else None,
        "faltan": sorted(router - detectadas),
        "extra": sorted(detectadas - router),
    }


def comparar_conteo(cantidad_router, detectados):
    cantidad_router = int(cantidad_router)
    if cantidad_router <= 0:
        raise ValueError("La cantidad del router debe ser mayor que 0.")
    return {
        "metodo": "conteo",
        "en_router": cantidad_router,
        "detectados": detectados,
        "coinciden": None,
        "porcentaje": round(100 * min(detectados, cantidad_router) / cantidad_router, 1),
        "faltan": [], "extra": [],
    }


def cargar():
    datos = almacenamiento.leer_json(ARCHIVO_VALIDACIONES, [])
    return datos if isinstance(datos, list) else []


def registrar(resultado, ultimo_escaneo, nota="", nombres=None):
    """Guarda la validación junto con los datos del escaneo comparado."""
    nombres = nombres or {}
    registro = dict(resultado)
    registro.update({
        "fecha": ahora_texto(),
        "escaneo": ultimo_escaneo.get("fecha"),
        "red": ultimo_escaneo.get("red"),
        "perfil": ultimo_escaneo.get("perfil"),
        "duracion": ultimo_escaneo.get("duracion"),
        "nota": str(nota or "")[:200],
        "faltan": [{"mac": m, "nombre": nombres.get(m)} for m in resultado["faltan"]],
        "extra": [{"mac": m, "nombre": nombres.get(m)} for m in resultado["extra"]],
    })
    validaciones = cargar()
    validaciones.append(registro)
    almacenamiento.escribir_json(ARCHIVO_VALIDACIONES, validaciones[-MAX_VALIDACIONES:])
    return registro


def resumen_por_perfil(validaciones):
    """Promedio de detección por perfil (para la tabla del informe)."""
    grupos = {}
    for v in validaciones:
        if v.get("porcentaje") is None:
            continue
        grupos.setdefault(v.get("perfil") or "?", []).append(v["porcentaje"])
    return {perfil: {"validaciones": len(p), "promedio": round(sum(p) / len(p), 1),
                     "minimo": min(p), "maximo": max(p)}
            for perfil, p in grupos.items()}


def a_csv(validaciones):
    """CSV separado por punto y coma, que Excel en español abre directamente."""
    salida = io.StringIO()
    escritor = csv.writer(salida, delimiter=";")
    escritor.writerow(["fecha", "fecha_escaneo", "red", "perfil", "duracion_s", "metodo",
                       "equipos_router", "detectados", "coinciden", "porcentaje",
                       "faltan", "extra", "nota"])
    for v in validaciones:
        escritor.writerow([
            v.get("fecha"), v.get("escaneo"), v.get("red"), v.get("perfil"), v.get("duracion"),
            v.get("metodo"), v.get("en_router"), v.get("detectados"),
            _celda(v.get("coinciden")), _celda(v.get("porcentaje")),
            len(v.get("faltan") or []), len(v.get("extra") or []), _celda(v.get("nota", "")),
        ])
    return "﻿" + salida.getvalue()     # BOM: Excel reconoce las tildes


def _celda(valor):
    """Formato para Excel en español: decimales con coma y vacío si no hay dato."""
    if valor is None:
        return ""
    if isinstance(valor, float):
        return str(valor).replace(".", ",")
    # Inyección de fórmulas: Excel ejecuta celdas que empiezan con = + - @.
    # Una nota como "=HYPERLINK(...)" se guarda como texto anteponiendo '.
    if isinstance(valor, str) and valor[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + valor
    return valor


def estadisticas_a_csv(estadisticas):
    """Estadísticas de cada escaneo, para calibrar el perfil automático."""
    salida = io.StringIO()
    escritor = csv.writer(salida, delimiter=";")
    columnas = ["fecha", "red", "sistema", "perfil", "modo_perfil", "perdida", "latencia_ms",
                "ronda1", "ronda2", "ronda3", "activos", "por_descubrimiento",
                "respondieron_mdns", "respondieron_ssdp", "vistos_ipv6", "solo_ipv6", "duracion"]
    escritor.writerow(columnas)
    for e in estadisticas if isinstance(estadisticas, list) else []:
        rondas = list(e.get("rondas") or [])[:3]
        rondas += [None] * (3 - len(rondas))
        fila = dict(e, ronda1=rondas[0], ronda2=rondas[1], ronda3=rondas[2])
        escritor.writerow([_celda(fila.get(c)) for c in columnas])
    return "\ufeff" + salida.getvalue()
