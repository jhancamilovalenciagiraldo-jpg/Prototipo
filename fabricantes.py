"""Fabricante de cada equipo según su MAC, con el registro OUI público de IEEE.

La lista no va dentro del programa porque IEEE la actualiza seguido; se
descarga desde la interfaz o con --actualizar-fabricantes."""

import csv
import io
import os
import urllib.request

from detector_red import config
from detector_red.escaner import es_mac_aleatoria, normalizar_mac

URL_OUI = "https://standards-oui.ieee.org/oui/oui.csv"
MAX_DESCARGA = 30 * 1024 * 1024        # la lista real pesa unos 3-4 MB
ARCHIVO_OUI = "oui.csv"

_tabla = None


def _rutas_posibles():
    yield config.ruta_archivo(ARCHIVO_OUI)
    yield os.path.join(config._carpeta_programa(), ARCHIVO_OUI)


def interpretar_csv(texto):
    tabla = {}
    for fila in csv.DictReader(io.StringIO(texto)):
        asignacion = (fila.get("Assignment") or "").strip().upper()
        nombre = (fila.get("Organization Name") or "").strip()
        if len(asignacion) == 6 and nombre:
            tabla[asignacion] = nombre
    return tabla


def cargar():
    global _tabla
    if _tabla is None:
        _tabla = {}
        for ruta in _rutas_posibles():
            if os.path.isfile(ruta):
                with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                    _tabla = interpretar_csv(f.read())
                break
    return _tabla


def disponible():
    return bool(cargar())


def buscar(mac):
    mac = normalizar_mac(mac)
    if not mac:
        return None
    if es_mac_aleatoria(mac):
        return "MAC privada"
    return cargar().get(mac.replace(":", "")[:6])


def actualizar(timeout=60):
    """Descarga la lista oficial. Devuelve la cantidad de fabricantes."""
    global _tabla
    pedido = urllib.request.Request(URL_OUI, headers={"User-Agent": "detector-red/0.7 (+open source)"})
    # El tope evita que una respuesta gigante llene la memoria
    with urllib.request.urlopen(pedido, timeout=timeout) as respuesta:
        datos = respuesta.read(MAX_DESCARGA + 1)
    if len(datos) > MAX_DESCARGA:
        raise ValueError("La descarga supera el tamaño esperado; se descartó.")
    texto = datos.decode("utf-8", "replace")
    tabla = interpretar_csv(texto)
    if len(tabla) < 1000:          # protección: no reemplazar con una descarga dañada
        raise ValueError("La descarga no parece la lista oficial de IEEE.")
    destino = config.ruta_archivo(ARCHIVO_OUI)
    with open(destino + ".tmp", "w", encoding="utf-8") as f:
        f.write(texto)
    os.replace(destino + ".tmp", destino)
    _tabla = tabla
    return len(tabla)
