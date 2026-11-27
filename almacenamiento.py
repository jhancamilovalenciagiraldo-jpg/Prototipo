"""Lectura y escritura segura de los archivos JSON."""

import contextlib
import json
import os
import shutil
import time

from detector_red import config


class ArchivoOcupado(Exception):
    """Otra instancia del programa está guardando datos en este momento."""


@contextlib.contextmanager
def bloqueo(espera=60, vencimiento=120):
    """Impide que dos instancias (tarea programada y menú) guarden a la vez y una
    pise los cambios de la otra. Un bloqueo abandonado vence a los 120 s."""
    ruta = config.ruta_archivo(".bloqueo")
    inicio = time.time()
    while True:
        try:
            fd = os.open(ruta, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(ruta) > vencimiento:
                    os.remove(ruta)
                    continue
            except OSError:
                continue
            if time.time() - inicio > espera:
                raise ArchivoOcupado("Otra instancia del programa está guardando datos.")
            time.sleep(0.5)
    try:
        yield
    finally:
        try:
            os.remove(ruta)
        except OSError:
            pass


def _solo_dueno(ruta):
    """Permisos 600 en Linux/macOS; en Windows %APPDATA% ya es privado por usuario."""
    if os.name != "nt":
        try:
            os.chmod(ruta, 0o600)
        except OSError:
            pass


def leer_json(nombre, defecto):
    ruta = config.ruta_archivo(nombre)
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return defecto
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Archivo dañado: se guarda una copia y se empieza de cero en vez de cerrar el programa
        respaldo = ruta + ".danado"
        shutil.copy2(ruta, respaldo)
        print(f" ⚠️ {nombre} estaba dañado; se guardó una copia en {respaldo}")
        return defecto


def escribir_json(nombre, datos):
    """Escritura atómica: si el programa se cierra a mitad, el archivo original
    queda intacto en vez de quedar cortado."""
    ruta = config.ruta_archivo(nombre)
    temporal = ruta + ".tmp"
    with open(temporal, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)
    try:
        os.replace(temporal, ruta)
    except PermissionError:      # p. ej. un antivirus tiene el archivo abierto
        shutil.copyfile(temporal, ruta)
        os.remove(temporal)
    _solo_dueno(ruta)


def respaldar(nombre, conservar=5):
    """Copia el archivo a 'respaldos' antes de borrar datos; guarda las 5 últimas."""
    origen = config.ruta_archivo(nombre)
    if not os.path.isfile(origen):
        return None
    carpeta = config.ruta_archivo("respaldos")
    os.makedirs(carpeta, exist_ok=True)
    base = nombre.rsplit(".", 1)[0]
    destino = os.path.join(carpeta, f"{base}-{time.strftime('%Y%m%d-%H%M%S')}.json")
    shutil.copy2(origen, destino)
    _solo_dueno(destino)
    copias = sorted(f for f in os.listdir(carpeta) if f.startswith(base + "-") and f.endswith(".json"))
    for viejo in copias[:-conservar]:
        try:
            os.remove(os.path.join(carpeta, viejo))
        except OSError:
            pass
    return destino


def tamano_archivo(nombre):
    try:
        return os.path.getsize(config.ruta_archivo(nombre))
    except OSError:
        return 0


def cargar_config():
    guardada = leer_json(config.ARCHIVO_CONFIG, {})
    cfg = dict(config.CONFIG_POR_DEFECTO)
    if isinstance(guardada, dict):
        cfg.update({k: v for k, v in guardada.items() if k in cfg})
    return cfg


def guardar_config(cfg):
    escribir_json(config.ARCHIVO_CONFIG, cfg)


def cargar_inventario_crudo():
    datos = leer_json(config.ARCHIVO_INVENTARIO, [])
    return datos if isinstance(datos, list) else []


def guardar_inventario(inventario):
    escribir_json(config.ARCHIVO_INVENTARIO, inventario)


def cargar_historial():
    datos = leer_json(config.ARCHIVO_HISTORIAL, [])
    return datos if isinstance(datos, list) else []


def guardar_historial(historial):
    escribir_json(config.ARCHIVO_HISTORIAL, historial)


def cargar_bajas():
    datos = leer_json(config.ARCHIVO_BAJAS, [])
    return datos if isinstance(datos, list) else []


def guardar_bajas(bajas):
    escribir_json(config.ARCHIVO_BAJAS, bajas)


def migrar_datos_antiguos():
    """Si la versión anterior dejó inventario.json / historial.json junto al
    código (o en la carpeta actual), los copia a la nueva carpeta de datos
    la primera vez. Los originales no se tocan."""
    destino = config.carpeta_datos()
    copiados = []
    candidatos = {os.getcwd(), config._carpeta_programa()}
    for nombre in (config.ARCHIVO_INVENTARIO, config.ARCHIVO_HISTORIAL):
        if os.path.exists(os.path.join(destino, nombre)):
            continue
        for carpeta in candidatos:
            origen = os.path.join(carpeta, nombre)
            if os.path.isfile(origen) and os.path.abspath(carpeta) != os.path.abspath(destino):
                shutil.copy2(origen, os.path.join(destino, nombre))
                copiados.append(origen)
                break
    return copiados
