"""Configuración, perfiles de router y rutas de los archivos de datos."""

import os
import sys

NOMBRE_APP = "DetectorRed"

# Perfiles según la capacidad del router.
#   hilos / lote: consultas simultáneas y cuántas se envían antes de pausar
#   rondas: reintentos para equipos que no respondieron (celulares dormidos)
#   espera_arp: tiempo para que lleguen las respuestas antes de leer la tabla
PERFILES = {
    "baja": {
        "hilos": 24, "lote": 24, "pausa_lote": 0.5,
        "rondas": 3, "espera_ronda": 2.5, "espera_arp": 1.0,
    },
    "media": {
        "hilos": 64, "lote": 64, "pausa_lote": 0.15,
        "rondas": 2, "espera_ronda": 2.0, "espera_arp": 0.8,
    },
    "alta": {
        "hilos": 128, "lote": 256, "pausa_lote": 0.05,
        "rondas": 2, "espera_ronda": 1.5, "espera_arp": 0.8,
    },
}

CONFIG_POR_DEFECTO = {
    "perfil_router": "auto",           # auto mide el router y elige baja/media/alta
    "red_manual": "",                  # vacío = detectar; ej. "192.168.0.0/22"
    "max_hosts": 1024,                 # evita escanear por error una /16 (65 000 IPs)
    "resolver_nombres": True,
    "descubrimiento_mdns": True,
    "descubrimiento_ssdp": True,
    "netbios": True,
    "vecinos_ipv6": True,
    # Con 1, un celular dormido aparece como desconectado/reconectado en cada escaneo
    "fallos_para_inactivo": 2,

    "limpieza_automatica": True,
    "retencion_historial_dias": 180,
    "max_eventos_historial": 5000,
    "baja_automatica": False,
    "dias_para_baja": 90,
    "dias_para_baja_mac_aleatoria": 30,  # las MAC privadas cambian: se limpian antes
    "archivar_bajas": True,
    "max_bajas_archivadas": 2000,

    "aviso_aceptado": False,

    "web_puerto": 8765,
    "web_acceso_red": False,           # True: otros equipos pueden entrar, con contraseña
    "web_bloqueo_local": False,        # True: también se pide contraseña en este PC
    "web_clave": "",                   # hash PBKDF2, nunca la contraseña en texto
    "web_certificado": "",             # rutas .pem para HTTPS (docs/SEGURIDAD.md)
    "web_clave_tls": "",
}

FORMATO_FECHA = "%Y-%m-%d %H:%M:%S"


def _carpeta_programa():
    """Carpeta donde está el programa (el .exe o la raíz del código fuente)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def carpeta_datos():
    """Carpeta de datos, en este orden: variable DETECTOR_RED_DATOS, carpeta
    "datos" junto al programa (modo portable) o la carpeta del usuario, que
    sobrevive a reinstalar."""
    ruta = os.environ.get("DETECTOR_RED_DATOS")
    if not ruta:
        portable = os.path.join(_carpeta_programa(), "datos")
        if os.path.isdir(portable):
            ruta = portable
        elif os.name == "nt":
            ruta = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), NOMBRE_APP)
        elif sys.platform == "darwin":
            ruta = os.path.join(os.path.expanduser("~/Library/Application Support"), NOMBRE_APP)
        else:
            base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
            ruta = os.path.join(base, NOMBRE_APP)
    os.makedirs(ruta, exist_ok=True)
    return ruta


def ruta_archivo(nombre):
    return os.path.join(carpeta_datos(), nombre)


ARCHIVO_INVENTARIO = "inventario.json"
ARCHIVO_HISTORIAL = "historial.json"
ARCHIVO_BAJAS = "bajas.json"
ARCHIVO_CONFIG = "config.json"
