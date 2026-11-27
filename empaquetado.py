"""Armado del ejecutable (PyInstaller) y del instalador (Inno Setup) desde la interfaz.

PyInstaller no compila para otros sistemas: en Windows produce un .exe, en
Linux un binario de Linux. Para los tres sistemas a la vez está el flujo de
GitHub Actions (.github/workflows/compilar.yml).
"""

import glob
import hashlib
import importlib.util
import os
import platform
import subprocess
import sys
import time

from detector_red import config

NOMBRE = "DetectorRed"
ES_WINDOWS = os.name == "nt"
_SIN_VENTANA = getattr(subprocess, "CREATE_NO_WINDOW", 0) if ES_WINDOWS else 0

RUTAS_INNO = [
    r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 6\ISCC.exe",
]


def congelado():
    """True si el programa ya está corriendo como ejecutable."""
    return bool(getattr(sys, "frozen", False))


def raiz():
    return config._carpeta_programa()


def ruta_ejecutable():
    return os.path.join(raiz(), "dist", NOMBRE + (".exe" if ES_WINDOWS else ""))


def ruta_inno():
    for ruta in RUTAS_INNO:
        if os.path.isfile(ruta):
            return ruta
    return None


def ruta_instalador():
    candidatos = glob.glob(os.path.join(raiz(), "salida_instalador", f"{NOMBRE}-Instalador-*.exe"))
    return max(candidatos, key=os.path.getmtime) if candidatos else None


def sha256(ruta):
    resumen = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1024 * 1024), b""):
            resumen.update(bloque)
    return resumen.hexdigest()


def describir(ruta):
    if not ruta or not os.path.isfile(ruta):
        return None
    return {
        "nombre": os.path.basename(ruta),
        "tamano_mb": round(os.path.getsize(ruta) / 1024 / 1024, 1),
        "fecha": time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(ruta))),
        "sha256": sha256(ruta),
    }


def estado():
    if congelado():
        return {"congelado": True, "sistema": platform.system(),
                "actual": describir(sys.executable)}
    return {
        "congelado": False,
        "sistema": platform.system(),
        "pyinstaller": importlib.util.find_spec("PyInstaller") is not None,
        "inno": ruta_inno() is not None,
        "ejecutable": describir(ruta_ejecutable()),
        "instalador": describir(ruta_instalador()),
    }


def _ejecutar(comando, mostrar, cwd=None):
    """Ejecuta un comando y pasa cada línea de salida a 'mostrar'. Devuelve el código."""
    proceso = subprocess.Popen(comando, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, errors="replace", creationflags=_SIN_VENTANA)
    for linea in proceso.stdout:
        linea = linea.rstrip()
        if linea:
            mostrar(linea)
    return proceso.wait()


def instalar_pyinstaller(mostrar=print):
    mostrar("Instalando PyInstaller con pip (necesita internet)...")
    codigo = _ejecutar([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"], mostrar)
    if codigo != 0:
        return {"ok": False, "error": "pip no pudo instalar PyInstaller. Revise la conexión a internet."}
    return {"ok": True}


def construir(mostrar=print):
    """Arma dist/DetectorRed(.exe) y devuelve su descripción."""
    if congelado():
        return {"ok": False, "error": "El ejecutable solo se arma desde el código fuente."}
    if importlib.util.find_spec("PyInstaller") is None:
        return {"ok": False, "error": "Falta PyInstaller. Instálelo primero."}
    carpeta = raiz()
    trabajo = os.path.join(carpeta, "build")
    comando = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console",
        "--name", NOMBRE,
        "--collect-data", "detector_red",          # incluye la página web dentro del ejecutable
        "--distpath", os.path.join(carpeta, "dist"),
        "--workpath", trabajo, "--specpath", trabajo,
        os.path.join(carpeta, "lanzador.py"),
    ]
    mostrar("Armando el ejecutable (tarda uno o dos minutos)...")
    inicio = time.time()
    if _ejecutar(comando, mostrar, cwd=carpeta) != 0 or not os.path.isfile(ruta_ejecutable()):
        return {"ok": False, "error": "PyInstaller terminó con error. Revise los mensajes."}
    info = describir(ruta_ejecutable())
    with open(ruta_ejecutable() + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{info['sha256']}  {info['nombre']}\n")
    mostrar(f"Listo en {time.time() - inicio:.0f} s: {info['nombre']} ({info['tamano_mb']} MB)")
    return {"ok": True, "ejecutable": info}


def construir_instalador(mostrar=print):
    """Arma el instalador con asistente usando instalador/detector_red.iss."""
    iscc = ruta_inno()
    if not iscc:
        return {"ok": False, "error": "Inno Setup no está instalado."}
    if not os.path.isfile(ruta_ejecutable()):
        return {"ok": False, "error": "Primero arme el ejecutable."}
    script = os.path.join(raiz(), "instalador", "detector_red.iss")
    mostrar("Armando el instalador con Inno Setup...")
    if _ejecutar([iscc, script], mostrar, cwd=os.path.dirname(script)) != 0 or not ruta_instalador():
        return {"ok": False, "error": "Inno Setup terminó con error. Revise los mensajes."}
    return {"ok": True, "instalador": describir(ruta_instalador())}


def archivo_para_descargar(tipo):
    """Ruta del archivo que se entrega al pulsar 'Descargar'."""
    if tipo == "actual" and congelado():
        return sys.executable
    if tipo == "ejecutable":
        return ruta_ejecutable() if os.path.isfile(ruta_ejecutable()) else None
    if tipo == "instalador":
        return ruta_instalador()
    return None
