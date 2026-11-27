"""Genera un archivo .sha256 por cada ejecutable de la carpeta dist/.

Quien descargue el programa puede comprobar que el archivo no fue alterado:
  Windows:  certutil -hashfile DetectorRed-Windows.exe SHA256
  Linux:    sha256sum -c DetectorRed-Linux.sha256
y comparar con el valor publicado junto a la versión.
"""
import hashlib
import pathlib

for archivo in sorted(pathlib.Path("dist").iterdir()):
    if archivo.suffix == ".sha256" or not archivo.is_file():
        continue
    resumen = hashlib.sha256(archivo.read_bytes()).hexdigest()
    archivo.with_name(archivo.stem + ".sha256").write_text(f"{resumen}  {archivo.name}\n", encoding="utf-8")
    print(f"{resumen}  {archivo.name}")
