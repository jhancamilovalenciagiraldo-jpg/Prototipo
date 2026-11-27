# Punto de entrada para ejecutar desde el código fuente (python lanzador.py)
# y para que PyInstaller genere el .exe.
import sys

from detector_red.main import main

if __name__ == "__main__":
    sys.exit(main())
