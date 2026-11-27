@echo off
REM ============================================================
REM  Genera dist\DetectorRed.exe (no necesita Python instalado
REM  en el equipo donde se vaya a usar).
REM  Ejecutar desde la carpeta raiz del proyecto:
REM      instalador\construir_windows.bat
REM ============================================================

python -m pip install --upgrade pyinstaller || goto error

REM --collect-data incluye la pagina web (detector_red\web\index.html) dentro del .exe
python -m PyInstaller --onefile --console --clean ^
    --name DetectorRed ^
    --collect-data detector_red ^
    lanzador.py || goto error

echo.
echo Listo: dist\DetectorRed.exe
echo Para el instalador con asistente abra instalador\detector_red.iss con Inno Setup.
goto fin

:error
echo Hubo un error. Revise que Python este instalado y en el PATH.
exit /b 1

:fin
