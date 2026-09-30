@echo off
rem Lanzador para Windows. Doble clic sobre este archivo.
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 lanzar_demo.py %*
    goto fin
)
where python >nul 2>nul
if %errorlevel%==0 (
    python lanzar_demo.py %*
    goto fin
)
echo No se encontro Python 3.
echo Instalalo desde https://www.python.org/downloads/
echo y marca la casilla "Add python.exe to PATH".

:fin
pause
