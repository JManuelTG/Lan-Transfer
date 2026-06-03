@echo off
title Compilador LAN Transfer (PyInstaller)
color 0E

echo ========================================================
echo       COMPILANDO LAN TRANSFER A EJECUTABLE (.EXE)
echo ========================================================
echo.
echo Ejecutando PyInstaller...
venv\Scripts\pyinstaller --onefile --name lan-transfer lan_transfer/cli.py

echo.
echo ========================================================
echo ¡Compilacion Finalizada!
echo.
echo Tu archivo listo para usar esta en la carpeta:
echo   dist\lan-transfer.exe
echo.
echo Puedes copiar ese archivo a cualquier PC y funcionara
echo sin necesidad de instalar Python.
echo ========================================================
pause
