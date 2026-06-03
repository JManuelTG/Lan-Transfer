@echo off
title Instalador LAN Transfer CLI
color 0A

echo ========================================================
echo       INSTALANDO LAN TRANSFER GLOBALMENTE
echo ========================================================
echo.
echo Compilando y agregando comando 'lan-transfer' al PATH del sistema...
pip install .

echo.
echo ========================================================
echo Instalacion completada exitosamente.
echo.
echo Ahora puedes abrir cualquier ventana de CMD o PowerShell
echo en cualquier carpeta de tu computadora y usar:
echo.
echo   lan-transfer send archivo.mp4
echo   lan-transfer receive IP:PUERTO archivo.mp4
echo.
echo (Para ver el menu de ayuda, escribe: lan-transfer --help)
echo ========================================================
pause
