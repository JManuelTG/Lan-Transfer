@echo off
title Desinstalador LAN Transfer CLI
color 0C

echo ========================================================
echo       DESINSTALANDO LAN TRANSFER GLOBALMENTE
echo ========================================================
echo.
echo Eliminando paquete y comando del sistema...
pip uninstall -y lan-transfer

echo.
echo ========================================================
echo El comando 'lan-transfer' ha sido removido exitosamente.
echo ========================================================
pause
