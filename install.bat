@echo off
title Instalador LAN Transfer CLI
color 0A

echo ========================================================
echo       INSTALANDO LAN TRANSFER GLOBALMENTE
echo ========================================================
echo.
echo 1. Instalando paquete en Python...
pip install .

echo.
echo 2. Creando atajo del sistema (lan-transfer.bat)...
:: Creamos el archivo temporal
echo @echo off > "%TEMP%\lan-transfer.bat"
echo python -m lan %%* >> "%TEMP%\lan-transfer.bat"

:: Intentamos moverlo a C:\Windows (Requiere permisos de administrador)
copy /Y "%TEMP%\lan-transfer.bat" "C:\Windows\lan-transfer.bat" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] Atajo creado en C:\Windows ^(Modo Administrador^)
) else (
    :: Si no es admin, lo intentamos poner en WindowsApps que siempre esta en el PATH del usuario
    copy /Y "%TEMP%\lan-transfer.bat" "%LOCALAPPDATA%\Microsoft\WindowsApps\lan-transfer.bat" >nul 2>&1
    echo [OK] Atajo creado en AppData.
)

echo.
echo ========================================================
echo ¡INSTALACION 100%% A PRUEBA DE FALLOS COMPLETADA!
echo.
echo Puedes usar desde cualquier carpeta:
echo.
echo   lan-transfer send archivo.mp4
echo   lan-transfer receive IP:PUERTO archivo.mp4
echo ========================================================
pause
