@echo off
title Instalador LAN Transfer CLI
color 0A

echo ========================================================
echo       INSTALANDO LAN TRANSFER GLOBALMENTE
echo ========================================================
echo.
echo Compilando y agregando comando 'lan-transfer' al sistema...
pip install .

echo.
echo Verificando variables de entorno (PATH)...
powershell -Command "$scripts = (python -c \"import sys, os; print(os.path.join(sys.prefix, 'Scripts'))\" | Out-String).Trim(); $path = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($path -notlike \"*$scripts*\") { [Environment]::SetEnvironmentVariable('Path', $path + ';' + $scripts, 'User'); Write-Host 'Se agrego Python Scripts al PATH exitosamente. (Reinicia la consola para aplicar cambios)' -ForegroundColor Yellow } else { Write-Host 'El PATH ya esta configurado correctamente.' -ForegroundColor Green }"

echo.
echo ========================================================
echo Instalacion completada exitosamente.
echo.
echo MUY IMPORTANTE: Si es la primera vez que instalas, 
echo CIERRA esta ventana de consola y ABRE UNA NUEVA para que
echo el comando sea reconocido.
echo.
echo Luego podras usar desde cualquier carpeta:
echo.
echo   lan-transfer send archivo.mp4
echo   lan-transfer receive IP:PUERTO archivo.mp4
echo ========================================================
pause
