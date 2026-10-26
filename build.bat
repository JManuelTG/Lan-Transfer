@echo off
title LAN Transfer Compiler (PyInstaller)
color 0E

echo ========================================================
echo       COMPILANDO LAN TRANSFER A EJECUTABLE (.EXE)
echo ========================================================
echo.
echo Ejecutando PyInstaller...
venv\Scripts\pyinstaller --clean -y lan-transfer.spec

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [X] Error durante la compilacion.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo [OK] Compilacion Finalizada!
echo.
echo Tu archivo portable listo para usar esta en:
echo   dist\lan-transfer.exe
echo.
echo Puedes copiar ese archivo a cualquier PC con Windows y
echo funcionara sin necesidad de instalar Python.
echo ========================================================
pause
