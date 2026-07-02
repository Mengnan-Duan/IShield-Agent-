@echo off
chcp 65001 >nul 2>&1
title IShield - AI Security Platform
cd /d "%~dp0"

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found
    pause
    exit /b 1
)

echo.
echo  ============================================================
echo   IShield v3.4.0 - AI Agent Security Gateway
echo   Starting security operations backend...
echo  ============================================================
echo.
echo   Console:   http://127.0.0.1:5000/
echo   Dashboard: http://127.0.0.1:5000/dashboard
echo.
echo   Please wait, service logs below...
echo.

:: Start backend
cd /d "%~dp0backend"
python run_backend.py

echo.
echo Backend stopped. Press any key to close...
pause >nul
