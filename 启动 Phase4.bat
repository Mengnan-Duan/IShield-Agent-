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
echo   IShield Phase 2.1 - AI Agent Security Platform
echo   Starting backend service...
echo  ============================================================
echo.
echo   Console:   http://127.0.0.1:5000/frontend.html
echo   Dashboard: http://127.0.0.1:5000/dashboard
echo.
echo   Please wait, backend logs below...
echo.

:: Start backend
cd /d "%~dp0backend"
python run_backend.py

echo.
echo Backend stopped. Press any key to close...
pause >nul
