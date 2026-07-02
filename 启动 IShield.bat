@echo off
setlocal
title IShield - AI Security Platform
cd /d "%~dp0"

set "PYTHON_CMD=python"
python --version >nul 2>&1
if errorlevel 1 if exist "%~dp0env\Scripts\python.exe" set "PYTHON_CMD=%~dp0env\Scripts\python.exe"

"%PYTHON_CMD%" --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [ERROR] Python not found. Please install Python or activate the project runtime first.
    echo.
    pause
    exit /b 1
)

if not exist "%~dp0backend\logs" mkdir "%~dp0backend\logs" >nul 2>&1
set "ISHIELD_LOG=%~dp0backend\logs\ishield-runtime.log"

cls
echo.
echo  ============================================================
echo   IShield v4.5.0 - AI Agent Cluster Guard
echo  ============================================================
echo.
echo   Console:   http://127.0.0.1:5000/
echo   Dashboard: http://127.0.0.1:5000/dashboard
echo.
echo   Startup:   cleanup old backend, then start a fresh instance
echo   Status:    starting backend and opening Console...
echo   Log:       backend\logs\ishield-runtime.log
echo.
echo  ============================================================
echo.

cd /d "%~dp0backend"
"%PYTHON_CMD%" run_backend.py > "%ISHIELD_LOG%" 2>&1

echo.
echo  Backend stopped. Runtime log:
echo  %ISHIELD_LOG%
echo.
pause
