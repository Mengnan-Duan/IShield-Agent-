@echo off
chcp 65001 >nul
setlocal
title IShield
cd /d "%~dp0"

set "PYTHON_CMD=python"
python --version >nul 2>&1
if errorlevel 1 if exist "%~dp0env\Scripts\python.exe" set "PYTHON_CMD=%~dp0env\Scripts\python.exe"

"%PYTHON_CMD%" --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo Python not found.
    echo Please install Python or activate the project runtime.
    echo.
    pause
    exit /b 1
)

if not exist "%~dp0backend\logs" mkdir "%~dp0backend\logs" >nul 2>&1

cls
cd /d "%~dp0backend"
"%PYTHON_CMD%" run_backend.py

echo.
echo Backend stopped.
echo.
pause
