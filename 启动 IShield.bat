@echo off
chcp 65001 >nul
setlocal
title IShield
cd /d "%~dp0"

set "PYTHON_CMD="
for %%P in ("%~dp0env\Scripts\python.exe" "%~dp0.venv\Scripts\python.exe" "python") do (
    if not defined PYTHON_CMD (
        "%%~P" --version >nul 2>&1
        if not errorlevel 1 set "PYTHON_CMD=%%~P"
    )
)

if not defined PYTHON_CMD (
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
