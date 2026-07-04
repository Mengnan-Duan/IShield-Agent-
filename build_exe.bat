@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHON_EXE="
if exist "env\Scripts\python.exe" set "PYTHON_EXE=env\Scripts\python.exe"
if not defined PYTHON_EXE if exist ".venv\Scripts\python.exe" set "PYTHON_EXE=.venv\Scripts\python.exe"
if not defined PYTHON_EXE set "PYTHON_EXE=python"
set "RELEASE_DIR=release"
set "RELEASE_APP_DIR=%RELEASE_DIR%\IShield"
set "RELEASE_ZIP=%RELEASE_DIR%\IShield-Final-Package.zip"

echo ============================================================
echo  IShield portable package builder
echo ============================================================
echo.

"%PYTHON_EXE%" --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python was not found.
  echo Please install Python or create env first.
  pause
  exit /b 1
)

echo [1/4] Checking dependencies...
"%PYTHON_EXE%" -m pip install -r requirements.txt
if errorlevel 1 (
  echo [WARN] Dependency update failed, usually because the network is unavailable.
  echo [WARN] Continuing if the local build environment already has core packages.
)
"%PYTHON_EXE%" -c "import flask, flask_cors, requests, PyInstaller"
if errorlevel 1 (
  echo [ERROR] Missing core dependency. Please install requirements.txt first.
  goto :error
)

echo [2/4] Building executable directory...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
"%PYTHON_EXE%" -m PyInstaller --noconfirm IShield.spec
if errorlevel 1 goto :error

echo [3/4] Checking packaged resources...
if not exist "dist\IShield\IShield.exe" goto :missing
if not exist "dist\IShield\_internal\README.md" goto :missing
if not exist "dist\IShield\_internal\frontend.html" goto :missing
if not exist "dist\IShield\_internal\dashboard.html" goto :missing
if not exist "dist\IShield\_internal\backend\config.py" goto :missing
if not exist "dist\IShield\_internal\backend\playbooks\default_playbooks.json" goto :missing
if not exist "dist\IShield\_internal\ffi.dll" goto :missing

echo [4/4] Creating zip package...
if exist "dist\IShield\runtime" rmdir /s /q "dist\IShield\runtime"
if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"
if exist "%RELEASE_APP_DIR%" rmdir /s /q "%RELEASE_APP_DIR%"
del /f /q "%RELEASE_DIR%\*.zip" >nul 2>&1
xcopy "dist\IShield" "%RELEASE_APP_DIR%\" /E /I /Y >nul
copy /Y "README.md" "%RELEASE_APP_DIR%\README.md" >nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path 'release\IShield' -DestinationPath 'release\IShield-Final-Package.zip' -Force"
if errorlevel 1 goto :error
if exist "%RELEASE_APP_DIR%" rmdir /s /q "%RELEASE_APP_DIR%"
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

echo.
echo Build completed.
echo Final package: %RELEASE_ZIP%
echo.
pause
exit /b 0

:missing
echo.
echo [ERROR] Build output is incomplete. Please check the lines above.
pause
exit /b 1

:error
echo.
echo [ERROR] Build failed. Please check the lines above.
pause
exit /b 1
