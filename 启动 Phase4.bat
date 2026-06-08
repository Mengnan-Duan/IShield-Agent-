@echo off
chcp 65001 >nul 2>&1
title IShield — 智能体安全平台

cd /d "%~dp0"

:: 检查 Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Python，请安装 Python 3.8+
    pause
    exit /b 1
)

echo.
echo  ============================================================
echo   IShield Phase 4 — 智能体安全平台
echo   正在启动后端服务...
echo  ============================================================
echo.
echo   控制台：  http://127.0.0.1:5000/frontend.html
echo   分析看板：http://127.0.0.1:5000/dashboard
echo.
echo   请稍候，后端日志将显示在下方...
echo.

:: 启动后端（从 backend/ 目录运行）
cd /d "%~dp0backend"
python run_backend.py
pause
