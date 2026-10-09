@echo off
title WAZUH RUST & ANGULAR SIEM - 1-CLICK LAUNCHER
color 0b

echo ==============================================================================
echo           WAZUH RUST SIEM CORE & ANGULAR 21 SOC LAUNCHER
echo ==============================================================================
echo.
call "%~dp0backend-rust\service-env.bat"

echo [*] Starting Step 0: Shared Auth Service (Port :3001)...
start "Provigil Auth Service (:3001)" cmd /k "cd /d %~dp0backend-rust && set CLICKHOUSE_DB=ndr&& set LISTEN_ADDR=0.0.0.0:3001&& target\release\auth-service.exe"

echo [*] Starting Step 1: Rust SIEM Engine & API Server (Port :8088)...
start "Wazuh Rust Core Server (:8088)" cmd /k "cd /d %~dp0backend-rust && set CLICKHOUSE_DB=ndr&& set PATH=C:\Users\josep\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin;%PATH% && target\release\siem-api.exe"

echo [*] Waiting 2 seconds for Rust backend to initialize...
timeout /t 2 /nobreak >nul

echo [*] Starting Step 2: Angular 21 Operations Center (:4200)...
start "Wazuh Angular SOC Dashboard (:4200)" cmd /k "cd /d %~dp0ndr-ui && npm start"

echo.
echo ==============================================================================
echo [✓] Both Backend & Frontend have been launched in dedicated terminal windows!
echo.
echo  - Rust Backend API:    http://localhost:8088
echo  - Live WebSocket Feed: ws://localhost:8088/ws/alerts
echo  - Angular SOC Portal:  http://localhost:4200
echo.
echo Opening your default browser to http://localhost:4200...
echo ==============================================================================
timeout /t 5 /nobreak >nul
start http://localhost:4200
pause
