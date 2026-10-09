@echo off
setlocal enabledelayedexpansion
title PROVIGIL AETHER - NEXT-GEN SIEM & EDR UNIFIED LAUNCHER
color 0a

echo ==============================================================================
echo        PROVIGIL AETHER SIEM & EDR - COMPLETE 1-CLICK LAUNCHER
echo ==============================================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "BACKEND_DIR=%SCRIPT_DIR%wazuh-rust-angular\backend-rust"
set "FRONTEND_DIR=%SCRIPT_DIR%wazuh-rust-angular\ndr-ui"

call "%BACKEND_DIR%\service-env.bat"

echo [*] Checking Auth Service (Port 3001)...
netstat -ano | findstr ":3001 " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo [OK] Auth service is already running on port 3001!
) else (
    echo [*] Starting shared Auth Service ^(logins, users, tenants^) on :3001...
    if exist "%BACKEND_DIR%\target\release\auth-service.exe" (
        start "Provigil Auth Service (:3001)" /D "%BACKEND_DIR%" cmd /k "set CLICKHOUSE_DB=ndr&& set LISTEN_ADDR=0.0.0.0:3001&& target\release\auth-service.exe"
    ) else (
        start "Provigil Auth Service (:3001)" /D "%BACKEND_DIR%" cmd /k "set CLICKHOUSE_DB=ndr&& set LISTEN_ADDR=0.0.0.0:3001&& cargo run --release -p auth-service"
    )
)
echo.

echo [*] Checking Backend (Port 8088)...
netstat -ano | findstr ":8088 " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo [OK] Backend is already running on port 8088!
) else (
    echo [*] Starting Rust SIEM Engine & API Server on :8088...
    set "CLICKHOUSE_DB=ndr"
    if exist "%BACKEND_DIR%\target\release\siem-api.exe" (
        start "Provigil SIEM Rust Core (:8088)" /D "%BACKEND_DIR%" "%BACKEND_DIR%\target\release\siem-api.exe"
    ) else if exist "%BACKEND_DIR%\target\debug\siem-api.exe" (
        start "Provigil SIEM Rust Core (:8088)" /D "%BACKEND_DIR%" "%BACKEND_DIR%\target\debug\siem-api.exe"
    ) else (
        start "Provigil SIEM Rust Core (:8088)" cmd /k "cd /d "%BACKEND_DIR%" && cargo run --bin siem-api"
    )
)

echo.
echo [*] Checking Frontend (Port 4200)...
netstat -ano | findstr ":4200 " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo [OK] Frontend is already running on port 4200!
) else (
    echo [*] Starting Angular Web Console via ng serve on :4200...
    start "Provigil SIEM Web Console (:4200)" cmd /k "cd /d "%FRONTEND_DIR%" && npm start"
)


echo.
echo ==============================================================================
echo [OK] SUCCESS: Both Backend and Frontend Services are Active!
echo.
echo  - Auth Service:          http://localhost:3001  (default login: admin / ndr@admin123 - change it)
echo  - Rust REST API:         http://localhost:8088
echo  - Live WebSocket Stream:  ws://localhost:8088/ws/alerts
echo  - Next-Gen Web Console:   http://localhost:4200
echo ==============================================================================
echo.
echo [*] Opening default web browser to http://localhost:4200 in 3 seconds...
timeout /t 3 /nobreak >nul
start http://localhost:4200
pause
