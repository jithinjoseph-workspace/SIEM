@echo off
title PROVIGIL WINDOWS AGENT - CONTROL CONSOLE
color 0a

echo ==============================================================================
echo             PROVIGIL WINDOWS ENDPOINT AGENT (Next-Gen EDR and XDR)
echo ==============================================================================
echo.
echo Select how you want to run the Windows Agent:
echo.
echo  [1] Launch Desktop Management GUI (win32ui Console)
echo  [2] Run Agent in Live Console Window (Interactive Testing)
echo  [3] Install and Start as 24/7 Automatic Background Windows Service
echo  [4] Stop Background Windows Service
echo  [5] Uninstall Background Windows Service
echo  [6] Check Current Service Status
echo.
set /p choice="Enter option [1-6]: "

if "%choice%"=="1" (
    echo.
    echo [*] Launching Desktop Management Console...
    cd /d %~dp0backend-rust
    start powershell -ExecutionPolicy Bypass -File wazuh-agent-ui.ps1
    exit /b
)

if "%choice%"=="2" (
    echo.
    echo [*] Running ProVigil Agent in interactive console mode...
    cd /d %~dp0backend-rust
    if exist "target\release\provigil-agent.exe" (
        target\release\provigil-agent.exe --run
    ) else (
        cargo run --release -p provigil-agent -- --run
    )
    pause
    exit /b
)

if "%choice%"=="3" (
    echo.
    echo [*] Installing as Automatic Windows Service (Requires Administrator)...
    cd /d %~dp0backend-rust
    if exist "target\release\provigil-agent.exe" (
        target\release\provigil-agent.exe --install
    ) else (
        cargo run --release -p provigil-agent -- --install
    )
    sc start ProVigilSvc
    pause
    exit /b
)

if "%choice%"=="4" (
    echo.
    echo [*] Stopping ProVigil background service...
    sc stop ProVigilSvc
    pause
    exit /b
)

if "%choice%"=="5" (
    echo.
    echo [*] Uninstalling ProVigil background service...
    cd /d %~dp0backend-rust
    if exist "target\release\provigil-agent.exe" (
        target\release\provigil-agent.exe --uninstall
    ) else (
        cargo run --release -p provigil-agent -- --uninstall
    )
    pause
    exit /b
)

if "%choice%"=="6" (
    echo.
    cd /d %~dp0backend-rust
    if exist "target\release\provigil-agent.exe" (
        target\release\provigil-agent.exe --status
    ) else (
        cargo run --release -p provigil-agent -- --status
    )
    pause
    exit /b
)

echo Invalid selection. Exiting.
pause
