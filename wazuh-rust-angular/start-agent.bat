@echo off
title WAZUH RUST WINDOWS AGENT - CONTROL CONSOLE
color 0a

echo ==============================================================================
echo              WAZUH RUST WINDOWS ENDPOINT AGENT (Next-Gen XDR)
echo ==============================================================================
echo.
echo Select how you want to run the Windows Agent:
echo.
echo  [1] Launch Desktop Management GUI (win32ui Console)
echo  [2] Run Agent in Live Console Window (Interactive Testing)
echo  [3] Install & Start as 24/7 Automatic Background Windows Service
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
    echo [*] Running Agent in interactive console mode...
    cd /d %~dp0backend-rust
    set PATH=C:\Users\josep\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin;%PATH%
    target\release\siem-agent.exe --console
    pause
    exit /b
)

if "%choice%"=="3" (
    echo.
    echo [*] Installing as Automatic Windows Service (Requires Administrator)...
    cd /d %~dp0backend-rust
    target\release\siem-agent.exe install-service http://127.0.0.1:8088 001
    pause
    exit /b
)

if "%choice%"=="4" (
    echo.
    echo [*] Stopping background service...
    cd /d %~dp0backend-rust
    target\release\siem-agent.exe stop-service
    pause
    exit /b
)

if "%choice%"=="5" (
    echo.
    echo [*] Uninstalling background service...
    cd /d %~dp0backend-rust
    target\release\siem-agent.exe uninstall-service
    pause
    exit /b
)

if "%choice%"=="6" (
    echo.
    cd /d %~dp0backend-rust
    target\release\siem-agent.exe status-service
    pause
    exit /b
)

echo Invalid selection. Exiting.
pause
