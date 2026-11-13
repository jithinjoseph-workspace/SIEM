@echo off
title PROVIGIL AETHER SIEM - STOP SERVICES
color 0c

echo ==============================================================================
echo            STOPPING PROVIGIL SIEM AND EDR SERVICES
echo ==============================================================================
echo.

echo [*] Stopping backend processes on port 8088...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8088" ^| findstr "LISTENING"') do (
    echo Killing PID %%a on port 8088...
    taskkill /F /PID %%a >nul 2>&1
)

echo [*] Stopping frontend processes on port 4200...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":4200" ^| findstr "LISTENING"') do (
    echo Killing PID %%a on port 4200...
    taskkill /F /PID %%a >nul 2>&1
)

echo [*] Terminating any remaining backend and agent processes...
taskkill /F /IM provigil-gateway.exe >nul 2>&1
taskkill /F /IM siem-api.exe >nul 2>&1
taskkill /F /IM auth-service.exe >nul 2>&1
taskkill /F /IM provigil-agent.exe >nul 2>&1
for %%p in (provigil-db provigil-analysisd provigil-remoted provigil-modulesd) do taskkill /F /IM %%p.exe >nul 2>&1

echo.
echo [OK] All services on ports 3011, 8088, 8089, 8443 and 4200 have been stopped.
echo ==============================================================================
timeout /t 3
