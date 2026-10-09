@echo off
title PROVIGIL AETHER SIEM - STOP SERVICES
color 0c

echo ==============================================================================
echo            STOPPING PROVIGIL SIEM & EDR SERVICES
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

echo [*] Terminating any remaining siem-api processes...
taskkill /F /IM siem-api.exe >nul 2>&1
taskkill /F /IM auth-service.exe >nul 2>&1

echo.
echo [OK] All services on ports 3001, 8088 and 4200 have been stopped.
echo ==============================================================================
timeout /t 3
