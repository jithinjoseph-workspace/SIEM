@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
set "BACKEND_DIR=%SCRIPT_DIR%wazuh-rust-angular\backend-rust"
set "FRONTEND_DIR=%SCRIPT_DIR%wazuh-rust-angular\ndr-ui"
rem Credentials and JWT_SECRET come from wazuh-rust-angular\.env (see .env.example).
call "%BACKEND_DIR%\service-env.bat"
if errorlevel 1 (
  pause
  exit /b 1
)
rem Each service window also writes its output to logs\<service>.log (previous run: .log.1).
set "LOG_DIR=%BACKEND_DIR%\logs"
set RUN_LOGGED=powershell -NoProfile -NoExit -ExecutionPolicy Bypass -File "%BACKEND_DIR%\run-logged.ps1"

set "COMPOSE_FILE=%SCRIPT_DIR%wazuh-rust-angular\docker-compose.yml"

echo.
echo ==============================================================================
echo    PROVIGIL AETHER - STARTING LOCAL SIEM SERVICES
echo ==============================================================================

call :port_open 8123
set "CH_READY=%errorlevel%"
call :port_open 6379
set "VK_READY=%errorlevel%"

if "%CH_READY%"=="0" if "%VK_READY%"=="0" goto :dependencies_ready

echo [*] ClickHouse (:8123) or Valkey (:6379) not detected.
echo [*] Checking Docker to automatically pull images and start containers...

where docker >nul 2>&1
if errorlevel 1 (
  echo [FAIL] Docker is not installed or not in PATH.
  echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop/
  goto :dependency_error
)

docker info >nul 2>&1
if errorlevel 1 (
  echo [FAIL] Docker Desktop is installed but not running.
  echo Please open/start Docker Desktop and try again.
  goto :dependency_error
)

echo [*] Launching ClickHouse and Valkey via Docker Compose (auto-pulling images if missing)...
docker compose -f "%COMPOSE_FILE%" up -d clickhouse valkey
if errorlevel 1 (
  echo [FAIL] Docker compose failed to pull or start containers.
  goto :dependency_error
)

:dependencies_ready
call :wait_port 8123 "ClickHouse" 35
if errorlevel 1 goto :dependency_error
call :wait_port 6379 "Valkey" 35
if errorlevel 1 goto :dependency_error

if not exist "%FRONTEND_DIR%\node_modules" (
  echo [*] Node dependencies not found. Running 'npm install' in %FRONTEND_DIR%...
  pushd "%FRONTEND_DIR%"
  call npm install
  popd
)

rem ?? Build the backend from the current sources (a running exe cannot be replaced) ??
echo [*] Stopping running backend processes before the build...
taskkill /F /IM siem-api.exe >nul 2>&1
taskkill /F /IM auth-service.exe >nul 2>&1
for %%p in (wazuh-db wazuh-analysisd wazuh-remoted wazuh-modulesd wazuh-monitord wazuh-maild wazuh-integratord wazuh-csyslogd) do taskkill /F /IM %%p.exe >nul 2>&1
echo [*] Building backend (auth-service, siem-api, wazuh manager daemons)...
pushd "%BACKEND_DIR%"
cargo build --release -p auth-service -p siem-api -p siem-wdb -p siem-analysisd -p siem-remoted -p siem-modulesd -p siem-monitord -p siem-maild -p siem-integratord -p siem-csyslogd
if errorlevel 1 (
  popd
  echo [FAIL] Backend build failed. Fix the errors above, the old binaries were not started.
  pause
  exit /b 1
)
popd
echo [OK] Backend built.

rem The Windows agent (wazuh-agent.exe) is cross-built in WSL; skipped when WSL is not available.
wsl -d Ubuntu-20.04 -- true >nul 2>&1
if errorlevel 1 (
  echo [WARN] WSL Ubuntu-20.04 not found: the Windows agent download keeps its previous build.
) else (
  echo [*] Building the Windows agent in WSL...
  pushd "%BACKEND_DIR%"
  wsl -d Ubuntu-20.04 -- bash tools/build-winagent.sh
  if errorlevel 1 echo [WARN] Windows agent build failed: the download keeps its previous build.
  popd
)

call :port_open 3001
if errorlevel 1 (
  echo [*] Starting Auth Service on :3001...
  if exist "%BACKEND_DIR%\target\release\auth-service.exe" (
    start "Provigil Auth Service (:3001)" /D "%BACKEND_DIR%" %RUN_LOGGED% -Log "%LOG_DIR%\auth-service.log" -Cmd "target\release\auth-service.exe"
  ) else (
    start "Provigil Auth Service (:3001)" /D "%BACKEND_DIR%" %RUN_LOGGED% -Log "%LOG_DIR%\auth-service.log" -Cmd "cargo run --release -p auth-service"
  )
)
call :wait_port 3001 "Auth service" 60
if errorlevel 1 goto :startup_error

call :port_open 8088
if errorlevel 1 (
  echo [*] Starting Rust SIEM API on :8088...
  if exist "%BACKEND_DIR%\target\release\siem-api.exe" (
    start "Provigil SIEM API (:8088)" /D "%BACKEND_DIR%" %RUN_LOGGED% -Log "%LOG_DIR%\siem-api.log" -Cmd "target\release\siem-api.exe"
  ) else (
    start "Provigil SIEM API (:8088)" /D "%BACKEND_DIR%" %RUN_LOGGED% -Log "%LOG_DIR%\siem-api.log" -Cmd "cargo run --bin siem-api"
  )
)
call :wait_port 8088 "SIEM API" 60
if errorlevel 1 goto :startup_error

call :port_open 4200
if errorlevel 1 (
  echo [*] Starting Angular UI on :4200...
  start "Provigil Angular UI (:4200)" /D "%FRONTEND_DIR%" %RUN_LOGGED% -Log "%LOG_DIR%\angular-ui.log" -Cmd "npm start"
)
call :wait_port 4200 "Angular UI" 60
if errorlevel 1 goto :startup_error

if not defined SIEM_LAN_IP (
  for /f "usebackq tokens=*" %%a in (`powershell -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet|WSL' -and $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1).IPAddress"`) do (
    if not "%%a"=="" set "SIEM_LAN_IP=%%a"
  )
)
if not defined SIEM_LAN_IP set "SIEM_LAN_IP=localhost"

echo.
echo ==============================================================================
echo [OK] SIEM is ready!
echo      LAN URL:   http://%SIEM_LAN_IP%:4200
echo      Local URL: http://localhost:4200
echo      API URL:   http://%SIEM_LAN_IP%:8088
echo      Logs:      %LOG_DIR%
echo ==============================================================================
start http://%SIEM_LAN_IP%:4200
exit /b 0

:port_open
netstat -ano | findstr /r /c:":%~1 .*LISTENING" >nul
exit /b %errorlevel%

:wait_port
set "WAIT_PORT=%~1"
set "WAIT_NAME=%~2"
set /a WAIT_SECONDS=%~3
for /L %%i in (1,1,%WAIT_SECONDS%) do (
  call :port_open %WAIT_PORT%
  if not errorlevel 1 (
    echo [OK] %WAIT_NAME% is listening on :%WAIT_PORT%
    exit /b 0
  )
  ping -n 2 127.0.0.1 >nul
)
echo [FAIL] %WAIT_NAME% did not start on :%WAIT_PORT%. Check its window or %LOG_DIR%.
exit /b 1

:dependency_error
echo [FAIL] ClickHouse or Valkey could not be started. Ensure Docker Desktop is running.
pause
exit /b 1

:startup_error
echo [FAIL] Startup stopped because a required service did not become healthy.
pause
exit /b 1
