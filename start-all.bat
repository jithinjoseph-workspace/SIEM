@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
set "BACKEND_DIR=%SCRIPT_DIR%wazuh-rust-angular\backend-rust"
set "FRONTEND_DIR=%SCRIPT_DIR%wazuh-rust-angular\ndr-ui"
call "%BACKEND_DIR%\service-env.bat"
set "CLICKHOUSE_URL=http://127.0.0.1:8123"
set "CLICKHOUSE_USER=default"
set "CLICKHOUSE_PASSWORD="
set "CLICKHOUSE_DB=ndr"
set "VALKEY_URL=redis://127.0.0.1:6379"

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

call :port_open 3001
if errorlevel 1 (
  echo [*] Starting Auth Service on :3001...
  if exist "%BACKEND_DIR%\target\release\auth-service.exe" (
    start "Provigil Auth Service (:3001)" /D "%BACKEND_DIR%" cmd /k "set CLICKHOUSE_URL=%CLICKHOUSE_URL%&& set CLICKHOUSE_USER=%CLICKHOUSE_USER%&& set CLICKHOUSE_PASSWORD=%CLICKHOUSE_PASSWORD%&& set CLICKHOUSE_DB=%CLICKHOUSE_DB%&& set VALKEY_URL=%VALKEY_URL%&& set JWT_SECRET=%JWT_SECRET%&& set LISTEN_ADDR=0.0.0.0:3001&& target\release\auth-service.exe"
  ) else (
    start "Provigil Auth Service (:3001)" /D "%BACKEND_DIR%" cmd /k "cargo run --release -p auth-service"
  )
)
call :wait_port 3001 "Auth service" 60
if errorlevel 1 goto :startup_error

call :port_open 8088
if errorlevel 1 (
  echo [*] Starting Rust SIEM API on :8088...
  if exist "%BACKEND_DIR%\target\release\siem-api.exe" (
    start "Provigil SIEM API (:8088)" /D "%BACKEND_DIR%" cmd /k "set CLICKHOUSE_URL=%CLICKHOUSE_URL%&& set CLICKHOUSE_USER=%CLICKHOUSE_USER%&& set CLICKHOUSE_PASSWORD=%CLICKHOUSE_PASSWORD%&& set CLICKHOUSE_DB=%CLICKHOUSE_DB%&& set VALKEY_URL=%VALKEY_URL%&& set JWT_SECRET=%JWT_SECRET%&& target\release\siem-api.exe"
  ) else (
    start "Provigil SIEM API (:8088)" /D "%BACKEND_DIR%" cmd /k "cargo run --bin siem-api"
  )
)
call :wait_port 8088 "SIEM API" 60
if errorlevel 1 goto :startup_error

call :port_open 4200
if errorlevel 1 (
  echo [*] Starting Angular UI on :4200...
  start "Provigil Angular UI (:4200)" /D "%FRONTEND_DIR%" cmd /k "npm start"
)
call :wait_port 4200 "Angular UI" 60
if errorlevel 1 goto :startup_error

echo.
echo [OK] SIEM is ready: http://localhost:4200
start http://localhost:4200
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
  timeout /t 1 /nobreak >nul
)
echo [FAIL] %WAIT_NAME% did not start on :%WAIT_PORT%. Check its terminal window for the error.
exit /b 1

:dependency_error
echo [FAIL] ClickHouse or Valkey could not be started. Ensure Docker Desktop is running.
pause
exit /b 1

:startup_error
echo [FAIL] Startup stopped because a required service did not become healthy.
pause
exit /b 1
