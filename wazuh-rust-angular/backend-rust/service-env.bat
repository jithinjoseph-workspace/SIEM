@echo off
rem ============================================================================
rem Shared settings for auth-service (:3011, LISTEN_ADDR) and siem-api (:8088), read from
rem wazuh-rust-angular\.env (git-ignored; template: .env.example).
rem Both must use the same JWT_SECRET and the same Valkey session store:
rem auth-service issues the tokens, siem-api validates them.
rem A variable already set in the shell wins over .env.
rem Call this from a launcher:  call "%BACKEND_DIR%\service-env.bat"
rem ============================================================================

set "SERVICE_ENV_DIR=%~dp0"
set "ENV_FILE=%SERVICE_ENV_DIR%..\.env"

if not exist "%ENV_FILE%" (
    echo [*] %ENV_FILE% not found, creating it from .env.example
    copy "%SERVICE_ENV_DIR%..\.env.example" "%ENV_FILE%" >nul || (echo [FAIL] cannot create %ENV_FILE% & exit /b 1)
)
for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%ENV_FILE%") do if not defined %%a set "%%a=%%b"

rem No JWT_SECRET yet: generate one (or take the old data\jwt_secret.txt so sessions survive) and store it in .env.
if not defined JWT_SECRET (
    powershell -NoProfile -Command "$f='%ENV_FILE%'; $old='%SERVICE_ENV_DIR%data\jwt_secret.txt'; if (Test-Path $old) { $s=(Get-Content $old -Raw).Trim() } else { $b=New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); $s=-join ($b | ForEach-Object { $_.ToString('x2') }) }; $l=@(Get-Content $f | Where-Object { $_ -notmatch '^JWT_SECRET=' }) + ('JWT_SECRET=' + $s); [IO.File]::WriteAllLines($f, [string[]]$l)"
    for /f "usebackq tokens=1,* delims==" %%a in (`findstr /b "JWT_SECRET=" "%ENV_FILE%"`) do set "JWT_SECRET=%%b"
)

rem No AGENT_KEYS_SECRET yet: generate one (it encrypts the agent keys siem-api keeps in ClickHouse).
if not defined AGENT_KEYS_SECRET (
    powershell -NoProfile -Command "$f='%ENV_FILE%'; $b=New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); $s=-join ($b | ForEach-Object { $_.ToString('x2') }); $l=@(Get-Content $f | Where-Object { $_ -notmatch '^AGENT_KEYS_SECRET=' }) + ('AGENT_KEYS_SECRET=' + $s); [IO.File]::WriteAllLines($f, [string[]]$l)"
    for /f "usebackq tokens=1,* delims==" %%a in (`findstr /b "AGENT_KEYS_SECRET=" "%ENV_FILE%"`) do set "AGENT_KEYS_SECRET=%%b"
)

for %%v in (CLICKHOUSE_URL CLICKHOUSE_USER CLICKHOUSE_DB VALKEY_URL JWT_SECRET AGENT_KEYS_SECRET) do if not defined %%v (
    echo [FAIL] %%v is not set in %ENV_FILE%
    exit /b 1
)

rem Auto-detect host LAN IP for siem-api and agent installers if not explicitly configured
if not defined SIEM_LAN_IP (
    for /f "tokens=*" %%i in ('powershell -NoProfile -Command "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress -First 1)"') do set "SIEM_LAN_IP=%%i"
)
if not defined SIEM_LAN_IP set "SIEM_LAN_IP=127.0.0.1"

rem auth-service provisions tenant databases from the NDR schema file
rem (<INSTALL_DIR>\config\clickhouse\init.sql).
if not defined INSTALL_DIR set "INSTALL_DIR=%SERVICE_ENV_DIR%..\..\ndr"
exit /b 0
