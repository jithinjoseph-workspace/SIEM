@echo off
rem ============================================================================
rem Shared settings for auth-service (:3001) and siem-api (:8088).
rem Both must use the same JWT_SECRET and the same Valkey session store:
rem auth-service issues the tokens, siem-api validates them.
rem Call this from a launcher:  call "%BACKEND_DIR%\service-env.bat"
rem ============================================================================

set "SERVICE_ENV_DIR=%~dp0"

if not defined CLICKHOUSE_URL set "CLICKHOUSE_URL=http://localhost:8123"
if not defined CLICKHOUSE_USER set "CLICKHOUSE_USER=default"
if not defined CLICKHOUSE_PASSWORD set "CLICKHOUSE_PASSWORD="
if not defined VALKEY_URL set "VALKEY_URL=redis://127.0.0.1:6379"

rem auth-service provisions tenant databases from the NDR schema file
rem (<INSTALL_DIR>\config\clickhouse\init.sql).
if not defined INSTALL_DIR set "INSTALL_DIR=%SERVICE_ENV_DIR%..\..\ndr"

rem One random secret per installation, kept in data\jwt_secret.txt (git-ignored).
if not defined JWT_SECRET (
    if not exist "%SERVICE_ENV_DIR%data" mkdir "%SERVICE_ENV_DIR%data"
    if not exist "%SERVICE_ENV_DIR%data\jwt_secret.txt" (
        powershell -NoProfile -Command "$b = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [IO.File]::WriteAllText('%SERVICE_ENV_DIR%data\jwt_secret.txt', -join ($b | ForEach-Object { $_.ToString('x2') }))"
    )
    set /p JWT_SECRET=<"%SERVICE_ENV_DIR%data\jwt_secret.txt"
)
