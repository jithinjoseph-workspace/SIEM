@echo off
set "PATH=C:\Users\josep\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin;%PATH%"
cargo build --release -j 2 -p siem-api -p provigil-gateway -p auth-service -p provigil-agent -p siem-active-response -p provigil-agentdb -p provigil-analysisd -p provigil-modulesd
