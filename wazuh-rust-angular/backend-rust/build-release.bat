@echo off
set "PATH=C:\Users\josep\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin;%PATH%"
cargo build --release -p siem-api -p auth-service -p provigil-agent -p siem-active-response -p siem-wdb -p siem-analysisd -p siem-remoted -p siem-modulesd
