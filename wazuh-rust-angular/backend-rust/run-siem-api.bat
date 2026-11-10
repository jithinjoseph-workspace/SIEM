@echo off
set "PATH=C:\Users\josep\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin;%PATH%"
call "%~dp0service-env.bat" || exit /b 1
target\debug\siem-api.exe
