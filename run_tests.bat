@echo off
set PATH=E:\mingw64\bin;%PATH%
cd /d "%~dp0SecureSessionManagement"
echo =================================================================
echo   RUNNING 30 AUTOMATED SECURITY TESTS
echo =================================================================
build\SecurityTests.exe
echo.
pause
