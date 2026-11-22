@echo off
set PATH=E:\mingw64\bin;%PATH%
cd /d "%~dp0SecureSessionManagement"
echo =================================================================
echo   STARTING SECURE SESSION MANAGEMENT INTERACTIVE CONSOLE
echo =================================================================
build\SecureSessionApp.exe
echo.
pause
