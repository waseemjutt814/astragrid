@echo off
setlocal
cd /d "%~dp0"
echo Starting AstraGrid from %CD%
echo.
"%~dp0astragrid.exe"
echo.
echo To run commands manually, open PowerShell in this folder and use:
echo   .\astragrid.exe --help
echo.
pause
