@echo off
echo Starting CalculatenTrade Application...
echo.

REM Set environment variables
set SMARTAPI_DISABLE_NETWORK=1
set OAUTHLIB_INSECURE_TRANSPORT=1
set FLASK_ENV=development

REM Change to the application directory
cd /d "%~dp0"

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo Python found, starting application...
echo.

REM Run the application
python run_app.py

pause