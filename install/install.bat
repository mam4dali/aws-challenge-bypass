@echo off
chcp 65001 >nul 2>&1
title AWS Challenge Bypass - Install

:: cd to project root (parent of this script's folder)
cd /d "%~dp0.."

echo ============================================
echo   Installing AWS Challenge Bypass
echo ============================================
echo.

:: Check Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo         Download from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/3] Creating virtual environment...
if exist venv (
    echo       venv already exists, skipping.
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo [2/3] Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo [3/3] Setting up .env file...
if exist .env (
    echo       .env already exists, skipping.
) else (
    copy .env.example .env >nul
    echo       .env created from .env.example
    echo       Edit .env to customize your settings.
)

echo.
echo ============================================
echo   Installation complete!
echo   Run the project with: run\run.bat
echo ============================================
pause
