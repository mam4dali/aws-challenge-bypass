@echo off
chcp 65001 >nul 2>&1
title AWS Challenge Bypass - Server

:: cd to project root (parent of this script's folder)
cd /d "%~dp0.."

:: Check venv exists
if not exist venv\Scripts\activate.bat (
    echo [ERROR] Virtual environment not found.
    echo         Run install\install.bat first.
    pause
    exit /b 1
)

:: Check .env exists
if not exist .env (
    echo [ERROR] .env file not found.
    echo         Run install\install.bat first.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat
echo Starting server...
python run.py
pause
