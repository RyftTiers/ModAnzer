@echo off
title ModAnzer
rem ModAnzer launcher - double-click to run the ModAnzer screenshare scanner.
rem Source: https://github.com/RyftTiers/ModAnzer
rem If ModAnzer.ps1 is in the same folder it runs that copy, otherwise it
rem downloads the latest version from https://ryfttiers-modanzer.onrender.com

if exist "%~dp0ModAnzer.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ModAnzer.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((irm https://ryfttiers-modanzer.onrender.com/ModAnzer.txt) -join [char]10)"
)

if %errorlevel% equ 1 (
    echo.
    echo ModAnzer could not start. Check your internet connection and try again.
    pause
)
