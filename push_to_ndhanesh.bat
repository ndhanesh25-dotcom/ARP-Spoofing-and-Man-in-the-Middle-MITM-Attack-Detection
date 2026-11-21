@echo off
title Uploading Project to ndhanesh25-dotcom GitHub
color 0A
cls
echo ==============================================================================
echo       NETGUARD - UPLOAD TO ndhanesh25-dotcom GITHUB REPOSITORY
echo ==============================================================================
echo.
echo [*] Target Repository:
echo     https://github.com/ndhanesh25-dotcom/ARP-Spoofing-and-Man-in-the-Middle-MITM-Attack-Detection.git
echo.
echo [*] Git Credential Manager will open a browser tab.
echo [*] Click "Sign in with your browser" / "Authorize" to complete the upload!
echo.
cd /d "%~dp0"
git push -u second main
echo.
if %errorlevel% equ 0 (
    echo ==============================================================================
    echo [SUCCESS] ALL PROJECT WORK HAS BEEN UPLOADED TO ndhanesh25-dotcom!
    echo ==============================================================================
) else (
    echo [ERROR] Upload failed with code %errorlevel%.
)
echo.
pause
