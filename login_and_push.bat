@echo off
title GitHub Login and Push to ndhanesh25-dotcom
color 0A
cls
echo ==============================================================================
echo       CONNECTING AND UPLOADING TO ndhanesh25-dotcom GITHUB ACCOUNT
echo ==============================================================================
echo.
echo [*] Authorizing GitHub for ndhanesh25-dotcom (n.dhanesh25@gmail.com)...
echo [*] A 8-character code will appear below.
echo [*] Copy the code, press ENTER to open the browser, and click Confirm!
echo.
gh auth login --hostname github.com --git-protocol https --web
echo.
echo [*] Configuring Git credentials...
gh auth setup-git
echo.
echo [*] Uploading all project files to ndhanesh25-dotcom...
cd /d "%~dp0"
git remote set-url second https://github.com/ndhanesh25-dotcom/ARP-Spoofing-and-Man-in-the-Middle-MITM-Attack-Detection.git
git push -u second main
echo.
if %errorlevel% equ 0 (
    echo ==============================================================================
    echo [SUCCESS] ALL PROJECT WORK HAS BEEN UPLOADED TO ndhanesh25-dotcom!
    echo ==============================================================================
) else (
    echo [ERROR] Upload encountered an issue.
)
echo.
pause
