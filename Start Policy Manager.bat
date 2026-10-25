@echo off
rem Launches Windows Policy Manager (it will ask for admin rights).
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0WinPolicyManager.ps1"
