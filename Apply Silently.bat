@echo off
rem Applies the ticked ("enabled": true) policies from policies.json with no GUI.
rem Use this to roll the same setup out to other office PCs.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinPolicyManager.ps1" -Silent
