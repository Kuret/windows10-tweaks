@echo off
SET ThisScriptsDirectory=%~dp0
SET PowerShellScriptPath=%ThisScriptsDirectory%/Scripts/Init.ps1

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoExit -NoProfile -ExecutionPolicy Bypass -File """"%PowerShellScriptPath%"""" ' -Verb RunAs}";