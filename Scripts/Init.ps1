# Set current directory, sometimes it is not set correctly after running from bat/cmd
$currentDir = Split-Path $script:MyInvocation.MyCommand.Path
Set-Location $currentDir
# Set HKCR Registry drive
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"


# Remove some built-in windows apps
Get-AppxPackage *bingsports* | Remove-AppxPackage
Get-AppxPackage *candycrush* | Remove-AppxPackage
Get-AppxPackage *drawboard* | Remove-AppxPackage
Get-AppxPackage *farmville* | Remove-AppxPackage
Get-AppxPackage *flipboard* | Remove-AppxPackage
Get-AppxPackage *gameloft* | Remove-AppxPackage
Get-AppxPackage *getstarted* | Remove-AppxPackage
Get-AppxPackage *iheartradio* | Remove-AppxPackage
Get-AppxPackage *king.com* | Remove-AppxPackage
Get-AppxPackage *minecraft* | Remove-AppxPackage
Get-AppxPackage *netflix* | Remove-AppxPackage
Get-AppxPackage *officehub* | Remove-AppxPackage
Get-AppxPackage *pandora* | Remove-AppxPackage
Get-AppxPackage *picsart* | Remove-AppxPackage
Get-AppxPackage *shazam* | Remove-AppxPackage
Get-AppxPackage *skypeapp* | Remove-AppxPackage
Get-AppxPackage *sway* | Remove-AppxPackage
Get-AppxPackage *tunein* | Remove-AppxPackage
Get-AppxPackage *twitter* | Remove-AppxPackage
Get-AppxPackage *wunderlist* | Remove-AppxPackage
Get-AppxPackage *zune* | Remove-AppxPackage


# Set explorer default location to This PC
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name LaunchTo -Value 1 -Type Dword
# Remove Folders from This PC
$path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"
Remove-Item -Path "$path\{088e3905-0323-4b02-9826-5d99428e115f}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{374DE290-123F-4565-9164-39C4925E467B}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{d3162b92-9365-467a-956b-92703aca08af}" -ErrorAction SilentlyContinue
Remove-Item -Path "$path\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ErrorAction SilentlyContinue
# Show file extensions for all file types
Set-ItemProperty $path -Name HideFileExt -Value 0 -Type Dword


# Disable WiFi sense, which saves your passwords in the cloud
$path = "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name WiFiSenseCredShared -Value 0 -Type DWord
Set-ItemProperty $path -Name WiFiSenseOpen -Value 0 -Type DWord


# Disable automatic updates (you'll still get notified when updates are available)
$path = "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name AUOptions -Value 3 -Type DWord # Value 3 = Download updates but don't auto install


# Privacy Settings
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name Enabled -Value 0 -Type DWord

$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name EnableWebContentEvaluation -Value 0 -Type DWord

$path = "HKCU:\Software\Microsoft\Input\TIPC"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name Enabled -Value 0 -Type DWord

$path = "HKCU:\Control Panel\International\User Profile"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name HttpAcceptLanguageOptOut -Value 1 -Type DWord


# Disable DataCollection/Telemetry
$path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name AllowTelemetry -Value 0 -Type DWord


# Clear built in keylogger log
$diagtrackfile = "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
takeown /f $diagtrackfile /r /d y
Clear-Content $diagtrackfile -ErrorAction SilentlyContinue


# Remove HKCR registry reference
Remove-PSDrive "HKCR"