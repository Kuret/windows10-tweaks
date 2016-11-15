# Set current directory, sometimes it is not set correctly after running from bat/cmd
$currentDir = Split-Path $script:MyInvocation.MyCommand.Path
Set-Location $currentDir
# Set HKCR Registry drive
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"


# Uninstall Microsoft OneDrive
Stop-Process -ProcessName OneDrive -Force -ErrorAction SilentlyContinue
Stop-Process -ProcessName explorer -Force -ErrorAction SilentlyContinue
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Remove-Item "$env:localappdata\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:programdata\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:userprofile\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\OneDriveTemp" -Recurse -Force -ErrorAction SilentlyContinue

$path = "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name DisableFileSyncNGSC -Value 1 -Type DWord

$path = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name System.IsPinnedToNameSpaceTree -Value 0 -Type DWord

$path = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name System.IsPinnedToNameSpaceTree -Value 0 -Type DWord

Reg Load "HKU\Default" "C:\Users\Default\NTUSER.DAT"
$path = "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
if (Test-Path $path)
{
    Reg Delete $path /v "OneDriveSetup" /f
}
Reg Unload "HKU\Default"

Remove-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
Sleep 10
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    takeown /f $item.FullName /r /d y
    Remove-Item $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
}