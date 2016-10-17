# Functions
function Unpin-App
{
    param([string]$appname)
((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from Start'} | %{$_.DoIt()}
}

# Set current directory, sometimes it is not set correctly after running from bat/cmd
$currentDir = Split-Path $script:MyInvocation.MyCommand.Path
Set-Location $currentDir

# Set HKCR Registry drive
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"


# Remove built-in windows apps
Get-AppxPackage *3dbuilder* | Remove-AppxPackage
Get-AppxPackage *alarms* | Remove-AppxPackage
Get-AppxPackage *bing* | Remove-AppxPackage
Get-AppxPackage *bingsports* | Remove-AppxPackage
Get-AppxPackage *calculator* | Remove-AppxPackage
Get-AppxPackage *candycrush* | Remove-AppxPackage
Get-AppxPackage *camera* | Remove-AppxPackage
Get-AppxPackage *communicationsapps* | Remove-AppxPackage
Get-AppxPackage *commsphone* | Remove-AppxPackage
Get-AppxPackage *drawboard* | Remove-AppxPackage
Get-AppxPackage *farmville* | Remove-AppxPackage
Get-AppxPackage *feedbackhub* | Remove-AppxPackage
Get-AppxPackage *flipboard* | Remove-AppxPackage
Get-AppxPackage *gameloft* | Remove-AppxPackage
Get-AppxPackage *getstarted* | Remove-AppxPackage
Get-AppxPackage *iheartradio* | Remove-AppxPackage
Get-AppxPackage *king.com* | Remove-AppxPackage
Get-AppxPackage *maps* | Remove-AppxPackage
Get-AppxPackage *messaging* | Remove-AppxPackage
Get-AppxPackage *minecraft* | Remove-AppxPackage
Get-AppxPackage *netflix* | Remove-AppxPackage
Get-AppxPackage *officehub* | Remove-AppxPackage
Get-AppxPackage *oneconnect* | Remove-AppxPackage
Get-AppxPackage *onenote* | Remove-AppxPackage
Get-AppxPackage *pandora* | Remove-AppxPackage
Get-AppxPackage people | Remove-AppxPackage
Get-AppxPackage *phone* | Remove-AppxPackage
Get-AppxPackage *photos* | Remove-AppxPackage
Get-AppxPackage *picsart* | Remove-AppxPackage
Get-AppxPackage *shazam* | Remove-AppxPackage
Get-AppxPackage *skypeapp* | Remove-AppxPackage
Get-AppxPackage *solitaire* | Remove-AppxPackage
Get-AppxPackage *soundrecorder* | Remove-AppxPackage
Get-AppxPackage *stickynotes* | Remove-AppxPackage
Get-AppxPackage *sway* | Remove-AppxPackage
Get-AppxPackage *tunein* | Remove-AppxPackage
Get-AppxPackage *twitter* | Remove-AppxPackage
Get-AppxPackage *windowsalarms* | Remove-AppxPackage
Get-AppxPackage *windowscamera* | Remove-AppxPackage
Get-AppxPackage *windowsphone* | Remove-AppxPackage
Get-AppxPackage *windowsreadinglist* | Remove-AppxPackage
Get-AppxPackage *windowssoundrecorder* | Remove-AppxPackage
Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage *wunderlist* | Remove-AppxPackage
Get-AppxPackage *zune* | Remove-AppxPackage

# Unpin Windows Store links
Unpin-App "Microsoft Edge"
Unpin-App "Cortana"
Unpin-App "Store"


# Set explorer default location to This PC
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name LaunchTo -Value 1 -Type Dword
# Show file extensions for all file types
Set-ItemProperty $path -Name HideFileExt -Value 0 -Type Dword
# Show drives with no media
Set-ItemProperty $path -Name HideDrivesWithNoMedia -Value 0 -Type DWord
# Show hidden files, folders and drives
Set-ItemProperty $path -Name ShowSuperHidden -Value 1 -Type Dword
# Show protected operating system files
Set-ItemProperty $path -Name Hidden -Value 1 -Type Dword


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


# Keyboard Accessibility tweaks
$path = "HKCU:\Control Panel\Accessibility\StickyKeys"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name Flags -Value "506" -Type String

$path = "HKCU:\Control Panel\Accessibility\Keyboard Response"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name Flags -Value "122" -Type String

$path = "HKCU:\Control Panel\Accessibility\ToggleKeys"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name Flags -Value "58" -Type String


# Remove WebResults from Windows Search
Set-WindowsSearchSetting -EnableWebResultsSetting $false


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

$path = "HKCU:\Software\Microsoft\Personalization\Settings"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name AcceptedPrivacyPolicy -Value 0 -Type DWord

# Disable Sync
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name BackupPolicy -Value 0x3c -Type DWord
Set-ItemProperty $path -Name DeviceMetadataUploaded -Value 0 -Type DWord
Set-ItemProperty $path -Name PriorLogons -Value 1 -Type DWord

$groups = @(
    "Accessibility"
    "AppSync"
    "BrowserSettings"
    "Credentials"
    "DesktopTheme"
    "Language"
    "PackageState"
    "Personalization"
    "StartLayout"
    "Windows"
)
foreach ($group in $groups) {
    $path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
    if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
    Set-ItemProperty $path -Name Enabled -Value 0 -Type Dword
}


# Disable scanning of contact info
$path = "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name HarvestContacts -Value 0 -Type DWord


# Microsoft Edge
$path = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name DoNotTrack -Value 1 -Type DWord

$path = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name ShowSearchSuggestionsGlobal -Value 0 -Type DWord

$path = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name FPEnabled -Value 0 -Type DWord

$path = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name EnabledV9 -Value 0 -Type DWord


# Disable running in the background for built-in apps
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
foreach ($key in (Get-ChildItem $path))
{
    Set-ItemProperty ("$path\" + $key.PSChildName) -Name Disabled -Value 1 -Type DWord
}


# Deny device access (let apps use camera/mic/location etc..)
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name Type -Value "LooselyCoupled" -Type String
Set-ItemProperty $path -Name Value -Value "Deny" -Type String
Set-ItemProperty $path -Name InitialAppValue -Value "Unspecified" -Type String

$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
foreach ($key in (Get-ChildItem $path))
{
    if (!($key.PSChildName -EQ "LooselyCoupled"))
    {
        Set-ItemProperty ("$path\" + $key.PSChildName) -Name Type -Value "InterfaceClass" -Type String
        Set-ItemProperty ("$path\" + $key.PSChildName) -Name Value -Value "Deny" -Type String
        Set-ItemProperty ("$path\" + $key.PSChildName) -Name InitialAppValue -Value "Unspecified" -Type String
    }
}


# Disable location sensor
$path = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name SensorPermissionState -Value 0 -Type DWord


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

# Remove windows 10 search box and task view button from taskbar
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name SearchboxTaskbarMode -Value 0 -Type DWord

$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name ShowTaskViewButton -Value 0 -Type DWord


# Enable System-wide Dark Theme (Applies only for Modern Apps)
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name AppsUseLightTheme -Value 0 -Type DWord

$path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name AppsUseLightTheme -Value 0 -Type DWord


# Disable Notifications and Action Center
$path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name UseActionCenterExperience -Value 0 -Type DWord

$path = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name DisableNotificationCenter -Value 1 -Type DWord


# Disable Lockscreen (Instantly arrive at password screen)
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name NoLockScreen -Value 1 -Type DWord


# Disable WiFi sense, which saves your passwords in the cloud
$path = "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name WiFiSenseCredShared -Value 0 -Type DWord
Set-ItemProperty $path -Name WiFiSenseOpen -Value 0 -Type DWord


# Disable automatic updates
$path = "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name NoAutoUpdate -Value 0 -Type DWord
Set-ItemProperty $path -Name AUOptions -Value 2 -Type DWord
Set-ItemProperty $path -Name ScheduledInstallDay -Value 0 -Type DWord
Set-ItemProperty $path -Name ScheduledInstallTime -Value 3 -Type DWord


# Disable p2p upload of updates
$path = "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name DODownloadMode -Value 0 -Type DWord

# Disable update available notification (Remember to manually check for updates once in a while)
takeown /F "$env:WinDIR\System32\MusNotification.exe"
icacls "$env:WinDIR\System32\MusNotification.exe" /deny "Everyone:(X)"
takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "Everyone:(X)"

# Disable DataCollection/Telemetry
$path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name AllowTelemetry -Value 0 -Type DWord

$path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name AllowTelemetry -Value 0 -Type DWord

$path = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
if (!(Test-Path $path)) { New-Item -Path $path -ItemType Key -Force }
Set-ItemProperty $path -Name AllowTelemetry -Value 0 -Type DWord


# Disable services
foreach ($serviceEntry in Get-Content "services.txt")
{
    Get-Service -Name $serviceEntry | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
}


# Disable scheduled tasks
$task = Get-ScheduledTask -TaskName "Microsoft Compatibility Appraiser"
Disable-ScheduledTask $task
$task = Get-ScheduledTask -TaskName "ProgramDataUpdater"
Disable-ScheduledTask $task
$task = Get-ScheduledTask -TaskName "Consolidator"
Disable-ScheduledTask $task
$task = Get-ScheduledTask -TaskName "KernelCeipTask"
Disable-ScheduledTask $task
$task = Get-ScheduledTask -TaskName "UsbCeip"
Disable-ScheduledTask $task


# Clear built in keylogger log
$diagtrackfile = "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
takeown /f $diagtrackfile /r /d y
Clear-Content $diagtrackfile -ErrorAction SilentlyContinue


# Block some Ad/Telemetry domains
$file = "$env:windir\System32\drivers\etc\hosts"
foreach ($domainEntry in Get-Content "domains.txt")
{
    $addEntry = "127.0.0.1 $domainEntry"
    if (!(Get-Content $file | Where-Object { $_.Contains("$addEntry") }))
    {
        $addEntry | Add-Content -PassThru $file -Encoding ASCII
    }
}


# Block some Telemetry IP adresses
$ips = Get-Content "ips.txt"
Remove-NetFirewallRule -DisplayName "Telemetry Block List" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Telemetry Block List" -Direction Outbound -Action Block -RemoteAddress ([string[]]$ips)


# Create God-Mode shortcut on Desktop (Contains links to every control panel / config menu in Windows)
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$GodMode = "$DesktopPath\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
if (!(Test-Path $GodMode))
{
    New-Item -Path $GodMode -ItemType Directory    
}


# Remove HKCR registry reference
Remove-PSDrive "HKCR"

# Restart explorer to apply visual changes
Stop-Process -ProcessName explorer