# Windows 10 Tweaks
Script to run after Windows 10 install and update
<br/><br/>
Check the Powershell script (Scripts/init.ps1) carefully before executing anything! (Always do this when executing a script from an unknown source)
<br/><br/>
Start the script by running Init.bat, this will ensure the PowerShell script has the right permissions applied
<br/><br/>
The script does the following:
<br/>
* Remove most of the built-in Windows Apps without breaking Store functionality
* Set Explorer's default location to 'This PC'
* Tweak some accessibility settings for the keyboard (StickyKeys off etc)
* Remove results from the web from start menu search
* Turn off the privacy settings corresponding to the ones in Settings/Privacy
* Disable syncing for apps and settings
* Disable scanning and collection of contact info
* Configure privacy and telemetry settings for Microsoft Edge
* Disable running in the background for built-in Windows apps
* Deny apps access to location/camera/mic/etc
* Disable the location sensor if device has one
* Uninstall OneDrive
* Remove the Search Bar and Task View buttons from the taskbar
* Apply a system-wide Dark Theme (Only works for Modern apps)
* Disable Notifications and Action Center
* Disable lockscreen (Instantly arrive at password screen)
* Disable WiFi sense, which saves your passwords to the cloud
* Disable Automatic Updates (Remember to check for security updates once in a while!)
* Disable p2p sharing of Windows Updates
* Disable the notification that tells the user when updates are available
* Disable Data Collection and Telemetry
* Disable some services which collect data
* Clear the log of Windows built-in keylogger
* Block some domains associated with Windows Telemetry
* Block some IPs associated with Windows Telemetry
* Create a God-Mode shortcut on start screen, which contains links to all config menus in Windows
