# Windows 10 Tweaks
Script to run after Windows 10 install and update
<br/><br/>
Check the Powershell script (Scripts/init.ps1) carefully before executing anything! (Always do this when executing a script from an unknown source)
<br/><br/>
Start the script by running Init.bat, this will ensure the PowerShell script has the right permissions applied
<br/><br/>
The script does the following:
<br/>
* Remove some built-in Windows Apps
* Set Explorer's default location to 'This PC'
* Remove results from the web from start menu search
* Disable WiFi sense, which saves your passwords to the cloud
* Disable Automatic Updates (You'll still get notified when updates are available)
* Disable Data Collection and Telemetry
* Clear the log of Windows built-in keylogger
<br/><br><br/>
There is also a script to remove the pre-installed OneDrive, start it by running OneDrive.bat
