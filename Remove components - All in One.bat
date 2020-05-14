<# : Begin batch (batch script is in commentary of powershell v2.0+)
@echo off
@title Windows 10 craps remover
rem Ask admin rights

rem Permissions verifications
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

rem Not admin
if '%errorlevel%' NEQ '0' (
echo Vrification des privilges administrateur
goto UACPrompt
) else ( goto gotAdmin )

rem Prompt for admin rights
:UACPrompt
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
set params = %*:"="
echo UAC.ShellExecute "%~s0", "%params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

"%temp%\getadmin.vbs"
exit /B

:gotAdmin
if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
pushd "%CD%"
CD /D "%~dp0"

rem Use local variables
setlocal
rem Change current directory to script location - useful for including .ps1 files
cd %~dp0

echo ษออออออออออออออออออออออออออป
echo บ Windows 10 craps remover บ
echo ศออออออออออออออออออออออออออผ
echo.
echo Cet utilitaire permet de nettoyer le mieux
echo possible les installations fraches de Windows 10.
echo Il restera quelques paramtres … changer
echo et quelques programme … retirer.
echo.

: Invoke this file as powershell expression
powershell -executionpolicy remotesigned -Command "Invoke-Expression $([System.IO.File]::ReadAllText('%~f0'))"
: Restore environment variables present before setlocal and restore current directory
endlocal

echo.
echo ษอออออออออออออออออออออออออป
echo บ Remove licence checking บ
echo ศอออออออออออออออออออออออออผ
echo.
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f

echo.
echo ษออออออออออออออออออออออป
echo บ Change many settings บ
echo ศออออออออออออออออออออออผ
echo.
@rem *** Disable Some Service ***
sc stop DiagTrack
sc stop diagnosticshub.standardcollector.service
sc stop dmwappushservice
sc stop WMPNetworkSvc
echo Disable Windows Search (Useless when using SSD)
sc stop WSearch

sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
sc config RemoteRegistry start= disabled
sc config WMPNetworkSvc start= demand
echo Set Windows Search service to "on demand"
sc config WSearch start= demand

rem Settings -> Privacy -> General -> Let apps use my advertising ID...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
rem - SmartScreen Filter for Store Apps: Disable
rem reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
rem - Let websites provide locally...
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
rem WiFi Sense: HotSpot Sharing: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
rem WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f
rem Change Windows Updates to "Notify to schedule restart"
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t REG_DWORD /d 1 /f
rem Disable P2P Update downlods outside of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f
rem *** Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for ***
rem 0 = hide completely, 1 = show only icon, 2 = show long search box
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
rem *** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
rem reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
rem *** Set Windows Explorer to start on This PC instead of Quick Access ***
rem 1 = This PC, 2 = Quick access
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

rem *** SCHEDULED TASKS tweaks ***
rem schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
rem schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

echo.
echo ษออออออออออออออออออออออออออออออออป
echo บ Set Internet Explorer settings บ
echo ศออออออออออออออออออออออออออออออออผ
echo.
rem Disable IE First Run Wizard and RSS Feeds
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f
rem Disable Internet Explorer Enhanced Security Enhanced
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073" /v "IsInstalled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073" /v "IsInstalled" /t REG_DWORD /d 0 /f
rem Force off-screen composition in IE
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /v "Force Offscreen Composition" /t REG_DWORD /d 1 /f
rem Don t check if IE default browser
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /v "Check_Associations" /t REG_SZ /d "no" /f
rem Don t check if IE default browser
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /v "Default_Page_URL" /t REG_SZ /d "http://www.google.fr" /f
rem Disable warm is mix for secure and not secure elements
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonZoneCrossing" /t REG_DWORD /d 0 /f

echo.
echo ษออออออออออออออออออออออออออออออออออออออป
echo บ Remove Telemetry and Data Collection บ
echo ศออออออออออออออออออออออออออออออออออออออผ
echo.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f

echo.
echo ษออออออออออออออออออออออออออออออออออป
echo บ Show file extensions in Explorer บ
echo ศออออออออออออออออออออออออออออออออออผ
echo.
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f

echo.
echo ษอออออออออออออออออป
echo บ Disable Cortana บ
echo ศอออออออออออออออออผ
echo.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

echo.
echo ษอออออออออออออออออออออป
echo บ Remove Windows Tips บ
echo ศอออออออออออออออออออออผ
echo.
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f

echo.
echo ษออออออออออออออออออออออออออออออออออป
echo บ Turn off Windows Error Reporting บ
echo ศออออออออออออออออออออออออออออออออออผ
echo.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

echo.
echo ษอออออออออออออออออออออออออออออออออออออออออป
echo บ Remove Contact button and co in Taskbar บ
echo ศอออออออออออออออออออออออออออออออออออออออออผ
echo.
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d 0 /f
reg add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /V PeopleBand /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f

echo.
echo ษออออออออออออออออออออออออออออออออออออออออป
echo บ Remove Windows Welcome Experience page บ
echo ศออออออออออออออออออออออออออออออออออออออออผ
echo.
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f

echo.
echo ษอออออออออออออออออออออออออออออป
echo บ Remove suggestions and tips บ
echo ศอออออออออออออออออออออออออออออผ
echo.
rem Tips
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
rem App suggestions before Fall Creator Update
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
rem App Suggestion on Start (Fall Creator Update)
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
rem Get tips, tricks, and suggestions as you use Windows
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
rem MyPeople Suggested Apps
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 /f
rem Timeline suggestions
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
rem Cloud content user experience
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f

echo.
echo ษออออออออออออออออออออออออออออออออออออออป
echo บ Disable the Recently Added Apps list บ
echo ศออออออออออออออออออออออออออออออออออออออผ
echo.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f

echo.
echo ษอออออออออออออออออออออออออออออออออออออออออออออออออออออป
echo บ Set Buttons on Main Taskbar to when taskbar is full บ
echo ศอออออออออออออออออออออออออออออออออออออออออออออออออออออผ
echo.
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarGlomLevel" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MMTaskbarGlomLevel" /t REG_DWORD /d 1 /f

echo.
echo ษอออออออออออออออออออป
echo บ Remove Xbox Stuff บ
echo ศอออออออออออออออออออผ
echo.
sc delete XblAuthManager
sc delete XblGameSave
sc delete XboxNetApiSvc
sc delete XboxGipSvc
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f

echo.
echo ษอออออออออออออออออออออป
echo บ Disable Lock Screen บ
echo ศอออออออออออออออออออออผ
echo.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f

echo.
echo ษอออออออออออออออออออออออออออออออป
echo บ Disable Windows Startup delay บ
echo ศอออออออออออออออออออออออออออออออผ
echo.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f

echo.
echo ษออออออออออออออออออออออออออออป
echo บ Enable BlueLight Reduction บ
echo ศออออออออออออออออออออออออออออผ
echo.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.bluelightreduction.bluelightreductionstate\windows.data.bluelightreduction.bluelightreductionstate" /v Data /t REG_BINARY /d 434201000a0201002a06d0b7e3f5052a2b0e1043420100c61497c1ecaf90ea89eb0100000000 /f

echo.
echo ษอออออออออออออออออออออออป
echo บ Remove guest password บ
echo ศอออออออออออออออออออออออผ
echo.
net user Invit ""

echo.
echo ษอออออออออออออออออออออออออออออออป
echo บ Remove local network password บ
echo ศอออออออออออออออออออออออออออออออผ
echo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 0 /f

echo.
echo ษออออออออออออออออออออออออออป
echo บ Remove preinstalled apps บ
echo ศออออออออออออออออออออออออออผ
echo.
rem Preinstalled apps, Minecraft Twitter etc all that - still need a clean default start menu to fully eliminate
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "PreInstalledAppsEnabled" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "PreInstalledAppsEverEnabled" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "OEMPreInstalledAppsEnabled" /D 0 /F
rem MS shoehorning apps quietly into your profile
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SilentInstalledAppsEnabled" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "ContentDeliveryAllowed" /D 0 /F
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContentEnabled" /D 0 /F

echo.
echo ษออออออออออออออออออออป
echo บ Enable "Dark Mode" บ
echo ศออออออออออออออออออออผ
echo.
Reg Add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /T REG_DWORD /V "AppsUseLightTheme" /D 0 /F
Reg Add "HKLM\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /T REG_DWORD /V "AppsUseLightTheme" /D 0 /F

echo.
echo ษอออออออออออออออออออออออออออป
echo บ Activate Verr Num on boot บ
echo ศอออออออออออออออออออออออออออผ
echo.
:setverrnum
set choice=
set /p choice=Activer le pav numrique au dmarrage (y/n) ? 
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='y' goto verrnumy
if '%choice%'=='n' goto endsetverrnum
if '%choice%'=='Y' goto verrnumy
if '%choice%'=='N' goto endsetverrnum
echo Choix invalide ("%choice%")
echo.
goto start
:verrnumy
reg add "HKU\.DEFAULT\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d "80000002" /f
reg add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d "2" /f
echo.
:endsetverrnum

echo.
echo ษอออออออออออออออออป
echo บ Remove OneDrive บ
echo ศอออออออออออออออออผ
echo.
:setonedrive
echo.
echo Attention, la suppression de Onedrive supprimera aussi le dossier Onedrive.
echo Faites une sauvegarde avant de pousuivre.
echo.
set choice=
set /p choice=Supprimer Onedrive (y/n) ? 
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='y' goto onedrivey
if '%choice%'=='n' goto endsetonedrive
if '%choice%'=='Y' goto onedrivey
if '%choice%'=='N' goto endsetonedrive
echo Choix invalide ("%choice%")
echo.
goto setonedrive
:onedrivey
set x86="%SYSTEMROOT%\System32\OneDriveSetup.exe"
set x64="%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe"
echo Closing OneDrive process.
echo.
taskkill /f /im OneDrive.exe > NUL 2>&1
ping 127.0.0.1 -n 5 > NUL 2>&1
echo Uninstalling OneDrive.
echo.
if exist %x64% (
%x64% /uninstall
) else (
%x86% /uninstall
)
ping 127.0.0.1 -n 5 > NUL 2>&1
echo Removing OneDrive leftovers.
echo.
rd "%USERPROFILE%\OneDrive" /Q /S
rd "C:\OneDriveTemp" /Q /S
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S
echo Removeing OneDrive from the Explorer Side Panel.
echo.
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
:endsetonedrive

echo Restart explorer.exe to apply some settings...
echo.
start /wait TASKKILL /F /IM explorer.exe
start explorer.exe
echo.
echo You must check if there is some crap left.
echo.
timeout 60
goto:eof
#>
# here start your powershell script

# example: include another .ps1 scripts (commented, for quick copy-paste and test run)
#. ".\anotherScript.ps1"
$Bloatware = @(
		"Microsoft.BingNews"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.Messaging"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.Office.Lens"
		"Microsoft.Office.OneNote"
		"Microsoft.Office.Sway"
		"Microsoft.Office.Todo.List"
		"Microsoft.OneConnect"
		"Microsoft.People"
		"Microsoft.Print3D"
		#"Microsoft.SkypeApp"
		"Microsoft.StorePurchaseApp"
		"Microsoft.Whiteboard"
		"Microsoft.WindowsAlarms"
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsMaps"
		"Microsoft.Xbox.TCUI"
		"Microsoft.XboxApp"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxIdentityProvider"
		"Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
		"*Microsoft.3DBuilder*"
		"*Microsoft.Microsoft3DViewer*"
		"*Microsoft.Print3D*"
		"*Microsoft.MixedReality.Portal*"
		"*ActiproSoftwareLLC*"
		"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
		"*AppConnector*"
		"*AutodeskSketchBook*"
		"*BingFinance*"
		"*BingFoodAndDrink*"
		"*BingSports*"
		"*BingTravel*"
		"*BubbleWitch3Saga*"
		"*CandyCrush*"
		"*Commsphone*"
		"*Connectivitystore*"
		"*Deezer*"
		"*Disney*"
		"*Dolby*"
		"*Duolingo-LearnLanguagesforFree*"
		"*Drawboard*"
		"*EclipseManager*"
		"*Facebook*"
		"*Feedback*"
		"*Fitbitcoach*"
		"*Flipboard*"
		"*Fresh Paint*"
		"*Gardenscapes*"
		"*GetHelp*"
		"*Getstarted*"
		"*Holo*"
		"*king*"
		"*March*"
		"*MarchofEmpires*"
		"*Minecraft*"
		"*Netflix*"
		"*Officehub*"
		"*Oneconnect*"
		"*PandoraMediaInc*"
		"*Phone*"
		"*Phototastic*"
		"*QuickAssist*"
		"*Roblox*"
		"*Royal Revolt*"
		"*Speed Test*"
		"*Spotify*"
		"*Sway*"
		"*Twitter*"
		"*Wallet*"
		"*Whiteboard*"
		"*xbox*"
		"*Wunderlist*"
)
foreach ($Bloat in $Bloatware) {
		Get-AppxPackage $Bloat| Remove-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
		Write-Output "Trying to remove $Bloat."
}
