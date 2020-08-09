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
rem echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
rem set params = %*:"="
rem echo UAC.ShellExecute "%~s0", "%params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

rem "%temp%\getadmin.vbs"
echo.
echo Vous n'avez pas les droits administrateurs, certains tweaks ne fonctionneront pas.
echo.
timeout 5
goto letstart

:gotAdmin
rem if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
rem pushd "%CD%"
rem CD /D "%~dp0"

rem Use local variables
setlocal
rem Change current directory to script location - useful for including .ps1 files
rem cd %~dp0

:letstart
echo ษออออออออออออออออออออออออออป
echo บ Windows 10 craps remover บ
echo ศออออออออออออออออออออออออออผ
echo.
echo Cet utilitaire permet de nettoyer le mieux
echo possible les installations fraches de Windows 10.
echo Il restera quelques paramtres … changer
echo et quelques programme … retirer.
echo.
echo.
echo Prenez le temps de vrifier les programmes supprims par cet utilitaire.
echo Certains d'entre eux pourraient vous tre utiles.
echo La liste des programmes supprims se trouve en fin de fichier.
echo.
timeout 10

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
echo Set Windows Search service to "on demand"
sc config WSearch start= demand

sc config DiagTrack start= disabled
sc stop Diagtrack
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
sc config RemoteRegistry start= disabled
sc stop remoteregistry
sc config WMPNetworkSvc start= demand
sc stop RetailDemo
sc delete RetailDemo

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
rem Remove mediacenter relative tasks
schtasks /delete /f /tn "\Microsoft\Windows\media center\activateWindowssearch"
schtasks /delete /f /tn "\Microsoft\Windows\media center\configureinternettimeservice"
schtasks /delete /f /tn "\Microsoft\Windows\media center\dispatchrecoverytasks"
schtasks /delete /f /tn "\Microsoft\Windows\media center\ehdrminit"
schtasks /delete /f /tn "\Microsoft\Windows\media center\installplayready"
schtasks /delete /f /tn "\Microsoft\Windows\media center\mcupdate"
schtasks /delete /f /tn "\Microsoft\Windows\media center\mediacenterrecoverytask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\objectstorerecoverytask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\ocuractivate"
schtasks /delete /f /tn "\Microsoft\Windows\media center\ocurdiscovery"
schtasks /delete /f /tn "\Microsoft\Windows\media center\pbdadiscovery">nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\media center\pbdadiscoveryw1"
schtasks /delete /f /tn "\Microsoft\Windows\media center\pbdadiscoveryw2"
schtasks /delete /f /tn "\Microsoft\Windows\media center\pvrrecoverytask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\pvrscheduletask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\registersearch"
schtasks /delete /f /tn "\Microsoft\Windows\media center\reindexsearchroot"
schtasks /delete /f /tn "\Microsoft\Windows\media center\sqlliterecoverytask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\updaterecordpath"

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
rem Remove the finish config message
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f

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
sc stop XblAuthManager
sc stop XblGameSave
sc stop XboxNetApiSvc
sc stop XboxGipSvc
sc stop xbgm
sc config XblAuthManager start= demand
sc config XblGameSave start= demand
sc config XboxNetApiSvc start= demand
sc config XboxGipSvc start= demand
sc config xbgm start= demand
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
echo ษออออออออออออออออออออออออออออออออออออออออออออป
echo บ Allow local network access when smb1 share บ
echo ศออออออออออออออออออออออออออออออออออออออออออออผ
echo.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t reg_dword /d 00000001 /f

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

echo.
echo ษออออออออออออออออออออออออออออออออออออออออออออออออป
echo บ Restart explorer.exe to apply some settings... บ
echo ศออออออออออออออออออออออออออออออออออออออออออออออออผ
echo.
start /wait TASKKILL /F /IM explorer.exe
start explorer.exe

echo.
echo ษอออออออออออออออออออออออออป
echo บ Update Windows Defender บ
echo ศอออออออออออออออออออออออออผ
echo.
"%ProgramFiles%\Windows Defender\mpcmdrun.exe" -SignatureUpdate

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
		"Microsoft.Windows.Cortana"
		"Microsoft.549981C3F5F10"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		#"Microsoft.Messaging"
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
		#"microsoft.windowscommunicationsapps"
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
		"*Wunderlist*"
		"*DragonManiaLegends"
		"*HiddenCityMysteryofShadows"
		"*MarchofEmpires"
		"*toolbar*"
		"06DAC6F6.StumbleUpon"
		"09B6C2D8.TheTreasuresofMontezuma3"
		"0E3921EB.sMedioTrueDVDforHP"
		"10084FinerCode.ChessTactics"
		"11610RobertVarga.StopwatchFree"
		"12262FiveStarGames.CrossyChickenRoad"
		"12726CosmosChong.AdvancedEnglishDictionary"
		"12926CandyKingStudio.StickmanWarriorsFighting"
		"134D4F5B.Box*"
		"1430GreenfieldTechnologie.PuzzleTouch*"
		"17036IYIA.StorySaverperInstagram"
		"184MagikHub.TextizeMindMap"
		"1867LennardSprong.PortablePuzzleCollection"
		"19965MattHafner.WifiAnalyzer"
		"20815shootingapp.AirFileViewer"
		"21090PaddyXu.QuickLook"
		"2121MagicCraftGames.ExplorationLiteCraftMining"
		"2164RexileStudios.FastYoutubeDownloader"
		"21824TapFunGames.DashImpossibleGeometryLite"
		"22062EdgeWaySoftware.TheLogosQuiz"
		"22094SynapticsIncorporate.AudioControls"
		"22094SynapticsIncorporate.SmartAudio2"
		"22094SynapticsIncorporate.SmartAudio3"
		"22380CatalanHilton.SolitaireDeluxe2019"
		"22450.BestVideoConverter"
		"24712m1dfmmengesha.TestFrameworkBP052015"
		"24712m1dfmmengesha.TestFrameworkBackpublish050515"
		"24712m1dfmmengesha.TestFrameworkwin81appxneutral06"
		"24712m1dfmmengesha.mxtest2"
		"25231MatthiasShapiro.BrickInstructions"
		"25529kineapps.MyCalendar"
		"25920Bala04.Mideo-VideoPlayer"
		"26704KathyGrobbelaar.GPSRoutes"
		"26720RandomSaladGamesLLC.HeartsDeluxe*"
		"26720RandomSaladGamesLLC.Hexter"
		"26720RandomSaladGamesLLC.SimpleMahjong"
		"26720RandomSaladGamesLLC.SimpleMinesweeper"
		"26720RandomSaladGamesLLC.SimpleSolitaire*"
		"26720RandomSaladGamesLLC.SimpleSpiderSolitaire"
		"26720RandomSaladGamesLLC.Spades"
		"2703103D.McAfeeCentral"
		"27182KingdomEntertainment.Bubble.io-Agario"
		"27182KingdomEntertainment.FlippyKnife3D"
		"27182KingdomEntertainment.PixelGun3DPocketCrafting"
		"2724RoyaleDragonPacoGames.SpaceFrontierFree"
		"27345RickyWalker.BlackjackMaster3"
		"28287mfYSoftware.MiniRadioPlayer"
		"29313JVGoldSoft.5962504421940"
		"29534ukaszKurant.Logicos"
		"29534ukaszKurant.Logicos2"
		"29814LackoLuboslav.Bluetoothanalyzer"
		"29982CsabaHarmath.UnCompress*"
		"2CB8455F.Tanks"
		"2FE3CB00.PICSART-PHOTOSTUDIO"
		"2FE3CB00.PicsArt-PhotoStudio*"
		"30472FranciscoRodrigues.14392819EE0CF"
		"32443PocketNet.Paper.io"
		"32988BernardoZamora.BackgammonPro"
		"32988BernardoZamora.SolitaireHD"
		"33916DoortoApps.HillClimbSimulation4x4"
		"34697joal.EasyMovieMaker"
		"35229MihaiM.QuizforGeeks"
		"35300Kubajzl.MCGuide"
		"35300Kubajzl.Slitherio"
		"37162EcsolvoTechnologies.UltraStopwatchTimer"
		"37442SublimeCo.AlarmClockForYou"
		"37457BenoitRenaud.HexWar"
		"37806WilhelmsenStudios.NowyouareinOrbit"
		"39674HytoGame.TexasHoldemOnline"
		"3973catalinux.BackgammonReloaded"
		"39806kalinnikol.FreeCellSolitaireHD"
		"39806kalinnikol.FreeHeartsHD"
		"39806kalinnikol.TheSpiderSolitaireHD"
		"401053BladeGames.3DDungeonEscape"
		"40459File-New-Project.EarTrumpet"
		"40538vasetest101.TESTFRAMEWORKABO2"
		"41038AXILESOFT.ACGMEDIAPLAYER"
		"41879VbfnetApps.FileDownloader"
		"42569AlexisPayendelaGaran.OtakuAssistant"
		"4262TopFreeGamesCOC.RunSausageRun"
		"4408APPStar.RiderUWP"
		"44218hungrymousegames.Mou"
		"44352GadgetWE.UnitConversion"
		"45375MiracleStudio.Splix.io"
		"45515SkyLineGames.Backgammon.free"
		"45604EntertainmentandMusi.Open7-Zip"
		"46928bounde.EclipseManager*"
		"47404LurkingDarknessOfRoy.SimpleStrategyRTS"
		"48682KiddoTest.Frameworkuapbase"
		"48938DngVnPhcThin.Deeep.io"
		"4961ThePlaymatE.DigitalImagination"
		"4AE8B7C2.Booking.comPartnerApp"
		"4AE8B7C2.Booking.comPartnerEdition*"
		"50856m1dfLL.TestFrameworkProd06221501"
		"51248Raximus.Dobryplan"
		"5269FriedChicken.YouTubeVideosDownloader*"
		"52755VolatileDove.LovingCubeEngine-experimentaledi"
		"55407EducationLife.LearntoMicrosoftAccess2010forBe"
		"56081SweetGamesBox.SlitherSnake.io"
		"56491SimulationFarmGames.100BallsOriginal"
		"57591LegendsSonicSagaGame.Twenty48Solitaire"
		"57689BIGWINStudio.Rider3D"
		"57868Codaapp.UploadforInstagram"
		"58033franckdakam.4KHDFreeWallpapers"
		"5895BlastCrushGames.ExtremeCarDrivingSimulator2"
		"59091GameDesignStudio.HeartsUnlimited"
		"59091GameDesignStudio.MahjongDe*"
		"59169Willpowersystems.BlueSkyBrowser"
		"5A894077.McAfeeSecurity"
		"64885BlueEdge.OneCalendar*"
		"65284GameCabbage.OffRoadDriftSeries"
		"65327Damicolo.BartSimpsonSkateMania"
		"664D3057.MahjongDeluxeFree"
		"6Wunderkinder.Wunderlist"
		"7475BEDA.BitcoinMiner"
		"780F5C7B.FarmUp"
		"7906AAC0.TOSHIBACanadaPartners*"
		"7906AAC0.ToshibaCanadaWarrantyService*"
		"7EE7776C.LinkedInforWindows"
		"7digitalLtd.7digitalMusicStore*"
		"828B5831.HiddenCityMysteryofShadows"
		"89006A2E.AutodeskSketchBook*"
		"8tracksradio.8tracksradio"
		"9393SKYFamily.RollyVortex"
		"9426MICRO-STARINTERNATION.DragonCenter"
		"95FE1D22.VUDUMoviesandTV"
		"9E2F88E3.Twitter"
		"9FD20106.MediaPlayerQueen"
		"A-Volute.Nahimic"
		"A025C540.Yandex.Music"
		"A278AB0D.DisneyMagicKingdoms"
		"A278AB0D.DragonManiaLegends*"
		"A278AB0D.GameloftGames"
		"A278AB0D.MarchofEmpires"
		"A278AB0D.PaddingtonRun"
		"A34E4AAB.YogaChef*"
		"A8C75DD4.Therefore"
		"A97ECD55.KYOCERAPrintCenter"
		"AD2F1837.BOAudioControl"
		"AD2F1837.BangOlufsenAudioControl"
		"AD2F1837.DiscoverHPTouchpointManager"
		"AD2F1837.GettingStartedwithWindows8"
		"AD2F1837.HPAudioCenter"
		"AD2F1837.HPBusinessSlimKeyboard"
		"AD2F1837.HPClassroomManager"
		"AD2F1837.HPConnectedMusic"
		"AD2F1837.HPConnectedPhotopoweredbySnapfish"
		"AD2F1837.HPCoolSense"
		"AD2F1837.HPFileViewer"
		"AD2F1837.HPGames"
		"AD2F1837.HPInc.EnergyStar"
		"AD2F1837.HPInteractiveLight"
		"AD2F1837.HPJumpStart"
		"AD2F1837.HPJumpStarts"
		"AD2F1837.HPPCHardwareDiagnosticsWindows"
		"AD2F1837.HPPhoneWise"
		"AD2F1837.HPPowerManager"
		"AD2F1837.HPPrimeFree"
		"AD2F1837.HPPrimeGraphingCalculator"
		"AD2F1837.HPPrivacySettings"
		"AD2F1837.HPRegistration"
		"AD2F1837.HPSupportAssistant"
		"AD2F1837.HPSureShieldAI"
		"AD2F1837.HPSystemEventUtility"
		"AD2F1837.HPSystemInformation"
		"AD2F1837.HPThermalControl"
		"AD2F1837.HPWelcome"
		"AD2F1837.HPWorkWise"
		"AD2F1837.SmartfriendbyHPCare"
		"AD2F1837.bulbDigitalPortfolioforHPSchoolPack"
		"ASUSCloudCorporation.MobileFileExplorer"
		"AccuWeather.AccuWeatherforWindows8*"
		"AcerIncorporated*"
		"AcerIncorporated.AcerCareCenter"
		"AcerIncorporated.AcerCollection"
		"AcerIncorporated.AcerCollectionS"
		"AcerIncorporated.AcerExplorer"
		"AcerIncorporated.AcerRegistration"
		"AcerIncorporated.PredatorSenseV31"
		"AcerIncorporated.QuickAccess"
		"AcerIncorporated.UserExperienceImprovementProgram"
		"AcrobatNotificationClient"
		"ActiproSoftwareLLC*"
		"ActiproSoftwareLLC.562882FEEB491"
		"Adictiz.SpaceDogRun"
		"AdobeNotificationClient"
		"AdobeSystemsIncorporated.AdobePhotoshopExpress*"
		"AdobeSystemsIncorporated.AdobeRevel*"
		"AdvancedMicroDevicesInc-2.59462344778C5"
		"AdvancedMicroDevicesInc-2.AMDDisplayEnhance"
		"AeriaCanadaStudioInc.BlockWarsSurvivalGames"
		"AeriaCanadaStudioInc.CopsVsRobbersJailBreak"
		"Amazon.com.Amazon*"
		"AppUp.IntelAppUpCatalogueAppWorldwideEdition*"
		"AppUp.IntelGraphicsExperience"
		"AppUp.IntelManagementandSecurityStatus"
		"AppUp.IntelOptaneMemoryandStorageManagement"
		"AppUp.ThunderboltControlCenter"
		"B9ECED6F.ASUSBatteryHealthCharging"
		"B9ECED6F.ASUSCalculator"
		"B9ECED6F.ASUSFiveinARow"
		"B9ECED6F.ASUSGIFTBOX*"
		"B9ECED6F.ASUSPCAssistant"
		"B9ECED6F.ASUSProductRegistrationProgram"
		"B9ECED6F.ASUSTutor"
		"B9ECED6F.ASUSTutorial"
		"B9ECED6F.ASUSWelcome"
		"B9ECED6F.ArmouryCrate"
		"B9ECED6F.AsusConverter"
		"B9ECED6F.GameVisual"
		"B9ECED6F.MyASUS"
		"B9ECED6F.TheWorldClock"
		"B9ECED6F.eManual"
		"BD9B8345.AlbumbySony*"
		"BD9B8345.MusicbySony*"
		"BD9B8345.Socialife*"
		"BD9B8345.VAIOCare*"
		"BD9B8345.VAIOMessageCenter*"
		"BrowseTechLLC.AdRemover"
		"C27EB4BA.DropboxOEM"
		"COMPALELECTRONICSINC.AlienwareOSDKits"
		"COMPALELECTRONICSINC.AlienwareTypeCaccessory"
		"COMPALELECTRONICSINC.Alienwaredockingaccessory"
		"ChaChaSearch.ChaChaPushNotification*"
		"CirqueCorporation.DellPointStick"
		"ClearChannelRadioDigital.iHeartRadio*"
		"CrackleInc.Crackle*"
		"CreativeTechnologyLtd.SoundBlasterConnect"
		"CyberLink.PowerDirectorforMSI"
		"CyberLinkCorp.ac.AcerCrystalEye*"
		"CyberLinkCorp.ac.PhotoDirectorforacerDesktop"
		"CyberLinkCorp.ac.PowerDirectorforacerDesktop"
		"CyberLinkCorp.ac.SocialJogger*"
		"CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC"
		"CyberLinkCorp.hs.YouCamforHP*"
		"CyberLinkCorp.id.PowerDVDforLenovoIdea*"
		"CyberLinkCorp.ss.SCamera"
		"CyberLinkCorp.ss.SGallery"
		"CyberLinkCorp.ss.SPlayer"
		"CyberLinkCorp.th.Power2GoforLenovo"
		"CyberLinkCorp.th.PowerDVDforLenovo"
		"D52A8D61.FarmVille2CountryEscape*"
		"D5BE6627.CompuCleverITHMBViewer"
		"D5BE6627.UltraBlu-rayPlayerSupportsDVD"
		"D5EA27B7.Duolingo-LearnLanguagesforFree*"
		"DB6EA5DB.CyberLinkMediaSuiteEssentials*"
		"DB6EA5DB.MediaSuiteEssentialsforDell"
		"DB6EA5DB.Power2GoforDell"
		"DB6EA5DB.PowerDirectorforDell"
		"DB6EA5DB.PowerMediaPlayerforDell"
		"DBA41F73.ColorNoteNotepadNotes"
		"DTSInc.51789B84BE3D7"
		"DTSInc.DTSCustomforAsus"
		"DTSInc.DTSHeadphoneXv1"
		"DailymotionSA.Dailymotion*"
		"DellInc.AlienwareCommandCenter"
		"DellInc.AlienwareCustomerConnect"
		"DellInc.AlienwareProductRegistration"
		"DellInc.DellCommandUpdate"
		"DellInc.DellCustomerConnect"
		"DellInc.DellDigitalDelivery"
		"DellInc.DellGettingStartedwithWindows8"
		"DellInc.DellHelpSupport"
		"DellInc.DellPowerManager"
		"DellInc.DellProductRegistration"
		"DellInc.DellShop"
		"DellInc.DellSupportAssistforPCs"
		"DellInc.DellUpdate"
		"DellInc.MyDell"
		"DeviceDoctor.RAROpener"
		"DevolverDigital.MyFriendPedroWin10"
		"DolbyLaboratories.DolbyAccess*"
		"DolbyLaboratories.DolbyAtmosSoundSystem"
		"DolbyLaboratories.DolbyAtmosforGaming"
		"DolbyLaboratories.DolbyAudioPremium"
		"Drawboard.DrawboardPDF*"
		"DriverToaster*"
		"E046963F.LenovoCompanion*"
		"E046963F.LenovoSupport*"
		"E0469640.CameraMan*"
		"E0469640.DeviceCollaboration*"
		"E0469640.LenovoRecommends*"
		"E0469640.LenovoUtility"
		"E0469640.NerveCenter"
		"E0469640.YogaCameraMan*"
		"E0469640.YogaPhoneCompanion*"
		"E0469640.YogaPicks*"
		"E3D1C1C1.MEOGO"
		"E97CB0A1.LogitechCameraController"
		"ELANMicroelectronicsCorpo.ELANTouchpadSetting"
		"ESPNInc.WatchESPN*"
		"Ebates.EbatesCashBack"
		"EncyclopaediaBritannica.EncyclopaediaBritannica*"
		"EnnovaResearch.ToshibaPlaces"
		"Evernote.Evernote"
		"Evernote.Skitch*"
		"EvilGrogGamesGmbH.WorldPeaceGeneral2017"
		"F223684A.SkateboardParty2Lite"
		"F5080380.ASUSPowerDirector*"
		"Facebook.317180B0BB486"
		"Facebook.Facebook"
		"Facebook.InstagramBeta*"
		"FilmOnLiveTVFree.FilmOnLiveTVFree*"
		"Fingersoft.HillClimbRacing"
		"Fingersoft.HillClimbRacing2"
		"FingertappsInstruments*"
		"FingertappsOrganizer*"
		"Flipboard.Flipboard*"
		"FreshPaint*"
		"GAMELOFTSA.Asphalt8Airborne*"
		"GAMELOFTSA.DespicableMeMinionRush"
		"GAMELOFTSA.GTRacing2TheRealCarExperience"
		"GAMELOFTSA.SharkDash*"
		"GIANTSSoftware.FarmingSimulator14"
		"GameCircusLLC.CoinDozer"
		"GameGeneticsApps.FreeOnlineGamesforLenovo*"
		"GettingStartedwithWindows8*"
		"GoogleInc.GoogleSearch"
		"HPConnectedMusic*"
		"HPConnectedPhotopoweredbySnapfish*"
		"HPRegistration*"
		"HuluLLC.HuluPlus*"
		"InsightAssessment.CriticalThinkingInsight"
		"JigsWar*"
		"K-NFBReadingTechnologiesI.BookPlace*"
		"KasperskyLab.KasperskyNow*"
		"KeeperSecurityInc.Keeper"
		"KindleforWindows8*"
		"Kortext.Kortext"
		"LGElectronics.LGControlCenter"
		"LGElectronics.LGEasyGuide2.0"
		"LGElectronics.LGOSD3"
		"LGElectronics.LGReaderMode"
		"LGElectronics.LGTroubleShooting2.0"
		"LenovoCorporation.LenovoID*"
		"LenovoCorporation.LenovoSettings*"
		"MAGIX.MusicMakerJam*"
		"MSWP.DellTypeCStatus"
		"McAfeeInc.01.McAfeeSecurityAdvisorforDell"
		"McAfeeInc.05.McAfeeSecurityAdvisorforASUS"
		"McAfeeInc.06.McAfeeSecurityAdvisorforLenovo"
		"Mobigame.ZombieTsunami"
		"MobileFileExplorer*"
		"MobilesRepublic.NewsRepublic"
		"MobirateLtd.ParkingMania"
		"MusicMakerJam*"
		"NAMCOBANDAIGamesInc.PAC-MANChampionshipEditionDXfo*"
		"NAVER.LINEwin8*"
		"NBCUniversalMediaLLC.NBCSportsLiveExtra*"
		"NORDCURRENT.COOKINGFEVER"
		"NevosoftLLC.MushroomAge"
		"NextGenerationGames.WildDinosaurSniperHuntingHuntt"
		"Nordcurrent.CookingFever"
		"OCS.OCS"
		"Ookla.SpeedtestbyOokla"
		"OrangeFrance.MaLivebox"
		"OrangeFrance.MailOrange"
		"OrangeFrance.TVdOrange"
		"PORTOEDITORA.EVe-Manuais"
		"PandoraMediaInc.29680B314EFC2"
		"PhotoAndVideoLabsLLC.MakeaPoster-ContinuumMediaSer"
		"PinballFx2*"
		"Pinterest.PinItButton"
		"Playtika.CaesarsSlotsFreeCasino*"
		"Priceline"
		"PricelinePartnerNetwork.Booking.comEMEABigsavingso"
		"PricelinePartnerNetwork.Booking.comUSABigsavingson"
		"PricelinePartnerNetwork.Priceline.comTheBestDealso"
		"PublicationsInternational.iCookbookSE*"
		"ROBLOXCorporation.ROBLOX"
		"RandomSaladGamesLLC.GinRummyProforHP*"
		"RandomSaladGamesLLC.HeartsforHP"
		"ReaderNotificationClient"
		"RealtekSemiconductorCorp.HPAudioControl"
		"RealtekSemiconductorCorp.RealtekAudioControl"
		"Relay.com.KiosqueRelay"
		"RivetNetworks.KillerControlCenter"
		"RivetNetworks.SmartByte"
		"RoomAdjustment"
		"RubenGerlach.Solitaire-Palace"
		"SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService"
		"SAMSUNGELECTRONICSCO.LTD.PCGallery"
		"SAMSUNGELECTRONICSCO.LTD.PCMessage"
		"SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner"
		"SAMSUNGELECTRONICSCO.LTD.SamsungPrinterExperience"
		"SAMSUNGELECTRONICSCO.LTD.Wi-FiTransfer"
		"STMicroelectronicsMEMS.DellFreeFallDataProtection"
		"ScreenovateTechnologies.DellMobileConnect"
		"ShazamEntertainmentLtd.Shazam*"
		"SilverCreekEntertainment.HardwoodHearts"
		"SkisoSoft.FireEngineSimulator"
		"SkisoSoft.TrashTruckSimulator"
		"SocialQuantumIreland.WildWestNewFrontier"
		"SolidRhino.SteelTactics"
		"SonicWALL.MobileConnect"
		"SpotifyAB.SpotifyMusic"
		"SprakelsoftUG.CrocsWorld"
		"SprakelsoftUG.FlapFlapFlap"
		"SymantecCorporation.5478111E43ACF"
		"SymantecCorporation.NortonSafeWeb"
		"SymantecCorporation.NortonStudio*"
		"SynapticsIncorporated.SynHPCommercialDApp"
		"SynapticsIncorporated.SynHPConsumerDApp"
		"TOSHIBATEC.ToshibaPrintExperience"
		"TeenGamesLLC.HelicopterSimulator3DFree-ContinuumRe"
		"TelegraphMediaGroupLtd.TheTelegraphforLenovo*"
		"TelltaleGames.MinecraftStoryMode-ATelltaleGamesSer"
		"TheNewYorkTimes.NYTCrossword*"
		"ThumbmunkeysLtd.PhototasticCollage"
		"ThumbmunkeysLtd.PhototasticCollage*"
		"ToshibaAmericaInformation.ToshibaCentral*"
		"TreeCardGames.HeartsFree"
		"TripAdvisorLLC.TripAdvisorHotelsFlightsRestaurants*"
		"TuneIn.TuneInRadio*"
		"UniversalMusicMobile.HPLOUNGE"
		"UptoElevenDigitalSolution.mysms-Textanywhere*"
		"VectorUnit.BeachBuggyRacing"
		"Vimeo.Vimeo*"
		"WavesAudio.MaxxAudioProforDell2019"
		"WavesAudio.WavesMaxxAudioProforDell"
		"Weather.TheWeatherChannelforHP*"
		"Weather.TheWeatherChannelforLenovo*"
		"WeatherBug.a.WeatherBug"
		"WhatsNew"
		"WildTangentGames*"
		"WildTangentGames.-GamesApp-"
		"WildTangentGames.63435CFB65F55"
		"WinZipComputing.WinZipUniversal*"
		"XINGAG.XING"
		"XLabzTechnologies.22450B0065C6A"
		"XeroxCorp.PrintExperience"
		"YouSendIt.HighTailForLenovo*"
		"ZeptoLabUKLimited.CutTheRope"
		"ZhuhaiKingsoftOfficeSoftw.WPSOffice"
		"ZhuhaiKingsoftOfficeSoftw.WPSOfficeforFree"
		"ZinioLLC.Zinio*"
		"Zolmo.JamiesRecipes"
		"avonmobility.EnglishClub"
		"eBayInc.eBay*"
		"esobiIncorporated.newsXpressoMetro*"
		"fingertappsASUS.FingertappsInstrumentsrecommendedb*"
		"fingertappsASUS.JigsWarrecommendedbyASUS*"
		"fingertappsasus.FingertappsOrganizerrecommendedbyA*"
		"flaregamesGmbH.RoyalRevolt2*"
		"king.com*"
		"king.com.BubbleWitch3Saga"
		"king.com.CandyCrushFriends"
		"king.com.CandyCrushSaga"
		"king.com.CandyCrushSodaSaga"
		"king.com.FarmHeroesSaga"
		"king.com.ParadiseBay"
		"n-tvNachrichtenfernsehenG.n-tvNachrichten"
		"sMedioforHP.sMedio360*"
		"sMedioforToshiba.TOSHIBAMediaPlayerbysMedioTrueLin*"
		"www.cyberlink.com.AudioDirectorforLGE"
		"www.cyberlink.com.ColorDirectorforLGE"
		"www.cyberlink.com.PhotoDirectorforLGE"
		"www.cyberlink.com.PowerDirectorforLGE"
		"www.cyberlink.com.PowerMediaPlayerforLGE"
		"zuukaInc.iStoryTimeLibrary*"
)

foreach ($Bloat in $Bloatware) {
		Get-AppxPackage $Bloat| Remove-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
		Write-Output "Trying to remove $Bloat."
}
