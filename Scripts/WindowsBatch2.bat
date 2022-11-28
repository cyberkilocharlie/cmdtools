@echo OFF
color 0a
echo 	   TEAM 15-4209
echo       Windows Batch Script 2                            cc-nd-nc
echo       11-2022                                                -KC

echo Download MalwareBytes [y/n]
set /p rdpChk="Download MalwareBytes [y/n]"
if %rdpChk%==y (
	echo Download MalwareBytes...
	start firefox.exe %https://www.malwarebytes.com/mwb-download/thankyou/%
	powershell Invoke-WebRequest -OutFile MBRTKit.exe https://data-cdn.mbamupdates.com/web/mbar-1.10.3.1001.exe
	MBRTKit.exe
	pause
)
if %rdpChk%==n (
	echo Skipped  MalwareBytes Download
)

echo Listing All Users...
set allUsers="dir C:\Users /b"
for /F "tokens=1*" %%G in ('%allUsers%') DO (
	echo %%G
)
echo ~END OF LIST~
pause
echo Fix Users...
start ms-settings /wait
pause
echo Fix UAC Settings...
C:\Windows\System32\UserAccountControlSettings.exe
pause

echo Listing Tasks...
tasklist
pause
echo Tasks Listed

echo Getting Windows Defender Stats...
Get-MpComputerStatus
pause
echo Running Windows Defender Scan...
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2
echo Opening Windows Defender...
%ProgramFiles%\Windows Defender\MpCmdRun.exe
echo Windows Defender Managed

echo Turning firewall on...
netsh advfirewall set allprofiles state on
echo Firewall on

echo Listing Networks...
netstat
echo Networks Listed

echo Opening Windows Defender Security Center...
mpcmdrun.exe
pause
echo Opened Windows Defender Security Center

echo Do you wish to remove disallowed media files? [y/n]
choice /c yn /m "Remove disallowed media files [y/n]"
if %ERRORLEVEL% equ 2 echo Skipping disallowed media files...
if %ERRORLEVEL% equ 1 (
        set filetypes=mp3 mov mp4 avi mpg mpeg flac m4a flv ogg gif png jpg jpeg
        cd C:\Users
        echo Deleting disallowed media file types...
        :: %%i = file extension
        for %%i in (!filetypes!) do (
        	echo Deleting all .%%i files...
           	:: %%a = individual file
           	for /f "delims=" %%a in ('dir /s /b *.%%i') do (
              		echo Deleting all .%%a files...
              		del "%%a"
        )
              )

echo Managing registry keys...
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
echo Restricting CD ROM drive...
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
echo Disabling auto Admin logon...
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
echo Clearing page file...
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
echo Preventing users from installing printer drivers... 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /fecho Adding auditing to Lsass.exe...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
echo Enabling LSA protection...
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
echo Limiting use of blank passwords...
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
echo Auditing access of Global System Objects...
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
echo Auditing Backup and Restore...
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
echo Restricting Anonymous Enumeration...
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
echo Disabling storage of domain passwords...
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
echo Taking away Anonymous user Everyone permissions...
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
echo Allowing Machine ID for NTLM...
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
echo Enabling do not display last user on logon...
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
echo Enabling Installer Detection...
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
echo Disabling undocking without logon...
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
echo Enabling CTRL+ALT+DEL...
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
echo Disabling machine account password changes...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
echo Requiring strong session key...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
echo Requiring Sign/Seal...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
echo Signing Channel...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
echo Sealing Channel...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
echo Requiring Security Signature - Disabled pursuant to checklist...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /fecho Enabling Security Signature - Disabled pursuant to checklist...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
echo Clearing null session pipes...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /fecho Resticting Anonymous user access to named pipes and shares...
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
echo Disabling IE password caching...
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
echo Warning users if website has a bad certificate...
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
echo Warning users if website redirects...
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
echo Enabling Do Not Track...
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
echo Showing hidden files...
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
echo Disabling sticky keys...
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
echo Showing super hidden files...
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
echo Disabling dump file creation...
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
echo Disabling autoruns...
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f

echo Listing Possible Penetrations...
cd C:\
echo Outputting Process Files (.txt) To C:\ Drive...
wmic process list brief > BriefProcesses.txt
if %errorlevel%==1 echo Brief Processes failed to write
wmic process list full >FullProcesses.txt
if %errorlevel%==1 echo Full Processes failed to write
wmic startup list full > StartupLists.txt
if %errorlevel%==1 echo Startup Processes failed to write
net start > StartedProcesses.txt
if %errorlevel%==1 echo Started processes failed to write
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run  Run.reg
if %errorlevel%==1 echo Run processes failed to write

REM TEAM 15-4209

echo Enable Password Policy: Password Policy Must Meet Complexity... 
echo Disable Password Policy: Store Passwords Using Reversible Encryption... 
start secpol.msc /wait
pause 
echo Enable CTRL ALT DEL At Logon... 
start netplwiz /wait
pause 

echo Listing Networks... 
netstat -aon | find /i "listening"
echo ~END OF LIST~
pause

echo Find Unwanted Media Files - Wild Card Search...
echo Opening File Explorer...
start .  
pause

echo Delete Unnecsary Programs...
start appwiz.cpl /wait
pause

echo Flashing Disk to .flashed Files....
dir /b /s "C:\Program Files\" > programfiles.flashed
dir /b /s "C:\Program Files (x86)\" >> programfiles.flashed
echo Program Files flashed
dir /b /s "C:\Users\" > users.flashed
dir /b /s "C:\Documents and Settings" >> users.flashed
echo User profiles flashed
dir /b /s "C:\" > c.flashed
echo C:\ Flashed
echo Finding Hacktools...
echo Finding Cain...
findstr "Cain" programfiles.flashed
if %errorlevel%==0 (
echo Detected Cain [Press Any Key To Continue]
)
echo Finding Nmap...
findstr "nmap" programfiles.flashed
if %errorlevel%==0 (
echo Detected Nmap [Press Any Key To Continue]
pause 
)
echo Finding Potential Keyloggers...
findstr "keylogger" programfiles.flashed
if %errorlevel%==0 (
echo Detected Potential Keylogger [Press Any Key To Continue]
pause 
)
echo Finding Potential Armitages...
findstr "Armitage" programfiles.flashed
if %errorlevel%==0 (
echo Detected Potential Armitage [Press Any Key To Continue]
pause 
)
echo Finding Potential Megasploit Frameworks...
findstr "Metasploit" programfiles.flashed
if %errorlevel%==0 (
echo Detected Potential Metasploit Framework [Press Any Key To Continue]
pause 
)
echo Finding Potential Shellters...
findstr "Shellter" programfiles.flashed
if %errorlevel%==0 (
echo  Detected Potential Shellter [Press Any Key To Continue]
pause 

echo Running System Integrety Check...
Sfc.exe /scannow
pause

echo Running MRT...
start mrt /f:y
pause

msg * END
