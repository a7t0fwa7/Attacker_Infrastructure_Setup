New-Item -Path C:\ -Name Temp -ItemType Directory -ErrorAction SilentlyContinue
New-Item -Path C:\ -Name payloads -ItemType Directory -ErrorAction SilentlyContinue

$env:TEMP = "C:\Temp"
$env:TMP = "C:\Temp"

# Defender
$Downloads = Get-ItemPropertyValue 'HKCU:\software\microsoft\windows\currentversion\explorer\shell folders\' -Name '{374DE290-123F-4565-9164-39C4925E467B}'
Add-MpPreference -ExclusionPath $Downloads
Add-MpPreference -ExclusionPath "C:\payloads\"
Add-MpPreference -ExclusionPath "C:\tools\"
Add-MpPreference -ExclusionPath "C:\Users\a7t0fwa7"
Add-MpPreference -ExclusionPath "P:\"
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend


# GitHub
Invoke-WebRequest -Uri https://github.com/dnSpy/dnSpy/releases/latest/download/dnSpy-netframework.zip -OutFile "$env:TEMP\dnSpy-netframework.zip"
Expand-Archive -Path "$env:TEMP\dnSpy-netframework.zip" -DestinationPath C:\tools\dnSpy

git clone https://github.com/lengjibo/RedTeamTools.git C:\tools\RedTeamTools
git clone https://github.com/aaaddress1/xlsKami.git C:\tools\ShenHaoMaXlsKami
git clone https://github.com/aaaddress1/Windows-APT-Warfare.git C:\tools\Windows-APT-Warfare
git clone https://github.com/aaaddress1/PR0CESS.git C:\tools\ShenHaoMaPR0CESS
git clone https://github.com/aaaddress1/Skrull.git C:\tools\ShenHaoMaSkrull
git clone https://github.com/timwhitez/Doge-RecycledGate.git C:\tools\Doge-RecycledGate
git clone https://github.com/cube0x0/SyscallPack.git C:\tools\SyscallPack
git clone https://github.com/klezVirus/SysWhispers3.git C:\tools\SysWhispers3 
git clone https://github.com/DarkCoderSc/PowerRunAsAttached.git C:\tools\DarkCoderPowerRunAsAttached
git clone https://github.com/DarkCoderSc/PowerRemoteDesktop.git C:\tools\DarkCoderPowerRemoteDesktop
git clone https://github.com/DarkCoderSc/PowerRunAsSystem.git C:\tools\DarkCoderPowerRunAsSystem
git clone https://github.com/ly4k/SpoolFool.git C:\tools\SpoolFool
git clone https://github.com/wavestone-cdt/Invoke-CleverSpray.git C:\tools\Invoke-CleverSpray
git clone https://github.com/Inf0secRabbit/BadAssMacros.git C:\tools\BadAssMacros
git clone https://github.com/sbasu7241/HellsGate.git C:\tools\HellsGate
git clone https://github.com/Ignitetechnologies/Credential-Dumping.git C:\tools\Credential-Dumping
git clone https://github.com/Idov31/FunctionStomping.git C:\tools\FunctionStomping
git clone https://github.com/safe6Sec/GolangBypassAV.git C:\tools\GolangBypassAV
git clone https://github.com/last-byte/DefenderSwitch.git C:\tools\DefenderSwitch
git clone https://github.com/mitchmoser/LACheck.git C:\tools\LocalAdminPrivEscChecker
git clone https://github.com/mgeeky/o365enum.git C:\tools\MGeekys_o365enum
git clone https://github.com/mgeeky/polonium.git C:\tools\MGeekys_map_out_AVs_EDRs_detection_surface_to_identify_their_gaps.
git clone https://github.com/mgeeky/VisualBasicObfuscator.git C:\tools\MGeekys_VB_Obfuscator_unmaintained
git clone https://github.com/mgeeky/Stracciatella.git C:\tools\MGeekys_Strcciatella 
git clone https://github.com/mgeeky/ProtectMyTooling.git C:\tools\MGeekys_ProtectMyTooling
git clone https://github.com/mgeeky/mgeeky-gists.git C:\tools\MGeekys_Gists
git clone https://github.com/mgeeky/Penetration-Testing-Tools.git C:\tools\MGeekys_Pentest_Tools
git clone https://github.com/MrTuxx/SocialPwned.git C:\tools\SocialPwned
git clone https://github.com/cmars/onionpipe.git C:\tools\tunneling_onionpipe
git clone https://github.com/irsdl/IIS-ShortName-Scanner.git C:\tools\IIS-ShortName-Scanner
git clone https://github.com/v4d1/Dome.git C:\tools\SubDomainEnum_Dome
git clone https://github.com/whydee86/ComPP.git C:\tools\Password_Gen_ComPP
git clone https://github.com/Taonn/EmailAll.git C:\tools\EmailAll
git clone https://github.com/fox-it/aclpwn.py.git C:\tools\aclpwn
git clone https://github.com/fox-it/Invoke-CredentialPhisher.git C:\tools\Invoke-CredentialPhisher
git clone https://github.com/xforcered/InlineExecute-Assembly.git C:\tools\InlineExecute-Assembly
git clone https://github.com/ORCA666/EVA2.git C:\tools\EVA2
git clone https://github.com/N4kedTurtle/HellsGatePoC.git C:\tools\HellsGatePoC
git clone https://github.com/3gstudent/Invoke-BuildAnonymousSMBServer.git C:\tools\Invoke-BuildAnonymousSMBServer
git clone https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement.git C:\tools\Offensive-VBA-and-XLS-Entanglement
git clone https://github.com/fox-it/aclpwn.py.git C:\tools\aclpwn
git clone https://github.com/fox-it/Invoke-CredentialPhisher.git C:\tools\Invoke-CredentialPhisher
git clone https://github.com/xforcered/InlineExecute-Assembly.git C:\tools\InlineExecute-Assembly
git clone https://github.com/ORCA666/EVA2.git C:\tools\EVA2
git clone https://github.com/N4kedTurtle/HellsGatePoC.git C:\tools\HellsGatePoC
git clone https://github.com/3gstudent/Invoke-BuildAnonymousSMBServer.git C:\tools\Invoke-BuildAnonymousSMBServer
git clone https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement.git C:\tools\Offensive-VBA-and-XLS-Entanglement
git clone https://github.com/AnErrupTion/LoGiC.NET.git C:\tools\LoGIC.NET
git clone https://github.com/r00t-3xp10it/meterpeter.git C:\tools\Powershell-Meterpreter
git clone https://github.com/GossiTheDog/HiveNightmare.git C:\tools\HiveNightmare
git clone https://github.com/Inf0secRabbit/BadAssMacros.git C:\tools\BadAssMacros
git clone https://github.com/d35ha/CallObfuscator.git C:\tools\CallObfuscator
git clone https://github.com/bats3c/ADCSPwn.git C:\tools\ADCSPwn
git clone https://github.com/ShutdownRepo/targetedKerberoast.git C:\tools\targetedKerberoast
git clone https://github.com/topotam/PetitPotam.git C:\tools\PetitPotam
git clone https://github.com/Flangvik/DeployPrinterNightmare.git C:\tools\DeployPrintNightMare
git clone https://github.com/two06/Inception.git C:\tools\Inception
git clone https://github.com/cube0x0/MiniDump.git C:\tools\MiniDump
git clone https://github.com/xp4xbox/Python-Backdoor.git C:\tools\Python-Backdoor
git clone https://github.com/xp4xbox/PyEvade.git C:\tools\PyEvade
git clone https://github.com/sevagas/macro_pack.git C:\tools\Macro_Pack
git clone https://github.com/ropnop/kerbrute.git C:\tools\kerbrute
git clone https://github.com/Flangvik/SharpCollection.git C:\tools\SharpCollection
git clone https://github.com/sevagas/macro_pack.git C:\tools\Macro_Pack
git clone https://github.com/ZeroPointSecurity/PhishingTemplates.git C:\tools\PhishingTemplates
git clone https://github.com/dafthack/MailSniper.git C:\tools\MailSniper
git clone https://github.com/GhostPack/Seatbelt.git C:\tools\Seatbelt
git clone --branch dev https://github.com/PowerShellMafia/PowerSploit.git C:\tools\PowerSploit
git clone https://github.com/tevora-threat/SharpView.git C:\tools\SharpView
git clone https://github.com/rasta-mouse/Sherlock.git C:\tools\Sherlock
git clone https://github.com/rasta-mouse/Watson.git C:\tools\Watson
git clone https://github.com/hfiref0x/UACME.git C:\tools\UACME
git clone https://github.com/BloodHoundAD/SharpHound3.git C:\tools\SharpHound3
git clone https://github.com/TheWover/donut.git C:\tools\donut
git clone https://github.com/rasta-mouse/MiscTools.git C:\tools\MiscTools
git clone https://github.com/djhohnstein/SharpChrome.git C:\tools\SharpChrome
git clone https://github.com/FSecureLABS/SharpGPOAbuse.git C:\tools\SharpGPOAbuse
git clone https://github.com/NetSPI/PowerUpSQL.git C:\tools\PowerUpSQL
git clone https://github.com/decoder-it/juicy-potato.git C:\tools\juicy-potato
git clone https://github.com/HarmJ0y/DAMP.git C:\tools\DAMP
git clone https://github.com/gentilkiwi/mimikatz.git C:\tools\mimikatz
git clone https://github.com/p3nt4/PowerShdll.git C:\tools\PowerShdll
git clone https://github.com/FortyNorthSecurity/Egress-Assess.git C:\tools\Egress-Assess
#git clone --recursive https://github.com/0xd4d/dnSpy.git C:\tools\dnSpy
git clone https://github.com/leechristensen/SpoolSample.git C:\tools\SpoolSample
git clone https://github.com/itm4n/PrivescCheck.git C:\tools\PrivescCheck
git clone https://github.com/aloksaurabh/OffenPowerSh.git C:\tools\OffenPowerSh
git clone https://github.com/artofwar2306/Invoke-Recon.git C:\tools\Invoke-Recon
git clone https://github.com/danielbohannon/Invoke-Obfuscation.git C:\tools\Invoke-Obfuscation
git clone https://github.com/CBHue/PyFuscation.git C:\tools\PyFuscation
git clone https://github.com/tokyoneon/Chimera.git C:\tools\Chimera
git clone https://github.com/S3cur3Th1sSh1t/WinPwn.git C:\tools\WinPWn
git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git C:\tools\PowerSharpPack
git clone https://github.com/S3cur3Th1sSh1t/MailSniper.git C:\tools\MailSniper
git clone https://github.com/S3cur3Th1sSh1t/Creds.git C:\tools\Creds
git clone https://github.com/S3cur3Th1sSh1t/Invoke-PrintDemon.git C:\tools\Invoke-PrintDemon
git clone https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader.git C:\tools\Invoke-SharpLoader
git clone https://github.com/S3cur3Th1sSh1t/Invoke-Sharpcradle.git C:\tools\Invoke-SharpCradle
git clone https://github.com/S3cur3Th1sSh1t/Get-System-Techniques.git C:\tools\Get-System-Techniques
git clone https://github.com/S3cur3Th1sSh1t/SharpLocker.git C:\tools\SharpLocker
git clone https://github.com/S3cur3Th1sSh1t/xencrypt.git C:\tools\xencrypt
git clone https://github.com/Flangvik/SimpleSourceProtector.git C:\tools\SimpleSourceProtector
git clone https://github.com/SnaffCon/Snaffler.git C:\tools\Snaffler
git clone https://github.com/Soledge/BlockEtw.git C:\tools\BlockEtw
git clone https://github.com/jxy-s/herpaderping.git C:\tools\herpaderping
git clone https://github.com/bytecod3r/Cobaltstrike-Aggressor-Scripts-Collection.git C:\tools\CobaltStrike-Agressor-Scripts-Collection
git clone https://github.com/bats3c/darkarmour.git C:\tools\darkarmour
git clone https://github.com/RythmStick/AMSITrigger.git C:\tools\AMSITrigger
git clone https://github.com/rasta-mouse/ThreatCheck.git C:tools\ThreatCheck
git clone https://github.com/mkaring/ConfuserEx.git C:\tools\ConfuserEx
git clone https://github.com/whitehat-zero/PowEnum.git C:\tools\PowEnum
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git C:\tools\WinAndLinPEAS
git clone https://github.com/GhostPack/Seatbelt.git C:\tools\Seatbelt
git clone https://github.com/GhostPack/Rubeus.git C:\tools\Rubeus
git clone https://github.com/GhostPack/SharpDPAPI.git C:\tools\SharpDPAPI
git clone https://github.com/GhostPack/SharpWMI.git C:\tools\SharpWMI
git clone https://github.com/GhostPack/SharpDump.git C:\tools\SharpDump
git clone https://github.com/GhostPack/SafetyKatz.git C:tools\SafetyKatz
git clone https://github.com/7Ragnarok7/Windows-Exploit-Suggester.git C:\tools\Windows-Exploit-Suggestor
git clone https://github.com/bitsadmin/wesng.git C:\tools\Windows-Exploit-Suggester-New-Generation
git clone https://github.com/rasta-mouse/ThreatCheck.git C:\tools\ThreatCheck

# IE first run
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name DisableFirstRunCustomize -Value 1

# Download DLL Export Viewer
Invoke-WebRequest -Uri 'https://www.nirsoft.net/utils/dllexp-x64.zip' -OutFile "$env:TEMP\dllexp.zip"
Expand-Archive -Path "$env:TEMP\dllexp.zip" -DestinationPath C:\tools\dllExportViewer

# BloodHound
Invoke-WebRequest -Uri 'https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-win32-x64.zip' -OutFile "$env:TEMP\BloodHound.zip"
Expand-Archive -Path "$env:TEMP\BloodHound.zip" -DestinationPath C:\tools\
Rename-Item -Path C:\tools\BloodHound-win32-x64\ -NewName BloodHound

# Install BloodHound-CustomQueries
#Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ZephrFish/Bloodhound-CustomQueries/73be20557538b870d886492ba137e20bcdd8c183/customqueries.json' -OutFile "C:\Users\$user\AppData\Roaming\bloodhound\customqueries.json"

# Install Neo4j
Invoke-WebRequest -Uri 'https://neo4j.com/artifact.php?name=neo4j-community-4.0.0-windows.zip' -OutFile "$env:TEMP\neo4j.zip"
Expand-Archive -Path "$env:TEMP\neo4j.zip" -DestinationPath C:\tools\
Rename-Item -Path C:\tools\neo4j-community-4.0.0\ -NewName Neo4j

# Install Adalanche
git clone https://github.com/lkarlslund/adalanche C:\tools\adalanche
cd C:\tools\adalanche\adalanche
build.cmd

## Visual Studio
#Invoke-WebRequest -Uri 'https://marketplace.visualstudio.com/_apis/public/gallery/publishers/VisualStudioClient/vsextensions/MicrosoftVisualStudio2017InstallerProjects/0.9.9/vspackage' -OutFile "$Downloads\InstallerProjects.vsix"
#Invoke-WebRequest -Uri 'https://download.microsoft.com/download/E/E/D/EEDF18A8-4AED-4CE0-BEBE-70A83094FC5A/BuildTools_Full.exe' -OutFile "$Downloads\BuildTools.exe"
#Enable-WindowsOptionalFeature -FeatureName NetFx3 -Online

## Visual Studio
#Invoke-WebRequest -Uri 'https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&channel=Release&version=VS2022&source=VSLandingPage&cid=2030&passive=false' -OutFile "$Downloads\VStudio.exe"

#Invoke-WebRequest -Uri 'https://visualstudioclient.gallerycdn.vsassets.io/extensions/visualstudioclient/microsoftvisualstudio2017installerprojects/1.0.0/1620063166533/InstallerProjects.vsix' -OutFile "$Downloads\InstallerProjects.vsix"
#Invoke-WebRequest -Uri 'https://download.microsoft.com/download/E/E/D/EEDF18A8-4AED-4CE0-BEBE-70A83094FC5A/BuildTools_Full.exe' -OutFile "$Downloads\BuildTools.exe"
Enable-WindowsOptionalFeature -FeatureName NetFx3 -Online

# GPRegistryPolicy
Install-Module GPRegistryPolicy -Force

# Networking
## VMware
netsh interface ip set address "Ethernet1" static 192.168.152.101 255.255.255.0 192.168.152.100

## VBox
netsh interface ip set address "Ethernet 2" static 192.168.152.101 255.255.255.0 192.168.152.100

route add -p 10.8.0.0 mask 255.255.255.0 192.168.152.100
route add -p 10.9.0.0 mask 255.255.255.0 192.168.152.100
route add -p 10.10.110.0 mask 255.255.255.0 192.168.152.100
Add-Content C:\Windows\System32\drivers\etc\hosts "192.168.152.100 kali"

# UI
Import-Module "$env:ChocolateyInstall\helpers\chocolateyInstaller.psm1" -Force
Set-WindowsExplorerOptions -EnableShowFileExtensions -EnableShowFullPathInTitleBar -EnableExpandToOpenFolder -EnableShowRibbon
Install-ChocolateyShortcut -shortcutFilePath "C:\Users\Public\Desktop\tools.lnk" -targetPath C:\tools\
Install-ChocolateyShortcut -shortcutFilePath "C:\Users\Public\Desktop\Neo4j.lnk" -targetPath "C:\tools\Neo4j\bin\neo4j.bat" -arguments "console" -runAsAdmin

New-Item -Path C:\ -Name BGInfo -ItemType Directory -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri 'https://github.com/a7t0fwa7/Attack_Infra_Setup/raw/master/wallpaper.jpg' -OutFile "C:\BGInfo\wallpaper.jpg"
Invoke-WebRequest -Uri 'https://github.com/a7t0fwa7/Attack_Infra_Setup/raw/master/bginfo.bgi' -OutFile "C:\BGInfo\bginfo.bgi"
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ -Name BGInfo -Value "C:\tools\sysinternals\Bginfo64.exe /accepteula /iC:\BGInfo\bginfo.bgi /timer:0"

# Misc
#$DesktopPath = [Environment]::GetFolderPath("Desktop")
#Remove-Item -Path "C:\Users\Public\Desktop\Boxstarter Shell.lnk"
#Remove-Item -Path C:\Temp\ -Recurse -Force
