<#
.SYNOPSIS
    Modern Attack VM Setup Script for Windows
.DESCRIPTION
    Sets up a Windows-based attack/pentesting VM with a comprehensive set of tools
    Combines the best elements of windows-attackvm.ps1 and choco_windows.ps1
.NOTES
    Version:        1.0
    Creation Date:  2023-10-19
#>

# --- Configuration ---
$Config = @{
    ToolsDrive = "C:"                               # Drive for tools installation
    ToolsDir = "C:\tools"                           # Directory for tools
    PayloadsDir = "C:\payloads"                     # Directory for payloads
    TempDir = "C:\Temp"                             # Temporary directory
    SetupNetworking = $true                         # Configure networking
    DisableDefender = $true                         # Configure Windows Defender
    InstallChocolateyTools = $true                  # Install tools via Chocolatey
    InstallGitTools = $true                         # Install tools via Git
    ConfigureUI = $true                             # Configure UI settings (BGInfo, etc.)
    VMType = "VMware"                               # VMware or VBox
    NetworkConfig = @{
        IPAddress = "192.168.152.101"
        SubnetMask = "255.255.255.0"
        Gateway = "192.168.152.100"
        Routes = @(
            @{ Network = "10.8.0.0"; Mask = "255.255.255.0"; Gateway = "192.168.152.100" },
            @{ Network = "10.9.0.0"; Mask = "255.255.255.0"; Gateway = "192.168.152.100" },
            @{ Network = "10.10.110.0"; Mask = "255.255.255.0"; Gateway = "192.168.152.100" }
        )
        HostEntries = @(
            @{ IP = "192.168.152.100"; Hostname = "kali" }
        )
    }
    LogFile = "C:\setup_log.txt"                    # Log file location
}

# --- Helper Functions ---
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color based on level
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
    
    # Write to log file
    Add-Content -Path $Config.LogFile -Value $logMessage
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-Environment {
    # Create necessary directories
    Write-Log "Creating directories..."
    
    foreach ($dir in @($Config.ToolsDir, $Config.PayloadsDir, $Config.TempDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            Write-Log "Created directory: $dir" -Level "SUCCESS"
        } else {
            Write-Log "Directory already exists: $dir"
        }
    }
    
    # Set temporary environment variables
    $env:TEMP = $Config.TempDir
    $env:TMP = $Config.TempDir
    Write-Log "Set temporary environment variables to: $($Config.TempDir)"
}

function Install-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            
            # Verify installation
            if (Get-Command choco -ErrorAction SilentlyContinue) {
                Write-Log "Chocolatey installed successfully" -Level "SUCCESS"
                
                # Configure Chocolatey
                choco feature enable -n allowGlobalConfirmation
                Write-Log "Enabled Chocolatey global confirmation"
            } else {
                Write-Log "Chocolatey installation failed" -Level "ERROR"
                return $false
            }
        } catch {
            Write-Log "Error installing Chocolatey: $_" -Level "ERROR"
            return $false
        }
    } else {
        Write-Log "Chocolatey is already installed"
    }
    return $true
}

function Configure-WindowsDefender {
    if (-not $Config.DisableDefender) {
        Write-Log "Skipping Windows Defender configuration as per configuration"
        return
    }
    
    Write-Log "Configuring Windows Defender..."
    try {
        # Get Downloads folder path
        $Downloads = Get-ItemPropertyValue 'HKCU:\software\microsoft\windows\currentversion\explorer\shell folders\' -Name '{374DE290-123F-4565-9164-39C4925E467B}'
        
        # Add exclusions
        Add-MpPreference -ExclusionPath $Downloads
        Add-MpPreference -ExclusionPath $Config.PayloadsDir
        Add-MpPreference -ExclusionPath $Config.ToolsDir
        Add-MpPreference -ExclusionPath $env:USERPROFILE
        
        # Disable cloud features
        Set-MpPreference -MAPSReporting Disabled
        Set-MpPreference -SubmitSamplesConsent NeverSend
        
        # Disable monitoring features for better performance with security tools
        Set-MpPreference -DisableBehaviorMonitoring $true
        Set-MpPreference -DisableScriptScanning $true
        Set-MpPreference -DisableIOAVProtection $true
        Set-MpPreference -DisableIntrusionPreventionSystem $true
        
        Write-Log "Windows Defender configured successfully" -Level "SUCCESS"
    } catch {
        Write-Log "Error configuring Windows Defender: $_" -Level "ERROR"
    }
}

function Configure-IEFirstRun {
    Write-Log "Configuring Internet Explorer first run..."
    try {
        if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name DisableFirstRunCustomize -Value 1 -PropertyType DWORD -Force | Out-Null
        Write-Log "Internet Explorer first run configured" -Level "SUCCESS"
    } catch {
        Write-Log "Error configuring Internet Explorer: $_" -Level "ERROR"
    }
}

function Install-ChocolateyTools {
    if (-not $Config.InstallChocolateyTools) {
        Write-Log "Skipping Chocolatey tools installation as per configuration"
        return
    }
    
    Write-Log "Installing tools via Chocolatey..."
    
    $packageGroups = @{
        "Core System Tools" = @(
            "7zip", "sysinternals", "notepadplusplus", "microsoft-windows-terminal", 
            "curl", "wget", "grep", "nmap", "wireshark", "putty", "cmder", "hxd"
        )
        "Development Tools" = @(
            "git", "python", "golang", "visualstudio2022community", "visualstudio2022buildtools", 
            "visualstudio2022-workload-vctools", "vscode", "dotnet-sdk", "cmake"
        )
        "Security Tools" = @(
            "ghidra", "cutter", "wireshark", "nmap", "hashcat", "tor-browser",
            "netcat", "putty", "burp-suite-free-edition", "openssl"
        )
        "Reverse Engineering" = @(
            "pestudio", "ida-free", "x64dbg.portable", "radare2", "dnspy", "ilspy",
            "cutter", "ghidra", "dnspy"
        )
        "Browsers" = @(
            "googlechrome", "firefox", "brave"
        )
        "Editors & Documentation" = @(
            "notepadplusplus", "vscode", "typora", "cherrytree", "obsidian"
        )
        "Utilities" = @(
            "procexp", "procmon", "autoruns", "networkmonitor", "tcpview", "regshot"
        )
    }
    
    foreach ($group in $packageGroups.Keys) {
        Write-Log "Installing $group..."
        $packages = $packageGroups[$group]
        
        foreach ($package in $packages) {
            try {
                Write-Log "  Installing $package..."
                choco install $package -y
                Write-Log "  Installed $package" -Level "SUCCESS"
            } catch {
                Write-Log "  Error installing $package: $_" -Level "ERROR"
            }
        }
    }
    
    Write-Log "Chocolatey tools installation completed" -Level "SUCCESS"
}

function Install-GitTools {
    if (-not $Config.InstallGitTools) {
        Write-Log "Skipping Git tools installation as per configuration"
        return
    }
    
    # Make sure Git is installed
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Log "Git not found. Installing via Chocolatey..."
        choco install git -y
    }
    
    Write-Log "Installing tools via Git..."
    
    # Define repository categories
    $repoCategories = @{
        "Credential Access" = @(
            "https://github.com/GhostPack/Rubeus.git",
            "https://github.com/GhostPack/SharpDPAPI.git",
            "https://github.com/gentilkiwi/mimikatz.git",
            "https://github.com/dafthack/MailSniper.git",
            "https://github.com/S3cur3Th1sSh1t/Creds.git"
        )
        "Lateral Movement" = @(
            "https://github.com/ShutdownRepo/targetedKerberoast.git",
            "https://github.com/fox-it/Invoke-CredentialPhisher.git",
            "https://github.com/leechristensen/SpoolSample.git",
            "https://github.com/topotam/PetitPotam.git"
        )
        "Privilege Escalation" = @(
            "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git",
            "https://github.com/itm4n/PrivescCheck.git",
            "https://github.com/GhostPack/Seatbelt.git",
            "https://github.com/GossiTheDog/HiveNightmare.git",
            "https://github.com/bats3c/ADCSPwn.git"
        )
        "Code Execution & Evasion" = @(
            "https://github.com/ORCA666/EVA2.git",
            "https://github.com/d35ha/CallObfuscator.git",
            "https://github.com/danielbohannon/Invoke-Obfuscation.git",
            "https://github.com/mgeeky/VisualBasicObfuscator.git",
            "https://github.com/mgeeky/ProtectMyTooling.git",
            "https://github.com/tokyoneon/Chimera.git",
            "https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git"
        )
        "Reconnaissance" = @(
            "https://github.com/BloodHoundAD/SharpHound3.git",
            "https://github.com/SnaffCon/Snaffler.git",
            "https://github.com/GhostPack/SharpWMI.git",
            "https://github.com/PowerShellMafia/PowerSploit.git",
            "https://github.com/tevora-threat/SharpView.git"
        )
        "Post Exploitation" = @(
            "https://github.com/TheWover/donut.git",
            "https://github.com/FSecureLABS/SharpGPOAbuse.git",
            "https://github.com/NetSPI/PowerUpSQL.git",
            "https://github.com/djhohnstein/SharpChrome.git"
        )
        "Defense Evasion" = @(
            "https://github.com/bats3c/darkarmour.git",
            "https://github.com/Soledge/BlockEtw.git",
            "https://github.com/jxy-s/herpaderping.git",
            "https://github.com/RythmStick/AMSITrigger.git"
        )
        "Vulnerability Assessment" = @(
            "https://github.com/bitsadmin/wesng.git",
            "https://github.com/rasta-mouse/Watson.git",
            "https://github.com/7Ragnarok7/Windows-Exploit-Suggester.git"
        )
        "Other Useful Tools" = @(
            "https://github.com/S3cur3Th1sSh1t/WinPwn.git",
            "https://github.com/ZeroPointSecurity/PhishingTemplates.git"
        )
    }
    
    # Clone repositories
    foreach ($category in $repoCategories.Keys) {
        Write-Log "Cloning $category tools..."
        $repos = $repoCategories[$category]
        
        foreach ($repo in $repos) {
            try {
                $repoName = ($repo -split "/")[-1].Replace(".git", "")
                $destination = Join-Path $Config.ToolsDir $repoName
                
                if (-not (Test-Path $destination)) {
                    Write-Log "  Cloning $repoName..."
                    git clone $repo $destination
                    Write-Log "  Cloned $repoName" -Level "SUCCESS"
                } else {
                    Write-Log "  Repository already exists: $repoName"
                }
            } catch {
                Write-Log "  Error cloning $repo: $_" -Level "ERROR"
            }
        }
    }
    
    Write-Log "Git tools installation completed" -Level "SUCCESS"
}

function Install-SpecialTools {
    Write-Log "Installing special tools..."
    
    # Install BloodHound
    try {
        Write-Log "  Installing BloodHound..."
        $bloodhoundZip = Join-Path $Config.TempDir "BloodHound.zip"
        Invoke-WebRequest -Uri 'https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-win32-x64.zip' -OutFile $bloodhoundZip
        Expand-Archive -Path $bloodhoundZip -DestinationPath $Config.ToolsDir -Force
        Rename-Item -Path (Join-Path $Config.ToolsDir "BloodHound-win32-x64") -NewName "BloodHound" -Force -ErrorAction SilentlyContinue
        Write-Log "  BloodHound installed" -Level "SUCCESS"
    } catch {
        Write-Log "  Error installing BloodHound: $_" -Level "ERROR"
    }
    
    # Install Neo4j
    try {
        Write-Log "  Installing Neo4j..."
        $neo4jZip = Join-Path $Config.TempDir "neo4j.zip"
        # Using a more recent version of Neo4j
        Invoke-WebRequest -Uri 'https://neo4j.com/artifact.php?name=neo4j-community-5.11.0-windows.zip' -OutFile $neo4jZip
        Expand-Archive -Path $neo4jZip -DestinationPath $Config.ToolsDir -Force
        
        # Find the exact folder name (version might change)
        $neo4jFolder = Get-ChildItem -Path $Config.ToolsDir -Directory -Filter "neo4j-community*" | Select-Object -First 1
        if ($neo4jFolder) {
            Rename-Item -Path $neo4jFolder.FullName -NewName "Neo4j" -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "  Neo4j installed" -Level "SUCCESS"
    } catch {
        Write-Log "  Error installing Neo4j: $_" -Level "ERROR"
    }
    
    # Install DLL Export Viewer
    try {
        Write-Log "  Installing DLL Export Viewer..."
        $dllExpZip = Join-Path $Config.TempDir "dllexp.zip"
        Invoke-WebRequest -Uri 'https://www.nirsoft.net/utils/dllexp-x64.zip' -OutFile $dllExpZip
        Expand-Archive -Path $dllExpZip -DestinationPath (Join-Path $Config.ToolsDir "dllExportViewer") -Force
        Write-Log "  DLL Export Viewer installed" -Level "SUCCESS"
    } catch {
        Write-Log "  Error installing DLL Export Viewer: $_" -Level "ERROR"
    }
    
    # Enable .NET Framework 3.5 (needed for various tools)
    try {
        Write-Log "  Enabling .NET Framework 3.5..."
        Enable-WindowsOptionalFeature -FeatureName NetFx3 -Online -NoRestart
        Write-Log "  .NET Framework 3.5 enabled" -Level "SUCCESS"
    } catch {
        Write-Log "  Error enabling .NET Framework 3.5: $_" -Level "ERROR"
    }
    
    Write-Log "Special tools installation completed" -Level "SUCCESS"
}

function Configure-Networking {
    if (-not $Config.SetupNetworking) {
        Write-Log "Skipping network configuration as per configuration"
        return
    }
    
    Write-Log "Configuring networking..."
    
    # Configure network adapter
    try {
        if ($Config.VMType -eq "VMware") {
            $interfaceName = "Ethernet1" # Common VMware interface name
            Write-Log "  Configuring VMware network adapter..."
        } else {
            $interfaceName = "Ethernet 2" # Common VirtualBox interface name
            Write-Log "  Configuring VirtualBox network adapter..."
        }
        
        # Set static IP
        $networkConfig = $Config.NetworkConfig
        netsh interface ip set address $interfaceName static $networkConfig.IPAddress $networkConfig.SubnetMask $networkConfig.Gateway
        Write-Log "  Set static IP to $($networkConfig.IPAddress)" -Level "SUCCESS"
        
        # Add static routes
        foreach ($route in $networkConfig.Routes) {
            route add -p $route.Network mask $route.Mask $route.Gateway
            Write-Log "  Added route for $($route.Network)" -Level "SUCCESS"
        }
        
        # Add host entries
        foreach ($hostEntry in $networkConfig.HostEntries) {
            $hostsFile = "$env:windir\System32\drivers\etc\hosts"
            $hostLine = "$($hostEntry.IP) $($hostEntry.Hostname)"
            
            if (-not (Select-String -Path $hostsFile -Pattern $hostLine -SimpleMatch -Quiet)) {
                Add-Content -Path $hostsFile -Value $hostLine
                Write-Log "  Added host entry: $hostLine" -Level "SUCCESS"
            }
        }
    } catch {
        Write-Log "Error configuring networking: $_" -Level "ERROR"
    }
    
    Write-Log "Network configuration completed" -Level "SUCCESS"
}

function Configure-UI {
    if (-not $Config.ConfigureUI) {
        Write-Log "Skipping UI configuration as per configuration"
        return
    }
    
    Write-Log "Configuring UI settings..."
    
    # Configure Windows Explorer options
    try {
        Write-Log "  Configuring Windows Explorer options..."
        
        # Import module from Chocolatey if available
        if (Test-Path "$env:ChocolateyInstall\helpers\chocolateyInstaller.psm1") {
            Import-Module "$env:ChocolateyInstall\helpers\chocolateyInstaller.psm1" -Force
            
            # Set explorer options
            Set-WindowsExplorerOptions -EnableShowFileExtensions -EnableShowFullPathInTitleBar -EnableExpandToOpenFolder -EnableShowRibbon
            Write-Log "  Windows Explorer options set" -Level "SUCCESS"
            
            # Create shortcuts
            Install-ChocolateyShortcut -shortcutFilePath "C:\Users\Public\Desktop\tools.lnk" -targetPath $Config.ToolsDir
            Install-ChocolateyShortcut -shortcutFilePath "C:\Users\Public\Desktop\Neo4j.lnk" -targetPath (Join-Path $Config.ToolsDir "Neo4j\bin\neo4j.bat") -arguments "console" -runAsAdmin
            Write-Log "  Desktop shortcuts created" -Level "SUCCESS"
        } else {
            Write-Log "  Chocolatey installer module not found" -Level "WARNING"
        }
    } catch {
        Write-Log "  Error configuring Windows Explorer: $_" -Level "ERROR"
    }
    
    # Set up BGInfo
    try {
        Write-Log "  Setting up BGInfo..."
        $bgInfoDir = "C:\BGInfo"
        
        if (-not (Test-Path $bgInfoDir)) {
            New-Item -Path $bgInfoDir -ItemType Directory -Force | Out-Null
        }
        
        # Download BGInfo files
        Invoke-WebRequest -Uri 'https://github.com/a7t0fwa7/Attack_Infra_Setup/raw/master/wallpaper.jpg' -OutFile "$bgInfoDir\wallpaper.jpg"
        Invoke-WebRequest -Uri 'https://github.com/a7t0fwa7/Attack_Infra_Setup/raw/master/bginfo.bgi' -OutFile "$bgInfoDir\bginfo.bgi"
        
        # Add BGInfo to startup
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" -Name BGInfo -Value "$Config.ToolsDir\sysinternals\Bginfo64.exe /accepteula /i$bgInfoDir\bginfo.bgi /timer:0" -PropertyType String -Force | Out-Null
        
        Write-Log "  BGInfo configured" -Level "SUCCESS"
    } catch {
        Write-Log "  Error setting up BGInfo: $_" -Level "ERROR"
    }
    
    Write-Log "UI configuration completed" -Level "SUCCESS"
}

function Main {
    # Start timestamp for overall execution time
    $startTime = Get-Date
    
    # Create log file directory if it doesn't exist
    $logDir = Split-Path -Parent $Config.LogFile
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    Write-Log "======= Starting Attack VM Setup =======" -Level "SUCCESS"
    
    # Check for admin privileges
    if (-not (Test-Administrator)) {
        Write-Log "This script requires administrator privileges. Please run as administrator." -Level "ERROR"
        exit 1
    }
    
    # Initialize environment (create directories, set environment variables)
    Initialize-Environment
    
    # Install and configure Chocolatey
    if (-not (Install-Chocolatey)) {
        Write-Log "Failed to install Chocolatey. Some functions may not work properly." -Level "WARNING"
    }
    
    # Configure Windows Defender
    Configure-WindowsDefender
    
    # Configure IE First Run
    Configure-IEFirstRun
    
    # Install tools via Chocolatey
    Install-ChocolateyTools
    
    # Install tools via Git
    Install-GitTools
    
    # Install special tools
    Install-SpecialTools
    
    # Configure networking
    Configure-Networking
    
    # Configure UI
    Configure-UI
    
    # Calculate and display execution time
    $endTime = Get-Date
    $executionTime = $endTime - $startTime
    
    Write-Log "======= Attack VM Setup Completed =======" -Level "SUCCESS"
    Write-Log "Total execution time: $($executionTime.TotalMinutes.ToString("0.00")) minutes" -Level "SUCCESS"
}

# Execute main function
Main
