# setup_lab.ps1

# --- Configuration ---
$ToolsDrive = "C:" # Or change to another drive like "D:" if preferred
$ToolsDir = Join-Path $ToolsDrive "tools"
$PayloadsDir = Join-Path $ToolsDrive "payloads"
$TempDir = Join-Path $ToolsDrive "Temp"

# --- Helper Functions ---
function Test-IsAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Script Start ---

# 1. Check for Administrator Privileges
if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator."
    # Optional: Attempt to relaunch as Admin
    # Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    exit 1
}
Write-Host "Running with Administrator privileges."

# 2. Check and Install Chocolatey
$chocoCheck = Get-Command choco -ErrorAction SilentlyContinue
if (-not $chocoCheck) {
    Write-Host "Chocolatey not found. Attempting installation..."
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Error "Chocolatey installation failed. Please install manually and re-run."
        exit 1
    }
    Write-Host "Chocolatey installed successfully."
} else {
    Write-Host "Chocolatey is already installed."
}

# 3. Create Directories
Write-Host "Creating directories..."
New-Item -Path $ToolsDrive -Name ($TempDir.Split('\')[-1]) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $ToolsDrive -Name ($PayloadsDir.Split('\')[-1]) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $ToolsDrive -Name ($ToolsDir.Split('\')[-1]) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

# 4. Set Temporary Environment Variables for this session
Write-Host "Setting TEMP/TMP environment variables for this session..."
$env:TEMP = $TempDir
$env:TMP = $TempDir
# For persistent system-wide change (requires elevation, uncomment if needed):
# [Environment]::SetEnvironmentVariable('TEMP', $TempDir, 'Machine')
# [Environment]::SetEnvironmentVariable('TMP', $TempDir, 'Machine')
# Write-Host "System TEMP/TMP variables set to $TempDir. A restart/re-login might be needed for full effect."

# 5. Configure Windows Defender Exclusions and Settings
Write-Host "Configuring Windows Defender settings..."
try {
    # Get User's Downloads folder path
    $Downloads = Get-ItemPropertyValue 'HKCU:\software\microsoft\windows\currentversion\explorer\shell folders\' -Name '{374DE290-123F-4565-9164-39C4925E467B}' -ErrorAction Stop

    # Add Path Exclusions (Uncomment Downloads if desired)
    Write-Host "  Adding path exclusions..."
    # Add-MpPreference -ExclusionPath $Downloads -ErrorAction Stop
    Add-MpPreference -ExclusionPath $PayloadsDir -ErrorAction Stop
    Add-MpPreference -ExclusionPath $ToolsDir -ErrorAction Stop
    # Add-MpPreference -ExclusionPath "P:\" # Uncomment if needed

    # Disable Cloud/Reporting Features
    Write-Host "  Disabling cloud reporting and sample submission..."
    Set-MpPreference -MAPSReporting Disabled -ErrorAction Stop
    Set-MpPreference -SubmitSamplesConsent NeverSend -ErrorAction Stop

    # Disable Common Interference Points for RE/Offsec
    Write-Host "  Disabling behavior monitoring, script scanning, IOAV, and NIS..."
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Stop
    Set-MpPreference -DisableScriptScanning $true -ErrorAction Stop
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop # Downloads/Attachments scan
    Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction Stop # Network Inspection

    # Optional: Add Process Exclusions if specific tools are consistently flagged
    # Example: Add-MpPreference -ExclusionProcess "mydebugger.exe" -ErrorAction Stop

    # --- Use with extreme caution in controlled environments ONLY ---
    # Write-Host "  WARNING: Disabling Real-time Monitoring!"
    # Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    # --- End Caution ---

    Write-Host "Defender settings applied."
} catch {
    Write-Warning "Failed to configure Windows Defender settings. Error: $($_.Exception.Message)"
    # Optionally, you could choose to exit the script here if Defender config is critical
    # exit 1
}

# 6. Configure Chocolatey
Write-Host "Enabling Chocolatey global confirmation..."
choco feature enable -n allowGlobalConfirmation

# 7. Install Packages
Write-Host "Installing Chocolatey packages..."

# Core Dev & System Tools
Write-Host "  Installing Core Dev & System Tools..."
choco install -y 7zip git chromium brave firefox curl wget putty cmder mingw notepadplusplus sysinternals --params "'/InstallDir:$([System.IO.Path]::Combine($ToolsDir, 'sysinternals'))'" winmerge microsoft-windows-terminal

# Reverse Engineering & Analysis
Write-Host "  Installing Reverse Engineering & Analysis Tools..."
choco install -y cutter reshack winapioverride apimonitor jregexanalyser regshot fakenet pestudio hollowshunter pebear radare2 ghidra hxd x64dbg.portable pesieve die

# Development Environments & Tools
Write-Host "  Installing Development Environments & Tools..."
choco install -y openjdk graphviz python anaconda3 golang visualstudio2022community visualstudio2022buildtools visualstudio2022-workload-manageddesktop visualstudio2022-workload-vctools vcredist140 codeblocks

# Cloud & Infra
Write-Host "  Installing Cloud & Infra Tools..."
choco install -y awscli azure-cli kubernetes-cli terraform pulumi

# IDEs & Editors
Write-Host "  Installing IDEs & Editors..."
choco install -y vscode vscode-cloud-code vscode-ansible

# Networking & Security
Write-Host "  Installing Networking & Security Tools..."
choco install -y nmap wireshark tor-browser netcat mobaexterm processhacker

# Password Cracking
Write-Host "  Installing Password Cracking Tools..."
choco install -y hashcat john-the-ripper

# Forensics
Write-Host "  Installing Forensics Tools..."
choco install -y volatility ftkimager
# Note: For Volatility 3, run manually after Python install: python -m pip install volatility3

# Databases & Productivity
Write-Host "  Installing Databases & Productivity Tools..."
choco install -y heidisql postman calibre termius signal cherrytree joplin obsidian github-desktop foxitreader

# Package Management (NuGet for VS)
Write-Host "  Installing Package Management Tools..."
choco install -y nugetpackagemanager

Write-Host "Chocolatey package installation process finished."

# 8. Final Cleanup (Review this section)
# The original script had an item 'B' here. Verify if this is needed or remove.
# Example: Remove Edge shortcut if it exists
# $publicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
# $edgeShortcut = Join-Path $publicDesktop "Microsoft Edge.lnk"
# if (Test-Path $edgeShortcut) {
#     Write-Host "Removing Microsoft Edge shortcut from Public Desktop..."
#     Remove-Item -Path $edgeShortcut -Force -ErrorAction SilentlyContinue
# }

Write-Host "Lab setup script finished."
