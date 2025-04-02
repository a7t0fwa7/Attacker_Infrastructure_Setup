# Attack Infrastructure Setup

This repository contains setup scripts for configuring Kali Linux and Windows environments for penetration testing and development purposes.

# Kali Linux Setup

The `Kali_Setup/C2andToolsSetupKali.sh` script automates the configuration of a Kali Linux machine.

## Script Overview

The script performs the following actions:
1.  **System Update:** Updates package lists and installs essential build tools and utilities (`curl`, `wget`, `git`, etc.).
2.  **Network Configuration (Optional):** Includes commented-out code to configure a static IP address on `eth1`, disable NetworkManager, enable IP forwarding, and set up basic `iptables` NAT rules (useful for C2 redirection). *This section is disabled by default.*
3.  **SSH Service:** Enables and starts the `sshd` service.
4.  **Development Tools:** Installs Go, Rust (via `rustup`), .NET SDK, Mingw-w64, Vlang, and Python3 (`pip`, `venv`, `dev`). Configures `GOPATH`.
5.  **Docker:** Installs Docker and adds the current user to the `docker` group.
6.  **Core Security Tools:** Installs VS Code, Evil-WinRM, CrackMapExec, BloodHound (with custom queries), and `smap`. *Note: A step to download an Obfuscated Mimikatz script is included but commented out for safety.*
7.  **Tool Directory Structure:** Creates categorized directories under `/opt` (e.g., `Intel-Tools`, `Command-and-Control`, `AV-Evasion-Tools`).
8.  **Git Repositories:** Clones a large number of security tools from GitHub into the relevant `/opt` directories. Handles updates if directories already exist. Includes special handling for non-Git downloads (e.g., Sub3Suite, Namemash).
9.  **C2 Frameworks:** Clones repositories for Sliver, Mythic, Havoc, and Shad0w C2 frameworks into `/opt/Command-and-Control/`. Installs Havoc dependencies. Includes a custom setup for Covenant that applies extensive modifications ("Venom" theme) and attempts to build it.
10. **MOTD:** Sets a custom message of the day.

## Installation Steps

1.  **Change Kali Password:** Open a terminal and change the default user's password:
    ```bash
    passwd
    ```
2.  **Set Root Password (Optional but recommended):** Gain root privileges and set a password for the root account:
    ```bash
    sudo -i
    passwd
    ```
    Log out and log back in as your regular user.
3.  **Run the Setup Script:** Download and execute the script using `curl` and `bash`. It will prompt for your `sudo` password as needed.
    ```bash
    curl -sS https://raw.githubusercontent.com/a7t0fwa7/Attack_Infra_Setup/main/Kali_Setup/C2andToolsSetupKali.sh | sudo bash -
    ```
4.  **Allow Root SSH Login (Optional - Security Risk):** If you need to SSH directly as root:
    *   Edit the SSH config: `sudo nano /etc/ssh/sshd_config`
    *   Find the `#PermitRootLogin prohibit-password` line (or similar) and change it to `PermitRootLogin yes`.
    *   Save the file (Ctrl+O, Enter) and exit (Ctrl+X).
    *   Restart the SSH service: `sudo systemctl restart sshd`
    *   **Warning:** Allowing direct root login via SSH is generally discouraged for security reasons. Use key-based authentication if possible.

5.  **Post-Installation:**
    *   **Log out and log back in** or **restart your shell** (`source ~/.profile`, `source ~/.zshrc`, or reboot) for `PATH` changes (Go, Rust) and Docker group membership to take effect.
    *   **C2 Framework Setup:** Most C2 frameworks (Mythic, Havoc, Sliver, Shad0w) require additional manual configuration, building, or setup steps. Refer to their respective documentation.
    *   **Network Config:** If you need the static IP/NAT configuration, uncomment the `setup_network` line near the bottom of the `C2andToolsSetupKali.sh` script before running it, or manually configure your network as needed.

## Alternative Kali Install (PimpmyKali)

Alternatively, you can use PimpmyKali:
1.  Download: `git clone https://github.com/Dewalt-arch/pimpmykali.git`
2.  Follow instructions in the PimpmyKali repository.
3.  Launch: `cd pimpmykali && sudo bash pimpmykali.sh`

---

# Windows Setup

There are two options for setting up a Windows environment for pentesting and red team operations:

1. **Standard Setup** using the `Windows_Setup/choco_windows.ps1` script
2. **Modern Attack VM Setup** using the new `Windows_Setup/modern-attackvm.ps1` script (recommended)

## Standard Setup Script Overview

The `Windows_Setup/choco_windows.ps1` script performs the following actions:
1.  **Admin Check:** Verifies it's running with Administrator privileges.
2.  **Chocolatey Install:** Installs Chocolatey if it's not already present.
3.  **Directory Creation:** Creates `C:\tools`, `C:\payloads`, and `C:\Temp`.
4.  **Environment Variables:** Sets the current session's `TEMP` and `TMP` variables to `C:\Temp`.
5.  **Windows Defender Configuration:**
    *   Adds path exclusions for `C:\tools`, `C:\payloads`.
    *   Disables MAPS reporting, sample submission, behavior monitoring, script scanning, IOAV protection (scan on download), and the Network Inspection System (NIS).
    *   *Note: Disabling Real-time Monitoring is commented out for safety.*
6.  **Chocolatey Configuration:** Enables global confirmations (`-y` equivalent).
7.  **Package Installation:** Installs a wide variety of tools using `choco install -y`, including:
    *   **Core Dev & System:** 7zip, Git, browsers (Chromium, Brave, Firefox), curl, wget, Putty, Cmder, Mingw, Notepad++, Sysinternals, WinMerge, Windows Terminal.
    *   **Reverse Engineering & Analysis:** Cutter, Resource Hacker, WinAPIOverride, API Monitor, RegShot, FakeNet-NG, PEStudio, HollowsHunter, PE-bear, Radare2, Ghidra, HxD, x64Dbg, PESieve, Detect It Easy (DIE).
    *   **Development:** OpenJDK, Graphviz, Python, Anaconda3, Go, Visual Studio 2022 (Community, Build Tools, Managed Desktop & C++ workloads), vcredist, Code::Blocks.
    *   **Cloud & Infra:** AWS CLI, Azure CLI, Kubectl, Terraform, Pulumi.
    *   **IDEs & Editors:** VS Code (with Cloud Code, Ansible extensions).
    *   **Networking & Security:** Nmap, Wireshark, Tor Browser, Netcat (ncat), MobaXterm.
    *   **Password Cracking:** Hashcat, John the Ripper.
    *   **Forensics:** Volatility, FTK Imager.
    *   **Databases & Productivity:** HeidiSQL, Postman, Calibre, Termius, Signal, CherryTree, Joplin, GitHub Desktop, Foxit Reader.
    *   **Package Management:** NuGet Package Manager.

## Modern Attack VM Setup (Recommended)

The new `Windows_Setup/modern-attackvm.ps1` script is a modernized and enhanced version that combines the best features of both `windows-attackvm.ps1` and `choco_windows.ps1`. 

### Key Features and Improvements

1. **Modular Design:** Organized into functions for better maintainability and clarity
2. **Enhanced Configurability:** Settings are in a configuration hash table
3. **Robust Error Handling:** Try-catch blocks with detailed error reporting
4. **Comprehensive Logging:** Logs to both console and file
5. **Categorized Tool Installation:** Tools are organized by purpose and function
6. **Optimized Tool Management:** 
   * Uses Chocolatey for packages with official repositories
   * Uses Git for specialized/bleeding-edge tools
7. **Improved Networking Configuration:** More robust network setup
8. **Better UI Configuration:** More reliable configuration of Windows Explorer and desktop

### Script Structure

The script is organized into the following main sections:

1. **Configuration:** All settings are stored in a centralized configuration hash
2. **Helper Functions:** Functions for logging, admin checks, etc.
3. **Core Functions:**
   * `Initialize-Environment`: Creates directories, sets variables
   * `Install-Chocolatey`: Installs and configures Chocolatey
   * `Configure-WindowsDefender`: Sets exclusions and disables monitoring features
   * `Install-ChocolateyTools`: Installs tools via Chocolatey by category
   * `Install-GitTools`: Clones repositories by category
   * `Install-SpecialTools`: Handles special cases like BloodHound, Neo4j
   * `Configure-Networking`: Sets up IP, routes, and hosts
   * `Configure-UI`: Sets Windows Explorer options, shortcuts, BGInfo
4. **Main Execution:** Orchestrates all operations with proper timing and dependency handling

## Installation Steps

### Option 1: Modern Attack VM Setup (Recommended)

1.  **Clone Repository:** Ensure you have this repository cloned or downloaded to your Windows machine.
2.  **Open PowerShell as Administrator:** Right-click the Start button and select "Windows PowerShell (Admin)" or "Windows Terminal (Admin)".
3.  **Navigate to Script Directory:** Change directory to where you cloned/downloaded this repository, then into the `Windows_Setup` folder.
    ```powershell
    # Example: Adjust path as needed
    cd C:\Users\YourUser\Downloads\Attack_Infra_Setup\Windows_Setup
    ```
4.  **Set Execution Policy (If Required):** If you haven't run PowerShell scripts before, you might need to bypass the execution policy for this session:
    ```powershell
    Set-ExecutionPolicy Bypass -Scope Process -Force
    ```
5.  **Run the Modern Setup Script:** Execute the modern script.
    ```powershell
    .\modern-attackvm.ps1
    ```
6.  **Monitor Progress:** The script provides detailed logging of its progress and any errors encountered.
7.  **Reboot:** After the script finishes, it's recommended to perform a manual reboot to ensure all environment variables, services, and system changes are fully applied.

### Option 2: Standard Setup

1.  **Follow steps 1-4 from Option 1**
2.  **Run the Standard Setup Script:** Execute the original script.
    ```powershell
    .\choco_windows.ps1
    ```
3.  **Wait:** The script will install Chocolatey (if needed) and then proceed to install all the packages. This can take a significant amount of time depending on your internet connection and system speed.
4.  **Reboot:** After the script finishes.

## Post-Installation Notes

*   Both scripts must be run with **Administrator privileges**.
*   Windows Defender settings are modified to prevent interference with security tools. Be aware of the security implications in your environment.
*   The modern script creates a log file (default: C:\setup_log.txt) that can be examined if issues occur.
*   You can customize the modern script by editing the configuration section at the top of the script.
*   Some tools require additional configuration after installation - refer to their documentation for details.
