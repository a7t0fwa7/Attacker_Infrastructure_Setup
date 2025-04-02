#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error when substituting.
# Exit if any command in a pipeline fails, not just the last one.
set -euo pipefail

# --- Configuration ---
STATIC_IP_INTERFACE="eth1"
STATIC_IP_ADDRESS="192.168.152.100/24" # Address/CIDR notation
VPN_INTERFACE="tun0"
TOOL_BASE_DIR="/opt"
CURRENT_USER=$(logname) # Get the actual logged-in user, safer than $USER in some contexts
CURRENT_HOME=$(eval echo ~$CURRENT_USER)

# --- Helper Functions ---

log_info() {
    echo "[+] INFO: $1"
}

log_warn() {
    echo "[!] WARN: $1"
}

log_error() {
    echo "[X] ERROR: $1" >&2
}

run_cmd() {
    log_info "Executing: $@"
    "$@"
}

run_cmd_sudo() {
    log_info "Executing with sudo: $@"
    sudo "$@"
}

check_command() {
    command -v "$1" &> /dev/null
}

# --- Setup Functions ---

update_system() {
    log_info "Updating package lists and upgrading system..."
    run_cmd_sudo apt-get update
    # Consider uncommenting the upgrade if desired, but it can take time
    # run_cmd_sudo apt-get -y upgrade
    run_cmd_sudo apt-get -y install curl wget git apt-transport-https dirmngr gpg build-essential
}

setup_network() {
    log_info "Configuring network interfaces and IP forwarding..."

    # Install necessary packages
    run_cmd_sudo apt-get -y install iptables-persistent netfilter-persistent

    # Configure static IP (using interfaces.d for better organization)
    # Warning: Disabling NetworkManager can break networking in Desktop Environments
    # Consider if this is truly necessary or if NetworkManager can be configured instead.
    log_warn "Disabling NetworkManager. Ensure this is intended."
    run_cmd_sudo systemctl stop NetworkManager.service
    run_cmd_sudo systemctl disable NetworkManager.service

    local interfaces_d_file="/etc/network/interfaces.d/${STATIC_IP_INTERFACE}-static"
    log_info "Creating static IP config at ${interfaces_d_file}"
    echo "auto ${STATIC_IP_INTERFACE}" | sudo tee "${interfaces_d_file}" > /dev/null
    echo "iface ${STATIC_IP_INTERFACE} inet static" | sudo tee -a "${interfaces_d_file}" > /dev/null
    echo "    address ${STATIC_IP_ADDRESS%/*}" | sudo tee -a "${interfaces_d_file}" > /dev/null
    # Calculate netmask from CIDR if needed, assuming /24 for simplicity here based on original
    if [[ "${STATIC_IP_ADDRESS}" == *"/"* ]]; then
         # Basic netmask for common CIDRs, needs improvement for arbitrary CIDRs
         case "${STATIC_IP_ADDRESS##*/}" in
             24) echo "    netmask 255.255.255.0" | sudo tee -a "${interfaces_d_file}" > /dev/null ;;
             16) echo "    netmask 255.255.0.0" | sudo tee -a "${interfaces_d_file}" > /dev/null ;;
             8)  echo "    netmask 255.0.0.0" | sudo tee -a "${interfaces_d_file}" > /dev/null ;;
             *) log_warn "Netmask calculation for CIDR /${STATIC_IP_ADDRESS##*/} not implemented, defaulting to 255.255.255.0"
                echo "    netmask 255.255.255.0" | sudo tee -a "${interfaces_d_file}" > /dev/null ;;
         esac
    else
        log_warn "Static IP address should be in CIDR notation (e.g., 192.168.152.100/24). Assuming /24."
        echo "    address ${STATIC_IP_ADDRESS}" | sudo tee -a "${interfaces_d_file}" > /dev/null
        echo "    netmask 255.255.255.0" | sudo tee -a "${interfaces_d_file}" > /dev/null
    fi

    # Restart networking service (consider 'ifup eth1' if less disruptive)
    log_info "Restarting networking service..."
    run_cmd_sudo systemctl restart networking

    # Enable IP forwarding using sysctl.d
    log_info "Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ip_forward.conf > /dev/null
    run_cmd_sudo sysctl -p /etc/sysctl.d/99-ip_forward.conf

    # Configure iptables rules
    log_info "Configuring iptables rules to forward traffic through ${VPN_INTERFACE}..."
    run_cmd_sudo iptables -t nat -A POSTROUTING -o "${VPN_INTERFACE}" -j MASQUERADE
    run_cmd_sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    run_cmd_sudo iptables -A FORWARD -i "${STATIC_IP_INTERFACE}" -o "${VPN_INTERFACE}" -j ACCEPT
    # These might be too broad depending on exact needs
    # run_cmd_sudo iptables -A FORWARD -i "${VPN_INTERFACE}" -o "${STATIC_IP_INTERFACE}" -j ACCEPT
    # run_cmd_sudo iptables -A FORWARD -i "${VPN_INTERFACE}" -o eth0 -j ACCEPT # Assuming eth0 is WAN? Be specific.
    # run_cmd_sudo iptables -A FORWARD -i eth0 -o "${VPN_INTERFACE}" -j ACCEPT

    # Save iptables rules
    log_info "Saving iptables rules..."
    run_cmd_sudo netfilter-persistent save
    run_cmd_sudo systemctl enable netfilter-persistent.service
}

enable_ssh() {
    log_info "Enabling SSH service..."
    run_cmd_sudo systemctl enable ssh.service
    run_cmd_sudo systemctl start ssh.service
}

install_dev_tools() {
    log_info "Installing core development tools (Go, Rust, .NET, Mingw)..."

    # Install Go (from apt)
    if ! check_command go; then
        log_info "Installing Go..."
        run_cmd_sudo apt-get update
        run_cmd_sudo apt-get -y install golang-go
        # Setup GOPATH if needed (apt package might handle this)
        if ! grep -q 'export GOPATH=' "${CURRENT_HOME}/.profile"; then
             log_info "Adding GOPATH to ${CURRENT_HOME}/.profile"
             echo '' >> "${CURRENT_HOME}/.profile"
             echo '# GoLang Path' >> "${CURRENT_HOME}/.profile"
             echo 'export GOPATH="$HOME/go"' >> "${CURRENT_HOME}/.profile"
             echo 'export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"' >> "${CURRENT_HOME}/.profile" # Add /usr/local/go/bin just in case
        fi
         if [[ -f "${CURRENT_HOME}/.zshrc" ]] && ! grep -q 'export GOPATH=' "${CURRENT_HOME}/.zshrc"; then
             log_info "Adding GOPATH to ${CURRENT_HOME}/.zshrc"
             echo '' >> "${CURRENT_HOME}/.zshrc"
             echo '# GoLang Path' >> "${CURRENT_HOME}/.zshrc"
             echo 'export GOPATH="$HOME/go"' >> "${CURRENT_HOME}/.zshrc"
             echo 'export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"' >> "${CURRENT_HOME}/.zshrc"
         fi
         # Create go directory if it doesn't exist
         mkdir -p "${CURRENT_HOME}/go"
         chown "${CURRENT_USER}:${CURRENT_USER}" "${CURRENT_HOME}/go" -R
    else
        log_info "Go is already installed."
    fi
    # Ensure Go env vars are available for the rest of the script
    export GOPATH="$CURRENT_HOME/go"
    export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"


    # Install Rust (using rustup - preferred method)
    if ! check_command rustc; then
        log_info "Installing Rust..."
        # The official installer requires user interaction, run non-interactively
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
        # Add cargo to the current script's PATH
        export PATH="${CURRENT_HOME}/.cargo/bin:${PATH}"
        # Note: User will need to source ~/.profile or ~/.zshrc or restart shell later
        log_warn "Rust installed. Please source ${CURRENT_HOME}/.cargo/env or restart your shell for changes to take effect."
    else
        log_info "Rust is already installed."
    fi

    # Install .NET SDK (using Microsoft's feed)
    if ! check_command dotnet; then
        log_info "Installing .NET SDK..."
        local dotnet_version="7.0" # Or choose "6.0" (LTS) or "8.0" (latest)
        local debian_version=$(lsb_release -sr | cut -d'.' -f1) # Get major Debian version (e.g., 11, 12)
        wget "https://packages.microsoft.com/config/debian/${debian_version}/packages-microsoft-prod.deb" -O packages-microsoft-prod.deb
        run_cmd_sudo dpkg -i packages-microsoft-prod.deb
        rm packages-microsoft-prod.deb
        run_cmd_sudo apt-get update
        run_cmd_sudo apt-get install -y "dotnet-sdk-${dotnet_version}"
    else
        log_info ".NET SDK is already installed."
    fi

    # Install Mingw-w64
    log_info "Installing Mingw-w64..."
    run_cmd_sudo apt-get -y install mingw-w64

    # Install Vlang (Cloning and building - check if apt package exists)
    if ! check_command v; then
        log_info "Installing Vlang..."
        local vlang_dir="${CURRENT_HOME}/git-tools/vlang"
        if [ ! -d "${vlang_dir}" ]; then
            run_cmd git clone https://github.com/vlang/v "${vlang_dir}"
        else
            log_info "Vlang source directory already exists. Skipping clone."
            # Optional: Add 'git pull' here if update is desired
        fi
        (
            cd "${vlang_dir}"
            log_info "Building Vlang..."
            run_cmd make
            run_cmd_sudo ./v symlink # Creates symlink in /usr/local/bin
        )
    else
        log_info "Vlang is already installed."
    fi

    # Install Python pip and common tools
    log_info "Installing Python3 pip and common libraries..."
    run_cmd_sudo apt-get -y install python3-pip python3-venv python3-dev
}

install_docker() {
    log_info "Installing Docker..."
    if ! check_command docker; then
        # Use Kali's docker.io package
        run_cmd_sudo apt-get update
        run_cmd_sudo apt-get -y install docker.io
        run_cmd_sudo systemctl enable docker --now
        log_info "Adding user ${CURRENT_USER} to the docker group..."
        run_cmd_sudo usermod -aG docker "${CURRENT_USER}"
        log_warn "You may need to log out and log back in for docker group changes to take effect."
    else
        log_info "Docker is already installed."
    fi
}

install_extra_tools() {
    log_info "Installing additional tools (VS Code, Evil-WinRM, CME, BloodHound)..."

    # Install VS Code (using Microsoft repo)
    if ! check_command code; then
        log_info "Installing VS Code..."
        run_cmd_sudo apt-get install -y wget gpg
        wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
        run_cmd_sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
        echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list > /dev/null
        rm -f packages.microsoft.gpg
        run_cmd_sudo apt-get update
        run_cmd_sudo apt-get install -y code
    else
        log_info "VS Code is already installed."
    fi

    # Install Evil-WinRM (Ruby gem)
    if ! check_command evil-winrm; then
        log_info "Installing Evil-WinRM..."
        run_cmd_sudo apt-get -y install ruby ruby-dev # Ensure Ruby is installed
        run_cmd_sudo gem install evil-winrm
    else
        log_info "Evil-WinRM is already installed."
    fi

    # Install CrackMapExec (from apt)
    if ! check_command crackmapexec; then
        log_info "Installing CrackMapExec..."
        run_cmd_sudo apt-get update
        run_cmd_sudo apt-get -y install crackmapexec
    else
        log_info "CrackMapExec is already installed."
    fi

    # Install BloodHound (from apt)
    if ! check_command bloodhound; then
        log_info "Installing BloodHound..."
        run_cmd_sudo apt-get update
        run_cmd_sudo apt-get -y install bloodhound
        log_info "Downloading BloodHound custom queries..."
        local bloodhound_config_dir="${CURRENT_HOME}/.config/bloodhound"
        mkdir -p "${bloodhound_config_dir}"
        # Choose one query set or merge them manually
        curl -o "${bloodhound_config_dir}/customqueries.json" "https://raw.githubusercontent.com/ZephrFish/Bloodhound-CustomQueries/main/customqueries.json"
        chown -R "${CURRENT_USER}:${CURRENT_USER}" "${bloodhound_config_dir}"
    else
        log_info "BloodHound is already installed."
    fi

    # Install smap (Go tool)
    if ! check_command smap; then
        log_info "Installing smap..."
        if check_command go; then
            run_cmd go install -v github.com/s0md3v/smap/cmd/smap@latest
        else
            log_warn "Go is not installed, cannot install smap."
        fi
    else
        log_info "smap is already installed."
    fi

    # Install Obfuscated Mimikatz (Warning: Security Risk)
    log_warn "Downloading and executing Obfuscated Mimikatz script from gist. Review the script first!"
    # Consider downloading manually or hosting the script yourself
    # curl -s https://gist.githubusercontent.com/a7t0fwa7/94591fe57d330cafbc89a349dc05c0e2/raw/dafbd32d1307c4ebb512e4eb7c43c7e1292bcac9/ObfuscateMimi_First.sh | bash
    log_warn "Skipping automatic execution of Obfuscated Mimikatz script for security reasons."
    log_info "To install manually, run: curl -s https://gist.githubusercontent.com/a7t0fwa7/94591fe57d330cafbc89a349dc05c0e2/raw/dafbd32d1307c4ebb512e4eb7c43c7e1292bcac9/ObfuscateMimi_First.sh | bash"

}

create_tool_dirs() {
    log_info "Creating tool directories in ${TOOL_BASE_DIR}..."
    local dirs=(
        "Intel-Tools" "Command-and-Control" "Reverse-Engineering" "Obfuscation-Tools"
        "Offensive-Tools" "AV-Evasion-Tools" "Useful-Lists" "Cloud" "CheatSheets"
        "Egress-Assess" # Added from git clone list
    )
    for dir in "${dirs[@]}"; do
        run_cmd_sudo mkdir -p "${TOOL_BASE_DIR}/${dir}"
        run_cmd_sudo chown "${CURRENT_USER}:${CURRENT_USER}" "${TOOL_BASE_DIR}/${dir}"
    done
}

# Function to safely clone or update a git repository
# Usage: git_clone_or_update <repo_url> <destination_dir> [sudo_chown]
git_clone_or_update() {
    local repo_url="$1"
    local dest_dir="$2"
    local sudo_chown_flag="${3:-false}" # Default to false

    log_info "Cloning/Updating ${repo_url} into ${dest_dir}"

    if [ -d "${dest_dir}/.git" ]; then
        log_info "Directory ${dest_dir} exists, attempting git pull..."
        ( # Run in subshell to avoid cd side effects
            cd "${dest_dir}"
            git pull || log_warn "git pull failed for ${dest_dir}. Manual check needed."
        )
    elif [ -d "${dest_dir}" ]; then
         log_warn "Directory ${dest_dir} exists but is not a git repository. Skipping."
    else
        # Clone into user's home first to avoid sudo git clone if possible
        local tmp_clone_dir="${CURRENT_HOME}/git-clones/$(basename ${dest_dir})"
        mkdir -p "$(dirname ${tmp_clone_dir})"
        if git clone "${repo_url}" "${tmp_clone_dir}"; then
            # Move to final destination
            if [ "${sudo_chown_flag}" = true ]; then
                run_cmd_sudo mv "${tmp_clone_dir}" "${dest_dir}"
                run_cmd_sudo chown -R "${CURRENT_USER}:${CURRENT_USER}" "${dest_dir}"
            else
                 # If destination is in user home, no sudo needed
                 if [[ "${dest_dir}" == ${CURRENT_HOME}* ]]; then
                     mv "${tmp_clone_dir}" "${dest_dir}"
                 else
                     # Destination requires sudo mv, but not chown
                     run_cmd_sudo mv "${tmp_clone_dir}" "${dest_dir}"
                 fi
            fi
            rmdir -p "$(dirname ${tmp_clone_dir})" 2>/dev/null || true # Clean up parent dirs if empty
        else
            log_error "Failed to clone ${repo_url}"
            rm -rf "${tmp_clone_dir}" # Clean up failed clone attempt
        fi
    fi
}


clone_security_tools() {
    log_info "Cloning security tools..."
    mkdir -p "${CURRENT_HOME}/git-clones" # Temp location for clones

    # --- Intel Tools ---
    git_clone_or_update https://github.com/evilsocket/legba.git "${TOOL_BASE_DIR}/Intel-Tools/LegbaBruteForcer" true
    # sub3suite release is a tar.gz, not a git repo - handle separately
    # git_clone_or_update https://github.com/3nock/sub3suite/releases/download/v0.0.3/sub3suite-v0.0.3-linux.tar.gz "${TOOL_BASE_DIR}/Intel-Tools/sub3suite" true
    git_clone_or_update https://github.com/MrTuxx/SocialPwned.git "${TOOL_BASE_DIR}/Intel-Tools/SocialPwned" true
    git_clone_or_update https://github.com/irsdl/IIS-ShortName-Scanner.git "${TOOL_BASE_DIR}/Intel-Tools/IIS-ShortName-Scanner" true
    git_clone_or_update https://github.com/v4d1/Dome.git "${TOOL_BASE_DIR}/Intel-Tools/SubDomainEnum_Dome" true
    git_clone_or_update https://github.com/whydee86/ComPP.git "${TOOL_BASE_DIR}/Intel-Tools/Password_Gen_ComPP" true
    git_clone_or_update https://github.com/Taonn/EmailAll.git "${TOOL_BASE_DIR}/Intel-Tools/EmailAll" true
    git_clone_or_update https://github.com/ropnop/kerbrute.git "${TOOL_BASE_DIR}/Intel-Tools/kerbrute" true
    git_clone_or_update https://github.com/rbsec/dnscan.git "${TOOL_BASE_DIR}/Intel-Tools/dnscan" true
    git_clone_or_update https://github.com/chinarulezzz/spoofcheck "${TOOL_BASE_DIR}/Intel-Tools/spoofcheck" true
    # Install spoofcheck deps
    if [ -f "${TOOL_BASE_DIR}/Intel-Tools/spoofcheck/requirements.txt" ]; then
        log_info "Installing dependencies for spoofcheck..."
        run_cmd_sudo pip3 install -r "${TOOL_BASE_DIR}/Intel-Tools/spoofcheck/requirements.txt"
    fi
    # Namemash is a gist, handle separately
    # git_clone_or_update https://gist.github.com/superkojiman/11076951 "${TOOL_BASE_DIR}/namemash" true
    git_clone_or_update https://github.com/byt3bl33d3r/SprayingToolkit.git "${TOOL_BASE_DIR}/Intel-Tools/SprayingToolkit" true
     if [ -f "${TOOL_BASE_DIR}/Intel-Tools/SprayingToolkit/requirements.txt" ]; then
        log_info "Installing dependencies for SprayingToolkit..."
        run_cmd_sudo pip3 install -r "${TOOL_BASE_DIR}/Intel-Tools/SprayingToolkit/requirements.txt"
    fi
    git_clone_or_update https://github.com/itm4n/PrivescCheck.git "${TOOL_BASE_DIR}/Intel-Tools/PrivescCheck" true # Also in Offensive-Tools? Keep one?
    git_clone_or_update https://github.com/artofwar2306/Invoke-Recon.git "${TOOL_BASE_DIR}/Intel-Tools/Invoke-Recon" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/MailSniper.git "${TOOL_BASE_DIR}/Intel-Tools/MailSniper" true
    git_clone_or_update https://github.com/SnaffCon/Snaffler.git "${TOOL_BASE_DIR}/Intel-Tools/Snaffler" true
    git_clone_or_update https://github.com/lkarlslund/adalanche.git "${TOOL_BASE_DIR}/Intel-Tools/ActiveDirectoryAdalanche" true
    # Build ADalanche
    if [ -f "${TOOL_BASE_DIR}/Intel-Tools/ActiveDirectoryAdalanche/build.sh" ]; then
        log_info "Building ADalanche..."
        ( cd "${TOOL_BASE_DIR}/Intel-Tools/ActiveDirectoryAdalanche" && sudo bash build.sh )
    fi

    # --- Offensive Tools ---
    git_clone_or_update https://github.com/dafthack/GraphRunner.git "${TOOL_BASE_DIR}/Offensive-Tools/GraphRunner" true
    git_clone_or_update https://github.com/The-Viper-One/PsMapExec.git "${TOOL_BASE_DIR}/Offensive-Tools/PsMapExec-Enum" true
    git_clone_or_update https://github.com/itm4n/PrivescCheck.git "${TOOL_BASE_DIR}/Offensive-Tools/PrivEscChecker" true # Duplicate?
    git_clone_or_update https://github.com/lengjibo/RedTeamTools.git "${TOOL_BASE_DIR}/Offensive-Tools/RedTeamTools" true
    git_clone_or_update https://github.com/timwhitez/Doge-RecycledGate.git "${TOOL_BASE_DIR}/Offensive-Tools/Doge-RecycledGate" true
    git_clone_or_update https://github.com/DarkCoderSc/PowerRunAsAttached.git "${TOOL_BASE_DIR}/Offensive-Tools/DarkCoderPowerRunAsAttached" true
    git_clone_or_update https://github.com/DarkCoderSc/PowerRemoteDesktop.git "${TOOL_BASE_DIR}/Offensive-Tools/DarkCoderPowerRemoteDesktop" true
    git_clone_or_update https://github.com/DarkCoderSc/PowerRunAsSystem.git "${TOOL_BASE_DIR}/Offensive-Tools/DarkCoderPowerRunAsSystem" true
    git_clone_or_update https://github.com/ly4k/SpoolFool.git "${TOOL_BASE_DIR}/Offensive-Tools/SpoolFool" true
    git_clone_or_update https://github.com/wavestone-cdt/Invoke-CleverSpray.git "${TOOL_BASE_DIR}/Offensive-Tools/Invoke-CleverSpray" true
    git_clone_or_update https://github.com/mitchmoser/LACheck.git "${TOOL_BASE_DIR}/Offensive-Tools/LocalAdminPrivEscChecker" true
    # Mgeeky tools commented out in original, keep commented
    # git_clone_or_update https://github.com/mgeeky/mgeeky-gists.git "${TOOL_BASE_DIR}/Offensive-Tools/MGeekys_Gists" true
    # git_clone_or_update https://github.com/mgeeky/Penetration-Testing-Tools.git "${TOOL_BASE_DIR}/Offensive-Tools/MGeekys_Pentest_Tools" true
    git_clone_or_update https://github.com/cmars/onionpipe.git "${TOOL_BASE_DIR}/Offensive-Tools/tunneling_onionpipe" true
    git_clone_or_update https://github.com/fox-it/aclpwn.py.git "${TOOL_BASE_DIR}/Offensive-Tools/aclpwn" true
    git_clone_or_update https://github.com/fox-it/Invoke-CredentialPhisher.git "${TOOL_BASE_DIR}/Offensive-Tools/Invoke-CredentialPhisher" true # Typo in original path fixed
    git_clone_or_update https://github.com/xforcered/InlineExecute-Assembly.git "${TOOL_BASE_DIR}/Offensive-Tools/InlineExecute-Assembly" true
    git_clone_or_update https://github.com/3gstudent/Invoke-BuildAnonymousSMBServer.git "${TOOL_BASE_DIR}/Offensive-Tools/Invoke-BuildAnonymousSMBServer" true
    git_clone_or_update https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement.git "${TOOL_BASE_DIR}/Offensive-Tools/Offensive-VBA-and-XLS-Entanglement" true
    git_clone_or_update https://github.com/GossiTheDog/HiveNightmare.git "${TOOL_BASE_DIR}/Offensive-Tools/HiveNightmare" true
    git_clone_or_update https://github.com/Inf0secRabbit/BadAssMacros.git "${TOOL_BASE_DIR}/Offensive-Tools/BadAssMacros" true # Duplicate?
    git_clone_or_update https://github.com/bats3c/ADCSPwn.git "${TOOL_BASE_DIR}/Offensive-Tools/ADCSPwn" true
    git_clone_or_update https://github.com/ShutdownRepo/targetedKerberoast.git "${TOOL_BASE_DIR}/Offensive-Tools/targetedKerberoast" true
    git_clone_or_update https://github.com/topotam/PetitPotam.git "${TOOL_BASE_DIR}/Offensive-Tools/PetitPotam" true
    git_clone_or_update https://github.com/Flangvik/DeployPrinterNightmare.git "${TOOL_BASE_DIR}/Offensive-Tools/DeployPrintNightMare" true
    git_clone_or_update https://github.com/cube0x0/MiniDump.git "${TOOL_BASE_DIR}/Offensive-Tools/MiniDump" true
    git_clone_or_update https://github.com/sevagas/macro_pack.git "${TOOL_BASE_DIR}/Offensive-Tools/Macro_Pack" true
    git_clone_or_update https://github.com/aloksaurabh/OffenPowerSh.git "${TOOL_BASE_DIR}/Offensive-Tools/OffenPowerSh" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/WinPwn.git "${TOOL_BASE_DIR}/Offensive-Tools/WinPWn" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git "${TOOL_BASE_DIR}/Offensive-Tools/PowerSharpPack" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/Creds.git "${TOOL_BASE_DIR}/Offensive-Tools/Creds" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/Invoke-PrintDemon.git "${TOOL_BASE_DIR}/Offensive-Tools/Invoke-PrintDemon" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader.git "${TOOL_BASE_DIR}/Offensive-Tools/Invoke-SharpLoader" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/Invoke-Sharpcradle.git "${TOOL_BASE_DIR}/Offensive-Tools/Invoke-SharpCradle" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/Get-System-Techniques.git "${TOOL_BASE_DIR}/Offensive-Tools/Get-System-Techniques" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/SharpLocker.git "${TOOL_BASE_DIR}/Offensive-Tools/SharpLocker" true
    git_clone_or_update https://github.com/jxy-s/herpaderping.git "${TOOL_BASE_DIR}/Offensive-Tools/herpaderping" true
    git_clone_or_update https://github.com/bytecod3r/Cobaltstrike-Aggressor-Scripts-Collection.git "${TOOL_BASE_DIR}/Offensive-Tools/CobaltStrike-Agressor-Scripts-Collection" true
    git_clone_or_update https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git "${TOOL_BASE_DIR}/Offensive-Tools/WinAndLinPEAS" true
    git_clone_or_update https://github.com/bitsadmin/wesng.git "${TOOL_BASE_DIR}/Offensive-Tools/WinExploitSuggestorNextGen" true
    git_clone_or_update https://github.com/samratashok/ADModule.git "${TOOL_BASE_DIR}/Offensive-Tools/ADModule" true
    git_clone_or_update https://github.com/Ignitetechnologies/Credential-Dumping.git "${TOOL_BASE_DIR}/Offensive-Tools/CredDump" true # Duplicate?

    # --- AV Evasion Tools ---
    git_clone_or_update https://github.com/h0ru/AMSI-Reaper.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/AMSI-Reaper" true
    git_clone_or_update https://github.com/aaaddress1/xlsKami.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/ShenHaoMaXlsKami" true
    git_clone_or_update https://github.com/aaaddress1/PR0CESS.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/ShenHaoMaPR0CESS" true
    git_clone_or_update https://github.com/aaaddress1/Skrull.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/ShenHaoMaSkrull" true
    git_clone_or_update https://github.com/cube0x0/SyscallPack.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/SyscallPack" true
    git_clone_or_update https://github.com/klezVirus/SysWhispers3.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/SysWhispers3" true
    git_clone_or_update https://github.com/Inf0secRabbit/BadAssMacros.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/BadAssMacros" true # Duplicate?
    git_clone_or_update https://github.com/sbasu7241/HellsGate.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/HellsGate" true
    git_clone_or_update https://github.com/Idov31/FunctionStomping.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/FunctionStomping" true
    git_clone_or_update https://github.com/safe6Sec/GolangBypassAV.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/GolangBypassAV" true
    git_clone_or_update https://github.com/last-byte/DefenderSwitch.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/DefenderSwitch" true
    # Mgeeky tools commented out in original
    # git_clone_or_update https://github.com/mgeeky/polonium.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/MGeekys_map_out_AVs_EDRs_detection_surface_to_identify_their_gaps." true
    # git_clone_or_update https://github.com/mgeeky/VisualBasicObfuscator.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/MGeekys_VB_Obfuscator_unmaintained" true
    # git_clone_or_update https://github.com/mgeeky/Stracciatella.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/MGeekys_Strcciatella" true
    git_clone_or_update https://github.com/ORCA666/EVA2.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/EVA2" true
    git_clone_or_update https://github.com/N4kedTurtle/HellsGatePoC.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/HellsGatePoC" true
    git_clone_or_update https://github.com/two06/Inception.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/Inception" true
    git_clone_or_update https://github.com/Soledge/BlockEtw.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/BlockEtw" true
    git_clone_or_update https://github.com/bats3c/darkarmour.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/darkarmour" true
    git_clone_or_update https://github.com/dosxuz/DefenderStop.git "${TOOL_BASE_DIR}/AV-Evasion-Tools/DefenderStop" true

    # --- Obfuscation Tools ---
    # git_clone_or_update https://github.com/mgeeky/ProtectMyTooling.git "${TOOL_BASE_DIR}/Obfuscation-Tools/MGeekys_ProtectMyTooling" true # Commented out
    git_clone_or_update https://github.com/AnErrupTion/LoGiC.NET.git "${TOOL_BASE_DIR}/Obfuscation-Tools/LoGIC.NET" true
    git_clone_or_update https://github.com/d35ha/CallObfuscator.git "${TOOL_BASE_DIR}/Obfuscation-Tools/CallObfuscator" true
    git_clone_or_update https://github.com/xp4xbox/PyEvade.git "${TOOL_BASE_DIR}/Obfuscation-Tools/PyEvade" true
    git_clone_or_update https://github.com/danielbohannon/Invoke-Obfuscation.git "${TOOL_BASE_DIR}/Obfuscation-Tools/Invoke-Obfuscation" true
    git_clone_or_update https://github.com/CBHue/PyFuscation.git "${TOOL_BASE_DIR}/Obfuscation-Tools/PyFuscation" true
    git_clone_or_update https://github.com/tokyoneon/Chimera.git "${TOOL_BASE_DIR}/Obfuscation-Tools/Chimera" true
    git_clone_or_update https://github.com/S3cur3Th1sSh1t/xencrypt.git "${TOOL_BASE_DIR}/Obfuscation-Tools/xencrypt" true
    git_clone_or_update https://github.com/Flangvik/SimpleSourceProtector.git "${TOOL_BASE_DIR}/Obfuscation-Tools/SimpleSourceProtector" true

    # --- Useful Lists ---
    git_clone_or_update https://github.com/danielmiessler/SecLists.git "${TOOL_BASE_DIR}/Useful-Lists/SecLists" true
    git_clone_or_update https://github.com/swisskyrepo/PayloadsAllTheThings.git "${TOOL_BASE_DIR}/Useful-Lists/PayloadsAllTheThings" true

    # --- Cheat Sheets ---
    git_clone_or_update https://github.com/a7t0fwa7/Windows-Local-Privilege-Escalation-CheatSheet.git "${TOOL_BASE_DIR}/CheatSheets/WinPrivEsc" true
    git_clone_or_update https://github.com/aaaddress1/Windows-APT-Warfare.git "${TOOL_BASE_DIR}/CheatSheets/Windows-APT-Warfare" true
    git_clone_or_update https://github.com/Ignitetechnologies/Credential-Dumping.git "${TOOL_BASE_DIR}/CheatSheets/Credential-Dumping" true # Duplicate?

    # --- Cloud Tools ---
    git_clone_or_update https://github.com/lutzenfried/Delegate.git "${TOOL_BASE_DIR}/Cloud/GCP_Domain_Delegation_Abuse" true # Typo 'suod' fixed
    git_clone_or_update https://github.com/initstring/cloud_enum.git "${TOOL_BASE_DIR}/Cloud/Multi_Cloud_Enum_tool" true
    git_clone_or_update https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation.git "${TOOL_BASE_DIR}/Cloud/GCP-IAM-Priv-Esc" true
    git_clone_or_update https://github.com/RhinoSecurityLabs/CloudScraper.git "${TOOL_BASE_DIR}/Cloud/CloudScraper" true
    git_clone_or_update https://github.com/RhinoSecurityLabs/GCPBucketBrute.git "${TOOL_BASE_DIR}/Cloud/GCPBucketBrute" true
    git_clone_or_update https://github.com/ZarvisD/Azure-AD.git "${TOOL_BASE_DIR}/Cloud/Azure-AD" true
    git_clone_or_update https://github.com/nccgroup/PMapper.git "${TOOL_BASE_DIR}/Cloud/AWS_PMapper" true
    git_clone_or_update https://github.com/nccgroup/ScoutSuite.git "${TOOL_BASE_DIR}/Cloud/MultiCloud_ScoutSuite" true
    git_clone_or_update https://github.com/NetSPI/MicroBurst.git "${TOOL_BASE_DIR}/Cloud/Azure_MicroBurst" true
    git_clone_or_update https://github.com/sa7mon/S3Scanner.git "${TOOL_BASE_DIR}/Cloud/AWS_S3Scanner" true
    git_clone_or_update https://github.com/aquasecurity/cloudsploit.git "${TOOL_BASE_DIR}/Cloud/MultiCloud_CloudSploit" true
    git_clone_or_update https://github.com/darkquasar/AzureHunter.git "${TOOL_BASE_DIR}/Cloud/Azure_Forensics_AzureHunter" true
    git_clone_or_update https://github.com/TROUBLE-1/Vajra.git "${TOOL_BASE_DIR}/Cloud/Azure_Vajra_Attack_Framework" true
    git_clone_or_update https://github.com/rkemery/bash-gcp-buckets-public.git "${TOOL_BASE_DIR}/Cloud/GCP_Enum_Buckets" true
    git_clone_or_update https://github.com/RhinoSecurityLabs/pacu.git "${TOOL_BASE_DIR}/Cloud/AWS_Exploitation_Framework_Pacu" true
    git_clone_or_update https://github.com/BishopFox/smogcloud.git "${TOOL_BASE_DIR}/Cloud/AWS_SmogCloud" true
    git_clone_or_update https://github.com/accurics/terrascan.git "${TOOL_BASE_DIR}/Cloud/IaaC_TerraScan" true
    git_clone_or_update https://github.com/FSecureLABS/leonidas.git "${TOOL_BASE_DIR}/Cloud/AWS_AttackSim_Framework_Leonidas" true

    # --- Egress Assess ---
    git_clone_or_update https://github.com/FortyNorthSecurity/Egress-Assess.git "${TOOL_BASE_DIR}/Egress-Assess" true

    # --- Special Handling ---
    # Sub3Suite (Download Tarball)
    local sub3suite_url="https://github.com/3nock/sub3suite/releases/download/v0.0.3/sub3suite-v0.0.3-linux.tar.gz"
    local sub3suite_dest="${TOOL_BASE_DIR}/Intel-Tools/sub3suite"
    if [ ! -d "${sub3suite_dest}" ]; then
        log_info "Downloading and extracting Sub3Suite..."
        run_cmd_sudo mkdir -p "${sub3suite_dest}"
        wget -qO- "${sub3suite_url}" | sudo tar -xz -C "${sub3suite_dest}" --strip-components=1 # Adjust strip-components if needed
        run_cmd_sudo chown -R "${CURRENT_USER}:${CURRENT_USER}" "${sub3suite_dest}"
    else
        log_info "Sub3Suite directory already exists. Skipping download."
    fi

    # Namemash (Download Gist)
    local namemash_url="https://gist.githubusercontent.com/superkojiman/11076951/raw/namemash.py" # Raw URL
    local namemash_dest="${TOOL_BASE_DIR}/Intel-Tools/namemash" # Changed location to Intel-Tools
    if [ ! -f "${namemash_dest}/namemash.py" ]; then
        log_info "Downloading Namemash..."
        run_cmd_sudo mkdir -p "${namemash_dest}"
        sudo wget -qO "${namemash_dest}/namemash.py" "${namemash_url}"
        run_cmd_sudo chmod +x "${namemash_dest}/namemash.py"
        run_cmd_sudo chown -R "${CURRENT_USER}:${CURRENT_USER}" "${namemash_dest}"
    else
        log_info "Namemash script already exists. Skipping download."
    fi

    log_info "Finished cloning tools."
    # Clean up empty clone dir
    rmdir "${CURRENT_HOME}/git-clones" 2>/dev/null || true
}


install_c2_frameworks() {
    log_info "Installing C2 Frameworks (Sliver, Mythic, Havoc, Covenant, Shad0w)..."
    local c2_dir="${TOOL_BASE_DIR}/Command-and-Control"

    # Sliver C2
    git_clone_or_update https://github.com/BishopFox/sliver.git "${c2_dir}/Sliver" true
    # Note: Sliver often requires manual steps or has its own install script. Check docs.

    # Mythic C2
    git_clone_or_update https://github.com/its-a-feature/Mythic "${c2_dir}/Mythic" true # Fixed double 'git clone'
    # Note: Mythic installation is complex (Docker). User needs to run './mythic-cli install github <agent>' etc.
    log_warn "Mythic cloned. Refer to Mythic documentation for installation and setup."

    # Havoc C2
    git_clone_or_update https://github.com/HavocFramework/Havoc.git "${c2_dir}/Havoc" true # Renamed H4voc -> Havoc
    # Install Havoc dependencies (ensure these cover everything needed)
    log_info "Installing Havoc dependencies..."
    run_cmd_sudo apt-get update
    run_cmd_sudo apt-get install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev \
        libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev \
        libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev \
        qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev \
        qtdeclarative5-dev golang-go python3-dev mingw-w64 nasm
    # Build Havoc (Refer to Havoc docs for exact build steps)
    log_warn "Havoc cloned and dependencies installed. Refer to Havoc documentation for build instructions (usually involves building Teamserver and Client)."
    # Example build steps (might need adjustment):
    # ( cd "${c2_dir}/Havoc/teamserver" && make )
    # ( cd "${c2_dir}/Havoc/client" && make )


    # Custom Covenant (Venom Mod)
    install_modified_covenant "${c2_dir}/Venom" # Use function

    # Shadow C2
    git_clone_or_update https://github.com/bats3c/shad0w.git "${c2_dir}/shad0w" true
    if [ -f "${c2_dir}/shad0w/install.sh" ]; then # Check if install script exists
        log_info "Running Shad0w install script..."
        ( cd "${c2_dir}/shad0w" && sudo ./install.sh ) # Check if sudo is needed by the script
    else
        log_warn "Shad0w install script not found. Refer to Shad0w documentation."
    fi
}

# Encapsulated Covenant modification logic
install_modified_covenant() {
    local dest_dir="$1"
    local source_repo="https://github.com/cobbr/Covenant.git" # Using original repo

    log_info "Setting up modified Covenant in ${dest_dir}..."

    if [ -d "${dest_dir}" ]; then
        log_warn "Destination directory ${dest_dir} already exists. Skipping Covenant setup."
        log_warn "Delete it manually if you want to reinstall."
        return
    fi

    log_info "Cloning original Covenant repository..."
    # Clone directly to final location with sudo, then chown
    run_cmd_sudo git clone --recurse-submodules "${source_repo}" "${dest_dir}"
    run_cmd_sudo chown -R "${CURRENT_USER}:${CURRENT_USER}" "${dest_dir}"

    local covenant_work_dir="${dest_dir}/Covenant"
    if [ ! -d "${covenant_work_dir}" ]; then
        log_error "Covenant checkout failed or directory structure unexpected at ${dest_dir}."
        return
    fi

    log_info "Applying 'Venom' modifications to Covenant..."
    ( # Run modifications in a subshell within the correct directory
        cd "${covenant_work_dir}"

        log_info "Moving directories..."
        # Use temporary names to avoid clashes if dirs exist
        mv ./Data/AssemblyReferences/ ../AssemblyReferences_temp || log_warn "Failed to move AssemblyReferences"
        mv ./Data/ReferenceSourceLibraries/ ../ReferenceSourceLibraries_temp || log_warn "Failed to move ReferenceSourceLibraries"
        mv ./Data/EmbeddedResources/ ../EmbeddedResources_temp || log_warn "Failed to move EmbeddedResources"

        mv ./Models/Covenant/ ./Models/Venom/ || log_warn "Failed to rename Models/Covenant"
        mv ./Components/CovenantUsers/ ./Components/VenomUsers/ || log_warn "Failed to rename Components/CovenantUsers"
        mv ./Components/Grunts/ ./Components/Nagas/ || log_warn "Failed to rename Components/Grunts"
        mv ./Models/Grunts/ ./Models/Nagas/ || log_warn "Failed to rename Models/Grunts"
        mv ./Data/Grunt/GruntBridge/ ./Data/Naga/NagaBridge/ || log_warn "Failed to rename GruntBridge" # Adjusted target
        mv ./Data/Grunt/GruntHTTP/ ./Data/Naga/NagaHTTP/ || log_warn "Failed to rename GruntHTTP" # Adjusted target
        mv ./Data/Grunt/GruntSMB/ ./Data/Naga/NagaSMB/ || log_warn "Failed to rename GruntSMB" # Adjusted target
        mv ./Components/GruntTaskings/ ./Components/NagaTaskings/ || log_warn "Failed to rename GruntTaskings"
        mv ./Components/GruntTasks/ ./Components/NagaTasks/ || log_warn "Failed to rename GruntTasks"
        mv ./Data/Grunt/ ./Data/Naga/ || log_warn "Failed to rename Data/Grunt" # Should be done after subdirs

        log_info "Applying sed replacements (this may take a while)..."
        # Combine sed commands for efficiency where possible, be careful with order
        find ./ -type f -print0 | xargs -0 sed -i \
            -e "s/Grunt/Naga/g" \
            -e "s/GRUNT/NAGA/g" \
            -e "s/grunt/naga/g" \
            -e "s/Covenant/Venom/g" \
            -e "s/COVENANT/VENOM/g" \
            -e "s/ExecuteStager/ExecNiveau/g" \
            -e "s/SetupAES/InstallerAES/g" \
            -e "s/SessionKey/CleSession/g" \
            -e "s/EncryptedChallenge/CryptageChallEnge/g" \
            -e "s/DecryptedChallenges/DecryptageDesChallenges/g" \
            -e "s/Stage0Body/PremierBody/g" \
            -e "s/Stage0Response/PremierResponse/g" \
            -e "s/Stage0Bytes/PremierBytes/g" \
            -e "s/Stage1Body/DeuxiemeBody/g" \
            -e "s/Stage1Response/DeuxiemeResponse/g" \
            -e "s/Stage1Bytes/DeuxiemeBytes/g" \
            -e "s/Stage2Body/TroisiemeBody/g" \
            -e "s/Stage2Response/TroisiemeResponse/g" \
            -e "s/Stage2Bytes/TroisiemeBytes/g" \
            -e "s/message64str/MeSSaGe64str/g" \
            -e "s/messageBytes/MeSSaGebytes/g" \
            -e "s/totalReadBytes/ToTalReaDBytes/g" \
            -e "s/deflateStream/deFlatEstream/g" \
            -e "s/memoryStream/memOrYstream/g" \
            -e "s/compressedBytes/comprimebytes/g" \
            -e "s/CookieWebClient/NagasWebClient/g" \
            -e "s/Jitter/JItTer/g" \
            -e "s/ConnectAttempts/ConneCTAttEmpTs/g" \
            -e "s/RegisterBody/RegistreBody/g" \
            -e "s/Hello World/Its me, nobody/g" \
            -e "s/ValidateCert/ValiderLeCerTif/g" \
            -e "s/UseCertPinning/UtiliseCertPin/g" \
            -e "s/EncryptedMessage/MessageCrypte/g" \
            -e "s/cookieWebClient/nagaWebClient/g" \
            -e "s/ProfileHttp/ProfilageHTTP/g" \
            -e "s/baseMessenger/bAsemEsSenGer/g" \
            -e "s/PartiallyDecrypted/decryptagePartiel/g" \
            -e "s/FullyDecrypted/decryptageComplet/g"

        log_info "Applying sed replacements specific to .cs files..."
        find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i \
            -e "s/REPLACE_/REMPLACE_/g" \
            -e "s/_PROFILE_/_PROFILAGE_/g" \
            -e "s/_VALIDATE_/_VALIDER_/g" \
            -e "s/GUID/AUTREID/g" \
            -e "s/guid/autreid/g" \
            -e "s/messenger/MeSsenGer/g" \
            -e "s/aes/cryptvar/g" \
            -e "s/aes2/cryptvar2/g" \
            -e "s/array5/arr5/g" \
            -e "s/array6/arr6/g" \
            -e "s/array4/arr4/g" \
            -e "s/array7/arr7/g" \
            -e "s/array1/arr1/g" \
            -e "s/array2/arr2/g" \
            -e "s/array3/arr3/g" \
            -e "s/list1/li1/g" \
            -e "s/list2/li2/g" \
            -e "s/list3/li3/g" \
            -e "s/list4/li4/g" \
            -e "s/list5/li5/g" \
            -e "s/group0/grp0/g" \
            -e "s/group1/grp1/g" \
            -e "s/group2/grp2/g" \
            -e "s/group3/grp3/g" \
            -e "s/group4/grp4/g" \
            -e "s/group5/grp5/g" \
            -e "s/group6/grp6/g" \
            -e "s/group7/grp7/g" \
            -e "s/group8/grp8/g"

        log_info "Applying sed replacements specific to .razor, .json, .yaml files..."
        find ./ -type f \( -name "*.razor" -o -name "*.json" -o -name "*.yaml" \) -print0 | xargs -0 sed -i \
            -e "s/GUID/AUTREID/g" \
            -e "s/guid/autreid/g"

        log_info "Renaming files containing 'Grunt' or 'Covenant'..."
        # Rename Grunt -> Naga
        find ./ -depth -name '*Grunt*' -exec bash -c 'mv "$0" "$(echo "$0" | sed -e "s/Grunt/Naga/g")"' {} \;
        find ./ -depth -name '*GRUNT*' -exec bash -c 'mv "$0" "$(echo "$0" | sed -e "s/GRUNT/NAGA/g")"' {} \;
        find ./ -depth -name '*grunt*' -exec bash -c 'mv "$0" "$(echo "$0" | sed -e "s/grunt/naga/g")"' {} \;
        # Rename Covenant -> Venom
        find ./ -depth -name '*Covenant*' -exec bash -c 'mv "$0" "$(echo "$0" | sed -e "s/Covenant/Venom/g")"' {} \;
        find ./ -depth -name '*COVENANT*' -exec bash -c 'mv "$0" "$(echo "$0" | sed -e "s/COVENANT/VENOM/g")"' {} \;

        log_info "Moving back directories..."
        mv ../AssemblyReferences_temp/ ./Data/AssemblyReferences || log_warn "Failed to move back AssemblyReferences"
        mv ../ReferenceSourceLibraries_temp/ ./Data/ReferenceSourceLibraries || log_warn "Failed to move back ReferenceSourceLibraries"
        mv ../EmbeddedResources_temp/ ./Data/EmbeddedResources || log_warn "Failed to move back EmbeddedResources"

        log_info "Building modified Covenant (Venom)..."
        if check_command dotnet; then
            dotnet build || log_error "Covenant build failed."
        else
            log_error "dotnet command not found. Cannot build Covenant."
        fi
    ) # End subshell
    log_info "Finished Covenant modification and build attempt."
}

set_motd() {
    log_info "Setting custom MOTD..."
    local motd_content="\nDark Ops || Field-Operations\nred-team-ops\n\n"
    echo -e "${motd_content}" | sudo tee /etc/motd > /dev/null
}

# --- Main Execution ---

main() {
    log_info "Starting Kali C2 and Tools Setup Script..."
    log_info "Running as user: ${CURRENT_USER} in home: ${CURRENT_HOME}"
    log_info "Tools will be installed in: ${TOOL_BASE_DIR}"

    update_system
    # setup_network # Uncomment if network configuration is needed
    enable_ssh
    install_dev_tools
    install_docker
    install_extra_tools
    create_tool_dirs
    clone_security_tools
    install_c2_frameworks
    set_motd

    log_info "-----------------------------------------------------"
    log_info "Setup script completed!"
    log_warn "Please review any warnings or errors above."
    log_warn "Remember to source ${CURRENT_HOME}/.profile or ${CURRENT_HOME}/.zshrc or restart your shell for PATH changes to take effect."
    log_warn "Docker group membership requires logout/login."
    log_warn "C2 frameworks (Mythic, Havoc, Sliver, Shad0w) require additional manual setup/build steps. Refer to their documentation."
    log_warn "The network setup section was commented out by default. Uncomment 'setup_network' in the script if needed."
    # log_warn "A reboot was previously included but is now commented out."
    # read -p "Press Enter to reboot, or Ctrl+C to cancel..."
    # sudo reboot
    log_info "-----------------------------------------------------"
}

# Run the main function
main

exit 0
