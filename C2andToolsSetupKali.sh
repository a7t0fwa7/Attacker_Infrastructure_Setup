#!/bin/bash

# Create Static IPs in VM
sudo apt -y update
sudo apt -y install iptables-persistent netfilter-persistent python3-pip

sudo systemctl disable network-manager.service
echo -en "\n\nauto eth0\niface eth0 inet dhcp\nauto eth1\niface eth1 inet static\n\taddress 192.168.152.100\n\tnetmask 255.255.255.0" | sudo tee -a /etc/network/interfaces
sudo service networking restart

sudo sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g" /etc/sysctl.conf

sudo sysctl net.ipv4.ip_forward=1

#Forward Windows Traffic to Kali tun0 VPN tunnel
sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i eth1 -o tun0 -j ACCEPT
sudo netfilter-persistent save
sudo systemctl enable netfilter-persistent.service


# Check if command line tools are installed
  if [[ -x "$(command -v go)" ]]; then
    echo -e '[+] Go is installed.'
  else
    echo -e "[-] Go is not installed.\n[+] Installing Go..."
    # Install Package
    wget https://golang.org/dl/go1.18.1.linux-amd64.tar.gz /root/Downloads/
    tar -xvf go1.18.1.linux-amd64.tar.gz -C /usr/local
    chown -R root:root /usr/local/go

    #Add GOPATH to .profile
    echo "export GOPATH=$HOME/go" >> $HOME/.profile
    echo "export PATH=$PATH=$GOPATH/bin" >> $HOME/.profile
    # Reload .profile
    source ~/.profile
    
    # Add GOPATH to .bashrc
    echo "GOROOT=/usr/lib/go" >> $HOME/.zshrc
    echo "GOPATH=$HOME/go" >> $HOME/.zshrc
    echo "PATH=$GOPATH/bin:$GOROOT/bin:$PATH" >> $HOME/.zshrc
    # Reload .zshrc
    source ~/.zshrc
  fi


#Install microsoft dotnet sdk 3.1
wget -q https://packages.microsoft.com/config/ubuntu/19.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt -y update
sudo apt -y install apt-transport-https
sudo apt -y update
sudo apt -y install dotnet-sdk-3.1
rm packages-microsoft-prod.deb

# Install Mingw-w64
sudo apt install mingw-w64

#Install Docker for Debian Buster and enable it (not opesec safe but practical for my usage)
sudo curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list 
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io -y 
#sudo systemctl start docker
sudo systemctl enable docker

#Install MonoDevelop IDE
sudo apt install apt-transport-https dirmngr
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb https://download.mono-project.com/repo/debian vs-buster main" | sudo tee /etc/apt/sources.list.d/mono-official-vs.list
sudo apt update
sudo apt install monodevelop

# Install SMAP
go install -v github.com/s0md3v/smap/cmd/smap@latest

#Create directories
sudo mkdir /opt/Intel-Tools
sudo mkdir /opt/Command-and-Control
sudo mkdir /opt/Reverse-Engineering
sudo mkdir /opt/Obfuscation-Tools
sudo mkdir /opt/Offensive-Tools
sudo mkdir /opt/AV-Evasion-Tools
sudo mkdir /opt/Useful-Lists
sudo mkdir /opt/Cloud

#Download and Install tools of the trade
sudo git clone https://github.com/MrTuxx/SocialPwned.git /opt/Intel-Tools/SocialPwned
sudo git clone https://github.com/cmars/onionpipe.git /opt/Offensive-Tools/tunneling_onionpipe
sudo git clone https://github.com/irsdl/IIS-ShortName-Scanner.git /opt/Intel-Tools/IIS-ShortName-Scanner
sudo git clone https://github.com/v4d1/Dome.git /opt/Intel-Tools/SubDomainEnum_Dome
sudo git clone https://github.com/whydee86/ComPP.git /opt/Intel-Tools/Password_Gen_ComPP
sudo git clone https://github.com/Taonn/EmailAll.git /opt/Intel-Tools/EmailAll
sudo git clone https://github.com/fox-it/aclpwn.py.git /opt/Offensive-Tools/aclpwn
sudo git clone https://github.com/fox-it/Invoke-CredentialPhisher.git /opt/Offensive/Tools/Invoke-CredentialPhisher
sudo git clone https://github.com/xforcered/InlineExecute-Assembly.git /opt/Offensive-Tools/InlineExecute-Assembly
sudo git clone https://github.com/ORCA666/EVA2.git /opt/AV-Evasion-Tools/EVA2
sudo git clone https://github.com/N4kedTurtle/HellsGatePoC.git /opt/AV-Evasion-Tools/HellsGatePoC
sudo git clone https://github.com/3gstudent/Invoke-BuildAnonymousSMBServer.git /opt/Offensive-Tools/Invoke-BuildAnonymousSMBServer
sudo git clone https://github.com/BC-SECURITY/Offensive-VBA-and-XLS-Entanglement.git /opt/Offensive-Tools/Offensive-VBA-and-XLS-Entanglement
sudo git clone https://github.com/AnErrupTion/LoGiC.NET.git /opt/Obfuscation-Tools/LoGIC.NET
sudo git clone https://github.com/r00t-3xp10it/meterpeter.git /opt/Command-and-Control/Powershell-Meterpreter
sudo git clone https://github.com/GossiTheDog/HiveNightmare.git /opt/Offensive-Tools/HiveNightmare
sudo git clone https://github.com/Inf0secRabbit/BadAssMacros.git /opt/Offensive-Tools/BadAssMacros
sudo git clone https://github.com/d35ha/CallObfuscator.git /opt/Obfuscation-Tools/CallObfuscator
sudo git clone https://github.com/bats3c/ADCSPwn.git /opt/Offensive-Tools/ADCSPwn
sudo git clone https://github.com/ShutdownRepo/targetedKerberoast.git /opt/Offensive-Tools/targetedKerberoast
sudo git clone https://github.com/topotam/PetitPotam.git /opt/Offensive-Tools/PetitPotam
sudo git clone https://github.com/Flangvik/DeployPrinterNightmare.git /opt/Offensive-Tools/DeployPrintNightMare
sudo git clone https://github.com/two06/Inception.git /opt/AV-Evasion-Tools/Inception
sudo git clone https://github.com/cube0x0/MiniDump.git /opt/Offensive-Tools/MiniDump
sudo git clone https://github.com/xp4xbox/Python-Backdoor.git /opt/Command-and-Control/Python-Backdoor
sudo git clone https://github.com/xp4xbox/PyEvade.git /opt/Obfuscation-Tools/PyEvade
sudo git clone https://github.com/sevagas/macro_pack.git /opt/Offensive-Tools/Macro_Pack
sudo git clone https://github.com/ropnop/kerbrute.git /opt/Intel-Tools/kerbrute
sudo git clone https://github.com/danielmiessler/SecLists.git /opt/Useful-Lists/SecLists
sudo git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/Useful-Lists/PayloadsAllTheThings
sudo git clone https://github.com/rbsec/dnscan.git /opt/Intel-Tools/dnscan
sudo git clone https://github.com/chinarulezzz/spoofcheck /opt/Intel-Tools/spoofcheck; cd /opt/Intel-Tools/spoofcheck; sudo pip3 install -r requirements.txt
sudo git clone https://gist.github.com/superkojiman/11076951 /opt/namemash; sudo chmod +x /opt/namemash/namemash.py
sudo git clone https://github.com/byt3bl33d3r/SprayingToolkit.git /opt/Intel-Tools/SprayingToolkit; cd /opt/Inten-Tools/SprayingToolkit; sudo pip3 install -r requirements.txt
sudo git clone https://github.com/FortyNorthSecurity/Egress-Assess.git /opt/Egress-Assess
sudo git clone https://github.com/itm4n/PrivescCheck.git /opt/Intel-Tools/PrivescCheck
sudo git clone https://github.com/aloksaurabh/OffenPowerSh.git /opt/Offensive-Tools/OffenPowerSh
sudo git clone https://github.com/artofwar2306/Invoke-Recon.git /opt/Intel-Tools/Invoke-Recon
sudo git clone https://github.com/danielbohannon/Invoke-Obfuscation.git /opt/Obfuscation-Tools/Invoke-Obfuscation
sudo git clone https://github.com/CBHue/PyFuscation.git /opt/Obfuscation-Tools/PyFuscation
sudo git clone https://github.com/tokyoneon/Chimera.git /opt/Obfuscation-Tools/Chimera
sudo git clone https://github.com/S3cur3Th1sSh1t/WinPwn.git /opt/Offensive-Tools/WinPWn
sudo git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git /opt/Offensive-Tools/PowerSharpPack
sudo git clone https://github.com/S3cur3Th1sSh1t/MailSniper.git /opt/Intel-Tools/MailSniper
sudo git clone https://github.com/S3cur3Th1sSh1t/Creds.git /opt/Offensive-Tools/Creds
sudo git clone https://github.com/S3cur3Th1sSh1t/Invoke-PrintDemon.git /opt/Offensive-Tools/Invoke-PrintDemon
sudo git clone https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader.git /opt/Offensive-Tools/Invoke-SharpLoader
sudo git clone https://github.com/S3cur3Th1sSh1t/Invoke-Sharpcradle.git /opt/Offensive-Tools/Invoke-SharpCradle
sudo git clone https://github.com/S3cur3Th1sSh1t/Get-System-Techniques.git /opt/Offensive-Tools/Get-System-Techniques
sudo git clone https://github.com/S3cur3Th1sSh1t/SharpLocker.git /opt/Offensive-Tools/SharpLocker
sudo git clone https://github.com/S3cur3Th1sSh1t/xencrypt.git /opt/Obfuscation-Tools/xencrypt
sudo git clone https://github.com/Flangvik/SimpleSourceProtector.git /opt/Obfuscation-Tools/SimpleSourceProtector
sudo git clone https://github.com/SnaffCon/Snaffler.git /opt/Intel-Tools/Snaffler
sudo git clone https://github.com/Soledge/BlockEtw.git /opt/AV-Evasion-Tools/BlockEtw
sudo git clone https://github.com/jxy-s/herpaderping.git /opt/Offensive-Tools/herpaderping
sudo git clone https://github.com/bytecod3r/Cobaltstrike-Aggressor-Scripts-Collection.git /opt/Offensive-Tools/CobaltStrike-Agressor-Scripts-Collection
sudo git clone https://github.com/bats3c/darkarmour.git /opt/AV-Evasion-Tools/darkarmour
sudo git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git /opt/Offensive-Tools/WinAndLinPEAS
sudo git clone https://github.com/bitsadmin/wesng.git /opt/Offensive-Tools/WinExploitSuggestorNextGen
sudo git clone https://github.com/samratashok/ADModule.git /opt/Offensive-Tools/ADModule
sudo git clone https://github.com/dosxuz/DefenderStop.git /opt/AV-Evasion-Tools/DefenderStop
sudo git clone https://github.com/Ignitetechnologies/Credential-Dumping.git /opt/Offensive-Tools/CredDump


# Install Cloud Analysis tools
sudo git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation.git /opt/Cloud/GCP-IAM-Priv-Esc
sudo git clone https://github.com/RhinoSecurityLabs/CloudScraper.git /opt/Cloud/CloudScraper
sudo git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git /opt/Cloud/GCPBucketBrute
sudo git clone https://github.com/ZarvisD/Azure-AD.git /opt/Cloud/Azure-AD
sudo git clone https://github.com/nccgroup/PMapper.git /opt/Cloud/AWS_PMapper
sudo git clone https://github.com/nccgroup/ScoutSuite.git /opt/Cloud/MultiCloud_ScoutSuite
sudo git clone https://github.com/NetSPI/MicroBurst.git /opt/Cloud/Azure_MicroBurst
sudo git clone https://github.com/sa7mon/S3Scanner.git /opt/Cloud/AWS_S3Scanner
sudo git clone https://github.com/aquasecurity/cloudsploit.git /opt/Cloud/MultiCloud_CloudSploit
sudo git clone https://github.com/darkquasar/AzureHunter.git /opt/Cloud/Azure_Forensics_AzureHunter
sudo git clone https://github.com/TROUBLE-1/Vajra.git /opt/Cloud/Azure_Vajra_Attack_Framework
sudo git clone https://github.com/rkemery/bash-gcp-buckets-public.git /opt/Cloud/GCP_Enum_Buckets
sudo git clone https://github.com/RhinoSecurityLabs/pacu.git /opt/Cloud/AWS_Exploitation_Framework_Pacu
sudo git clone https://github.com/BishopFox/smogcloud.git /opt/Cloud/AWS_SmogCloud
sudo git clone https://github.com/accurics/terrascan.git /opt/Cloud/IaaC_TerraScan
sudo git clone https://github.com/FSecureLABS/leonidas.git /opt/Cloud/AWS_AttackSim_Framework_Leonidas



# Install BloodHound
sudo apt install bloodhound
# Install Custom Queries for BloodHound
#$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/customqueries.json"
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/ZephrFish/Bloodhound-CustomQueries/main/customqueries.json"

# Install ADalanche
sudo git clone https://github.com/lkarlslund/adalanche.git /opt/Intel-Tools/ActiveDirectoryAdalanche
cd adalanche
bash build.sh

#Download and install Obfuscated Mimikatz
curl -s https://gist.githubusercontent.com/a7t0fwa7/94591fe57d330cafbc89a349dc05c0e2/raw/dafbd32d1307c4ebb512e4eb7c43c7e1292bcac9/ObfuscateMimi_First.sh | bash

# Install Evil-WinRM
sudo gem install evil-winrm
# Install CrackMapExec for Kali
sudo apt install crackmapexec
#Install CME in Docker
#sudo docker run -it --entrypoint=/bin/sh --name crackmapexec -v ~/.cme:/root/.cme byt3bl33d3r/crackmapexec
#After exiting your container, you can restart it using the following command:
#docker start crackmapexec
#docker exec -it crackmapexec sh

# Download Sliver C2
sudo git clone https://github.com/BishopFox/sliver.git /opt/Command-and-Control/Sliver

# Download Mythic C2
sudo git clone git clone https://github.com/its-a-feature/Mythic /opt/Command-and-Control/Mythic

# Install Custom Covenant
sudo git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git /opt/Command-and-Control/CovenantModified
#sudo git clone --recurse-submodules https://github.com/cobbr/Covenant.git /opt/Command-and-Control/CovenantModified
cd /opt/Command-and-Control/CovenantModified/Covenant/

mv ./Data/AssemblyReferences/ ../AssemblyReferences/


mv ./Data/ReferenceSourceLibraries/ ../ReferenceSourceLibraries/

mv ./Data/EmbeddedResources/ ../EmbeddedResources/


mv ./Models/Covenant/ ./Models/Venom/
mv ./Components/CovenantUsers/ ./Components/VenomUsers/
mv ./Components/Grunts/ ./Components/Nagas/
mv ./Models/Grunts/ ./Models/Nagas/
mv ./Data/Grunt/GruntBridge/ ./Data/Grunt/NagaBridge/
mv ./Data/Grunt/GruntHTTP/ ./Data/Grunt/NagaHTTP/
mv ./Data/Grunt/GruntSMB/ ./Data/Grunt/NagaSMB/
mv ./Components/GruntTaskings/ ./Components/NagaTaskings/
mv ./Components/GruntTasks/ ./Components/NagaTasks/
mv ./Data/Grunt/ ./Data/Naga/



find ./ -type f -print0 | xargs -0 sed -i "s/Grunt/Naga/g"
find ./ -type f -print0 | xargs -0 sed -i "s/GRUNT/NAGA/g"
find ./ -type f -print0 | xargs -0 sed -i "s/grunt/naga/g"

#find ./ -type f -print0 | xargs -0 sed -i "s/covenant/easypeasy/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Covenant/Venom/g"
find ./ -type f -print0 | xargs -0 sed -i "s/COVENANT/VENOM/g"

find ./ -type f -print0 | xargs -0 sed -i "s/ExecuteStager/ExecNiveau/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/REPLACE_PROFILE/REP_PROF/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/REPLACE_PIPE/REP_PIP/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/GUID/ANGID/g"
find ./ -type f -print0 | xargs -0 sed -i "s/SetupAES/InstallerAES/g"
find ./ -type f -print0 | xargs -0 sed -i "s/SessionKey/CleSession/g"
find ./ -type f -print0 | xargs -0 sed -i "s/EncryptedChallenge/CryptageChallEnge/g"

find ./ -type f -print0 | xargs -0 sed -i "s/DecryptedChallenges/DecryptageDesChallenges/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Body/PremierBody/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Response/PremierResponse/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Bytes/PremierBytes/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Body/DeuxiemeBody/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Response/DeuxiemeResponse/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Bytes/DeuxiemeBytes/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Body/TroisiemeBody/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Response/TroisiemeResponse/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Bytes/TroisiemeBytes/g"
find ./ -type f -print0 | xargs -0 sed -i "s/message64str/MeSSaGe64str/g"
find ./ -type f -print0 | xargs -0 sed -i "s/messageBytes/MeSSaGebytes/g"

find ./ -type f -print0 | xargs -0 sed -i "s/totalReadBytes/ToTalReaDBytes/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/inputStream/instream/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/outputStream/outstream/g"
find ./ -type f -print0 | xargs -0 sed -i "s/deflateStream/deFlatEstream/g"
find ./ -type f -print0 | xargs -0 sed -i "s/memoryStream/memOrYstream/g"
find ./ -type f -print0 | xargs -0 sed -i "s/compressedBytes/comprimebytes/g"

find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/REPLACE_/REMPLACE_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/_PROFILE_/_PROFILAGE_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/_VALIDATE_/_VALIDER_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/GUID/AUTREID/g"
find ./ -type f -name "*.razor" -print0 | xargs -0 sed -i "s/GUID/AUTREID/g"
find ./ -type f -name "*.json" -print0 | xargs -0 sed -i "s/GUID/AUTREID/g"
find ./ -type f -name "*.yaml" -print0 | xargs -0 sed -i "s/GUID/AUTREID/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/guid/autreid/g"
find ./ -type f -name "*.razor" -print0 | xargs -0 sed -i "s/guid/autreid/g"
find ./ -type f -name "*.json" -print0 | xargs -0 sed -i "s/guid/autreid/g"
find ./ -type f -name "*.yaml" -print0 | xargs -0 sed -i "s/guid/autreid/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ProfileHttp/ProfilageHTTP/g"
find ./ -type f -print0 | xargs -0 sed -i "s/baseMessenger/bAsemEsSenGer/g"

find ./ -type f -print0 | xargs -0 sed -i "s/PartiallyDecrypted/decryptagePartiel/g"
find ./ -type f -print0 | xargs -0 sed -i "s/FullyDecrypted/decryptageComplet/g"
find ./ -type f -print0 | xargs -0 sed -i "s/compressedBytes/comprimebytes/g"

find ./ -type f -print0 | xargs -0 sed -i "s/CookieWebClient/NagasWebClient/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/CookieContainer/KekseContains/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/GetWebRequest/DoAnWebReq/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Jitter/JItTer/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ConnectAttempts/ConneCTAttEmpTs/g"
find ./ -type f -print0 | xargs -0 sed -i "s/RegisterBody/RegistreBody/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/messenger/MeSsenGer/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Hello World/Its me, nobody/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ValidateCert/ValiderLeCerTif/g"
find ./ -type f -print0 | xargs -0 sed -i "s/UseCertPinning/UtiliseCertPin/g"
find ./ -type f -print0 | xargs -0 sed -i "s/EncryptedMessage/MessageCrypte/g"
find ./ -type f -print0 | xargs -0 sed -i "s/cookieWebClient/nagaWebClient/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/aes/cryptvar/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/aes2/cryptvar2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array5/arr5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array6/arr6/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array4/arr4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array7/arr7/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array1/arr1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array2/arr2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array3/arr3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list1/li1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list2/li2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list3/li3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list4/li4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list5/li5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group0/grp0/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group1/grp1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group2/grp2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group3/grp3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group4/grp4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group5/grp5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group6/grp6/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group7/grp7/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group8/grp8/g"



find ./ -type f -name "*Grunt*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/Grunt/Naga/g")";
	mv "${FILE}" "${newfile}";
done
find ./ -type f -name "*GRUNT*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/GRUNT/NAGA/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*grunt*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/grunt/naga/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*Covenant*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/Covenant/Venom/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*COVENANT*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/COVENANT/VENOM/g")";
	mv "${FILE}" "${newfile}";
done

#find ./ -type f -name "*covenant*" | while read FILE ; do
#	newfile="$(echo ${FILE} |sed -e "s/covenant/ottocommand/g")";
#	mv "${FILE}" "${newfile}";
#done

mv ../AssemblyReferences/ ./Data/ 

mv ../ReferenceSourceLibraries/ ./Data/ 

mv ../EmbeddedResources/ ./Data/ 

dotnet build

# Build Shadow C2
sudo git clone --recurse-submodules https://github.com/bats3c/shad0w.git /opt/Command-and-Control/shad0w
cd shad0w
sudo ./shad0w install

sudo systemctl enable ssh.service

echo -en "\nDark Ops || Field-Operations\nred-team-ops\n\n" | sudo tee /etc/motd

sudo reboot
