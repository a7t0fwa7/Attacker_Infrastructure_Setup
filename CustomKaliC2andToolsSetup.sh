#!/bin/bash

# Create Static IPs in VM
sudo apt -y update
sudo apt -y install iptables-persistent netfilter-persistent python3-pip

sudo systemctl disable network-manager.service
echo -en "\n\nauto eth0\niface eth0 inet dhcp\nauto eth1\niface eth1 inet static\n\taddress 192.168.152.100\n\tnetmask 255.255.255.0" | sudo tee -a /etc/network/interfaces
sudo service networking restart

sudo sysctl -w net.ipv4.ip_forward=1

sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
sudo netfilter-persistent save
sudo systemctl enable netfilter-persistent.service

sudo sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g" /etc/sysctl.conf

#Install microsoft dotnet sdk 3.1
wget -q https://packages.microsoft.com/config/ubuntu/19.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt -y update
sudo apt -y install apt-transport-https
sudo apt -y update
sudo apt -y install dotnet-sdk-3.1
rm packages-microsoft-prod.deb

#Install Docker for Debian Buster and enable it (not opesec safe but practical for my usage)
sudo curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list 
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io -y 
#sudo systemctl start docker
sudo systemctl enable docker

#Create directories
sudo mkdir /opt/Intel-Tools
sudo mkdir /opt/Command-and-Control
sudo mkdir /opt/Reverse-Engineering
sudo mkdir /opt/Obfuscation-Tools
sudo mkdir /opt/Offensive-Tools
sudo mkdir /opt/AV-Evasion-Tools
sudo mkdir /opt/Useful-Lists

#Download and Install tools of the trade
sudo git clone https://github.com/danielmiessler/SecLists.git /opt/Useful-Lists/SecLists
sudo git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/Useful-Lists/PayloadsAllTheThings
sudo git clone https://github.com/rbsec/dnscan.git /opt/Intel-Tools/dnscan
sudo git clone https://github.com/chinarulezzz/spoofcheck /opt/Intel-Tools/spoofcheck; cd /opt/spoofcheck; sudo pip3 install -r requirements.txt
sudo git clone https://gist.github.com/superkojiman/11076951 /opt/namemash; sudo chmod +x /opt/namemash/namemash.py
sudo git clone https://github.com/byt3bl33d3r/SprayingToolkit.git /opt/SprayingToolkit; cd /opt/SprayingToolkit; sudo pip3 install -r requirements.txt
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
sudo gem install evil-winrm
# Install CrackMapExec for Kali
sudo apt install crackmapexec
#Install CME in Docker
sudo docker run -it --entrypoint=/bin/sh --name crackmapexec -v ~/.cme:/root/.cme byt3bl33d3r/crackmapexec
#After exiting your container, you can restart it using the following command:
#docker start crackmapexec
#docker exec -it crackmapexec sh


# Install Custom Covenant
sudo git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git /opt/Command-and-Control/Covenant

cd /opt/Covenant/Covenant/

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

sudo reboot
