#!/bin/bash
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

wget -q https://packages.microsoft.com/config/ubuntu/19.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt -y update
sudo apt -y install apt-transport-https
sudo apt -y update
sudo apt -y install dotnet-sdk-3.1
rm packages-microsoft-prod.deb

sudo git clone https://github.com/rbsec/dnscan.git /opt/dnscan
sudo git clone https://github.com/chinarulezzz/spoofcheck /opt/spoofcheck; cd /opt/spoofcheck; sudo pip3 install -r requirements.txt
sudo git clone https://gist.github.com/superkojiman/11076951 /opt/namemash; sudo chmod +x /opt/namemash/namemash.py
sudo git clone https://github.com/byt3bl33d3r/SprayingToolkit.git /opt/SprayingToolkit; cd /opt/SprayingToolkit; sudo pip3 install -r requirements.txt
sudo git clone https://github.com/FortyNorthSecurity/Egress-Assess.git /opt/Egress-Assess
sudo git clone https://github.com/itm4n/PrivescCheck.git /opt/PrivescCheck
sudo git clone https://github.com/aloksaurabh/OffenPowerSh.git /opt/OffenPowerSh
sudo git clone https://github.com/artofwar2306/Invoke-Recon.git /opt/Invoke-Recon
sudo git clone https://github.com/danielbohannon/Invoke-Obfuscation.git /opt/Invoke-Obfuscation
sudo git clone https://github.com/CBHue/PyFuscation.git /opt/PyFuscation
sudo git clone https://github.com/tokyoneon/Chimera.git /opt/Chimera
sudo git clone https://github.com/S3cur3Th1sSh1t/WinPwn.git /opt/WinPWn
sudo git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git /opt/PowerSharpPack
sudo git clone https://github.com/S3cur3Th1sSh1t/MailSniper.git /opt/MailSniper
sudo git clone https://github.com/S3cur3Th1sSh1t/Creds.git /opt/Creds
sudo git clone https://github.com/S3cur3Th1sSh1t/Invoke-PrintDemon.git /opt/Invoke-PrintDemon
sudo git clone https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader.git /opt/Invoke-SharpLoader
sudo git clone https://github.com/S3cur3Th1sSh1t/Invoke-Sharpcradle.git /opt/Invoke-SharpCradle
sudo git clone https://github.com/S3cur3Th1sSh1t/Get-System-Techniques.git /opt/Get-System-Techniques
sudo git clone https://github.com/S3cur3Th1sSh1t/SharpLocker.git /opt/SharpLocker
sudo git clone https://github.com/S3cur3Th1sSh1t/xencrypt.git /opt/xencrypt
sudo git clone https://github.com/Flangvik/SimpleSourceProtector.git /opt/SimpleSourceProtector
sudo git clone https://github.com/SnaffCon/Snaffler.git /opt/Snaffler
sudo git clone https://github.com/Soledge/BlockEtw.git /opt/BlockEtw
sudo git clone https://github.com/jxy-s/herpaderping.git /opt/herpaderping
sudo git clone https://github.com/bytecod3r/Cobaltstrike-Aggressor-Scripts-Collection.git /opt/CobaltStrike-Agressor-Scripts-Collection
sudo git clone https://github.com/bats3c/darkarmour.git /opt/darkarmour
sudo git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git /opt/WinAndLinPEAS
sudo git clone https://github.com/bitsadmin/wesng.git /opt/WinExploitSuggestorNextGen
sudo git clone https://github.com/samratashok/ADModule.git /opt/ADModule
sudo gem install evil-winrm

sudo git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git /opt/Covenant

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

sudo systemctl enable ssh.service

sudo reboot
