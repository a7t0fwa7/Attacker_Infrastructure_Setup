# Kali Install

Just Git clone it and install on Kali
```
curl -sS https://raw.githubusercontent.com/a7t0fwa7/Attack_Infra_Setup/main/CustomKaliC2andToolsSetup.sh | sudo bash -

```

# Windows Install

On the Windows VM, open a PowerShell prompt as Administrator and run:
1) ```PS C:\Windows\system32> Set-ExecutionPolicy Unrestricted```

2) ```PS > . { Invoke-WebRequest -useb https://boxstarter.org/bootstrapper.ps1 } | iex; Get-Boxstarter -Force```

Once the installation has completed, a Boxstarter Shell icon will appear on your desktop.  Launch the Boxstarter Shell and enter the following commands:
```
$Cred = Get-Credential $env:USERNAME
Install-BoxstarterPackage -PackageName https://raw.githubusercontent.com/artofwar2306/RTOVMSetup/master/setup -Credential $Cred
```
Once the Boxstarter packages have been installed, install the three Visual Studio applications in your Downloads folder.  When installing Visual Studio Community edition, select the .NET and C++ Desktop Development Environments from the main Workloads menu, then find and select the Windows XP v141 tools from the Individual components menu.

Then perform one final manual reboot.
