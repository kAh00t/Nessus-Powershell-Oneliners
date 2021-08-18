Below is a list of powershell commands that can aid in diagnosing issues with Tenable Nessus Credential Patch Audit. 

Note: These commands will make changes to the local machine only, I understand that it is possible that if the device recieves a GPO update this will override the changes made. Keep this in mind! 

* * *
# IMPORTANT - Remember to take note of the original settings so you can clean up after yourself! #####
* * *

Common issues that these steps might help resolve:
- WMI Not Available 
- Authentication Failure - Local Checks Not Run 
- Nessus Windows Scan Not Performed with Admin Privileges (i.e. "It was not possible to connect to '\\MACHINENAME\ADMIN%' with the supplied credentials 

From what I can tell, TCP ports 135,139,445 and WMI-IN are required to be open for a scan to run successfully. 

Below is a guide that I have generally found useful, the steps from which have been used to build the following powershell commands.
https://community.tenable.com/s/article/Troubleshooting-Credential-scanning-on-Windows


1. The Windows Management Instrumentation (WMI) service must be enabled on the target. For more information, see https://technet.microsoft.com/en-us/library/cc180684.aspx
2. The Remote Registry service must be enabled on the target.
3. File & Printer Sharing must be enabled in the target's network configuration.
4. An SMB account must be used that has local administrator rights on the target.
    Note: A domain account can be used as long as that account is a local administrator on the devices being scanned.
5. TCP ports 139 and 445 must be open between the Nessus Scanner and the target.
6. Ensure that there are no security policies are in place that blocks access to these services. This includes:
        Windows Security Policies
        Antivirus or Endpoint Security rules
        IPS/IDS
7. The default administrative shares must be enabled.
  - These shares include:
    - IPC$
    - ADMIN$
    - C$
  - The setting that controls this is AutoShareServer which must be set to 1.
  - Windows 10 has the ADMIN$ disabled by default.
  - For all other OS's, these shares are enabled by default and can cause other issues if disabled. For more information, see http://support.microsoft.com/kb/842715/en-us

A general indicator that the patch audit ran correctly is the presence of "WMI Available" in the scan logs, and "Credentialed Checks : Yes" in Nessus Scan Information plugin output. 

* * *
# Scan to confirm ports are open before procedding
- Note - you will still need to ensure that WMI-In is allowed on the target device, so far as I know this can't be easily tested remotely and you will likely need to check the software firewall configuration, if not open use the powershell commands below or edit the Domain firewall by GPO. 

```
sudo nmap -sS -Pn -p 135,139,445 -iL <list of targets> 
```

* * *
# Check Admin Creds Work
- Credentials have admin rights if they can access C$ and ADMIN$ share, both required for Nessus to work 
- My testing indicates that you can use either:
  - Domain Admin account (in most situations
  - Local Administrator account (you will need to enable the LocalAccountTokenFilterPolicy i.e. set to 1, to use this account from a remote device) 
  - Domain User inside the Administrators group of each device you are scanning (handy if you have a limited scope to scan on a domain but don't want to use DA)
    

#### Check credentials are working from a Linux box 
```
smbclient //192.168.0.110/C$ -U 'DOMAIN\USERNAME' 'PASSWORD'
smbclient //192.168.0.110/IPC$ -U 'DOMAIN\USERNAME' 'PASSWORD'
smbclient //192.168.0.110/ADMIN$ -U 'DOMAIN\USERNAME' 'PASSWORD'
```

#### Check credentials are working from a Windows box 
```
net use \\192.168.0.110\admin$ "" /user:"USERNAME" "PASSWORD"
net use \\192.168.0.110\admin$ "" /user:"USERNAME" "PASSWORD"
net use \\192.168.0.110\admin$ "" /user:"USERNAME" "PASSWORD"
```

* * *

# Check Registry/Confirm ForceGuest is not set to 1 (Classic is required for Nessus seemingly) 

#### Check ForceGuest Value (and ensure it is not set to 1)
```
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "ForceGuest" | select ForceGuest
```

#### Set to "Classic"
```
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "ForceGuest" -Value 0 
```

#### Set to "Guest" 
```
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "ForceGuest" -Value 1
```
* * *

# Set Windows Firewall Rules to required to allow Nessus to perform a full credentialed scan (WMI-IN, 135,139,445) 

#### Add software firewall rules to allow Nessus Credentialed Scanning. Rules are named for ease of identification and removal. Double check no other explicit deny rules prevent these custom rules running. If you are on a domain/public profile you will need to change the "profile" bit. 

```
netsh advfirewall firewall add rule dir=in name ="Nessus_Allow_WMI-in_Private" program=%systemroot%\system32\svchost.exe service=winmgmt action = allow protocol=TCP localport=any profile=private
```
```
netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=135 name="Nessus_Allow_TCP_135_private_DCOM_In" profile=private
```
```
netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=139 name="Nessus_Allow_TCP_139_private_NB_Session_In" profile=private
```
```
netsh advfirewall firewall add rule dir=in action=allow protocol=TCP localport=445 name="Nessus_Allow_TCP_445_private_SMB_In" profile=private
```

#### Remove Custom Rules 
```
netsh advfirewall firewall delete rule name="Nessus_Allow_WMI-in_Private" profile=private
```
```
netsh advfirewall firewall delete rule name="Nessus_Allow_TCP_135_private_DCOM_In" profile=private
```
```
netsh advfirewall firewall delete rule name="Nessus_Allow_TCP_139_private_NB_Session_In" profile=private
```
```
netsh advfirewall firewall delete rule name="Nessus_Allow_TCP_445_private_SMB_In" profile=private
```

* * *
# Enable/Disable LocalAccountTokenFilterPolicy
- Required to be set to 1 (Disabled) if using a local adminisitrator account from a remote device, or a domain user in the local admins group. 
- Shouldn't be required if using a default administrator account (

#### Get LocalAccountTokenFilterPolicy. Disabled if set to 1 
```
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name "LocalAccountTokenFilterPolicy" | select LocalAccountTokenFilterPolicy
```


#### Disable LocalAccountTokenFilterPolicy by making a registry change to 1 
```
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name "LocalAccountTokenFilterPolicy" -Value 1
```

#### Enable LocalAccountTokenFilterPolicy by making a registry change to 0
```
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name "LocalAccountTokenFilterPolicy" -Value 0 
```

* * *

# Check/Enable/Disable Admin Shares
- Restart required for changes to take effect!  
- Disabled by default on modern Windows 10 versions to my understanding

### Check if admin shares are enabled (AutoShareServer/AutoShareWorkstaiton)
```
Get-SmbServerConfiguration | select AutoShareServer,AutoShareWorkstation
```
#### Enble AutoShareServer and AutoShareWorkstation
```
Set-SmbServerConfiguration -AutoShareServer $True -AutoShareWorkstation $True -Confirm:$false
```
#### Disable AutoShareServer and AutoShareWorkstation 
```
Set-SmbServerConfiguration -AutoShareServer  $False -AutoShareWorkstation $False -Confirm:$false
```

* * *
# Check/Enable/Run Remote Registry and WMI 
- Nessus will not scan correct if WMI or Remote Registry are not set to "Automatic" or "Manual". 
- You also need to ensure that the Remote Registry service is not set to "disabled", else Nessus will not be able to start the remote registry. 


#### Check status of WMI and RemoteRegistry
```
Get-Service RemoteRegistry,Winmgmt | Select-Object -Property Name, StartType, Status
```
#### Enable RemoteRegistry/WMI by changing status to Automatic startup type (required for Nessus, Manual works too)
```
Set-Service RemoteRegistry -StartupType Automatic -PassThru
Set-Service winmgmt -StartupType Automatic -PassThru
```

#### Start Remote Registry/WMI 
```
Set-Service -Name RemoteRegistry -Status Running -PassThru
Set-Service -Name winmgmt -Status Running -PassThru
```
#### Stop Remote Registry/WMI
```
Set-Service -Name RemoteRegistry -Status Stopped -PassThru
Set-Service -Name winmgmt -Status Stopped -PassThru
```

#### Disable RemoteRegistry/WMI (careful - other services might rely on these, take note of current settings and ensure you set them back the way they were to ensure nothing breaks)
```
Set-Service RemoteRegistry -StartupType Disabled -PassThru
Set-Service winmgmt -StartupType Disabled -PassThru
```

* * *

