https://community.tenable.com/s/article/Troubleshooting-Credential-scanning-on-Windows

* * *
# Check Creds Work
- Credentials have admin rights if they can access C$ and ADMIN$ share, both required for Nessus to work 

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
# Check Local Security Policy 

Local Security Policy > Security Settings > Local Policies > Security Options > Network access: Sharing and security model for local accounts
- Should be set to Classic - local users authenticate as themselves 

* * *

# Set Windows Firewall Rules to allow Nessus (WMI-IN, 135,139,445) 

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
netsh advfirewall firewall delete rule name="Nessus_Allow_TCP_445_private_SMB_In" profile=private
```

* * *
# Enable LocalAccountTokenFilterPolicy
- Required if using a local adminisitrator account

#### Get LocalAccountTokenFilterPolicy. Enabled if set to 1 
```
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name "LocalAccountTokenFilterPolicy" | select LocalAccountTokenFilterPolicy
```
```
#### Enable LocalAccountTokenFilterPolicy by making a registry change to 1 
```
```
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name "LocalAccountTokenFilterPolicy" -Value 1
```

#### Disable LocalAccountTokenFilterPolicy by making a registry change to 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name "LocalAccountTokenFilterPolicy" -Value 0 

* * *
# Check/Enable/Disable Admin Shares
- Restart required after changing 
### Check if admin shares are enabled (AutoShareServer/AutoShareWorkstaiton)
```
Get-SmbServerConfiguration | select AutoShareServer,AutoShareWorkstation
```
```
### Enble AutoShareServer and AutoShareWorkstation

```
Set-SmbServerConfiguration -AutoShareServer $True -AutoShareWorkstation $True -Confirm:$false
```
### Disable AutoShareServer and AutoShareWorkstation 
```
Set-SmbServerConfiguration -AutoShareServer  $False -AutoShareWorkstation $False -Confirm:$false
```

* * *
# Check/Enable/Run Remote Registry and WMI 

### Check status of WMI and RemoteRegistry
```
Get-Service RemoteRegistry,Winmgmt | Select-Object -Property Name, StartType, Status
```
### Enable RemoteRegistry/WMI by changing status to Automatic startup type (required for Nessus, Manual works too)
```
Set-Service RemoteRegistry -StartupType Automatic -PassThru
Set-Service winmgmt -StartupType Automatic -PassThru
```

### Start Remote Registry/WMI 
```
Set-Service -Name RemoteRegistry -Status Running -PassThru
Set-Service -Name winmgmt -Status Running -PassThru
```
### Stop Remote Registry/WMI
```
Set-Service -Name RemoteRegistry -Status Stopped -PassThru
Set-Service -Name winmgmt -Status Stopped -PassThru
```

### Disable RemoteRegistry/WMI (careful - other services might rely on these, take note of current settings and ensure you set them back the way they were to ensure nothing breaks)
```
Set-Service RemoteRegistry -StartupType Disabled -PassThru
Set-Service winmgmt -StartupType Disabled -PassThru
```
* * *

# Check Registry/Confirm ForceGuest is not set to 1 

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
