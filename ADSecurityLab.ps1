
<#
    File: ADSecurityLab.ps1
    Author: Sam Sanoop (@snoopysecurity)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>


function Create-AD {

<#
.SYNOPSIS
    Installs Active Directory Services and sets up a domain called adinsecurelab.local
 
.EXAMPLE
     Create-AD
 
.INPUTS
    None
 
.OUTPUTS
    None
 
.NOTES
    Author:  @snoopysecurity
#>


Write-Output "[+] Installing Windows AD Domain Services and setting up domain"
Install-WindowsFeature –Name AD-Domain-Services -IncludeManagementTools
Add-windowsfeature RSAT-ADDS
Import-Module ADDSDeployment

$netbiosName = "ADINSECURELAB"
$secpw = ConvertTo-SecureString "Password123" -AsPlainText -Force
$domainname = "adinsecurelab.local"

Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2012" -DomainName $domainname -DomainNetbiosName $netbiosName -ForestMode "Win2012" -InstallDns -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false  -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "Vagrant90" -Force) -SysvolPath "C:\Windows\SYSVOL" -Force:$tru


Write-Output "[+] Installing Windows AD Domain Services and setting up domain"
Write-Output "adinsecurelab.local created"
Write-Output "Please reboot, if not already your Domain Controller and login as the domain administrator and run setupscript2.ps1 as that use"

}

function Create-Domain-Data {

<#
.SYNOPSIS
    Create Users and set up Active Directory misconfigurations
 
.EXAMPLE
     Create-Domain-Data
 
.INPUTS
    None
 
.OUTPUTS
    None
 
.NOTES
    Author:  @snoopysecurity
#>

Write-Output "[+] Creating Users and setting up Active Directory misconfigurations"


Import-Module ActiveDirectory


New-ADOrganizationalUnit -Name "Managers" -Path "DC=adinsecurelab,DC=local"
NEW-ADGroup –name "Managers" –groupscope Global –path "OU=Managers,DC=adinsecurelab,DC=local"
New-ADUser -Name "Jack Robinson" -GivenName "Jack" -Surname "Robinson"  -Description "Samrobinson123" -SamAccountName "Jack.Robinson" -UserPrincipalName "J.Robinson@adinsecure.lab" -Path "OU=Managers,DC=adinsecurelab,DC=local" -AccountPassword (Convertto-SecureString -AsPlainText "Samrobinson123" -Force) -Enabled $true
New-ADUser -Name "Joe Standing" -GivenName "Joe" -Surname "Standing"  -Description "Execute Vice Preseident of Strategic Innovation, Holistic Integration and Corporate Development" -SamAccountName "Joe.Standing" -UserPrincipalName "J.Standing@adinsecure.lab" -Path "OU=Managers,DC=adinsecurelab,DC=local" -AccountPassword (Convertto-SecureString -AsPlainText "Executive12399$" -Force) -Enabled $true
Add-ADGroupMember -Identity Managers -Members Jack.Robinson,Joe.Standing
net group "Domain Admins" Joe.Standing /ADD /DOMAIN

New-ADOrganizationalUnit -Name "HR" -Path "DC=adinsecurelab,DC=local"
NEW-ADGroup –name "HR" –groupscope Global –path "OU=HR,DC=adinsecurelab,DC=local"
New-ADUser -Name "Katie Haggerty" -GivenName "Katie" -Surname "Haggerty"  -Description "HR Staff1" -SamAccountName "Katie.Haggerty" -UserPrincipalName "K.Haggerty@adinsecure.lab" -Path "OU=HR,DC=adinsecurelab,DC=local" -AccountPassword (Convertto-SecureString -AsPlainText "Str0ngPaSS67" -Force) -Enabled $true
New-ADUser -Name "Olivia Weidman" -GivenName "Olivia" -Surname "Weidman"  -Description "HR Staff1" -SamAccountName "Olivia.Weidman" -UserPrincipalName "O.Weidman@adinsecure.lab" -Path "OU=HR,DC=adinsecurelab,DC=local" -AccountPassword (Convertto-SecureString -AsPlainText "St4SDFxSS11434DF" -Force) -Enabled $true
Add-ADGroupMember -Identity HR -Members Olivia.Weidman,Katie.Haggerty



New-ADOrganizationalUnit -Name "Dev" -Path "DC=adinsecurelab,DC=local"
NEW-ADGroup –name "Dev" –groupscope Global –path "OU=Dev,DC=adinsecurelab,DC=local"
New-ADUser -Name "Rob Pratt" -GivenName "Robert" -Surname "Pratt"  -Description ".NET Contractor" -SamAccountName "Robert.Pratt" -UserPrincipalName "R.Pratt@adinsecure.lab" -Path "OU=Dev,DC=adinsecurelab,DC=local" -AccountPassword (Convertto-SecureString -AsPlainText "Password123" -Force) -Enabled $true
New-ADUser -Name "Pritesh Choudwory" -GivenName "Pritesh" -Surname "Choudwory"  -Description ".NET Contractor 2" -SamAccountName "Pritest.Choudwory" -UserPrincipalName "P.Choudwory@adinsecure.lab" -Path "OU=Dev,DC=adinsecurelab,DC=local" -AccountPassword (Convertto-SecureString -AsPlainText "PaSS12345678" -Force) -Enabled $true
Add-ADGroupMember -Identity Dev -Members Pritest.Choudwory,Robert.Pratt



Write-Output "[+] Creating Kerberoasting setup"
net localgroup administrators ADINSECURELAB\Robert.Pratt /add
setspn -s http/adinsecurelab.local:80 Robert.Pratt

Write-Output "[+] Enabling WinRM, if not already enabled and misconfiguring settings"
winrm quickconfig -transport:http -quiet -force
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{CredSSP="true"}'



Write-Output "[+] Disabling Windows Updates"
New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WindowsUpdate
New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AU
New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1


Write-Output "[+] Setting LocalAccountTokenFilterPolicy to 1"
Set-ItemProperty -Path 'HKLM:\SOFTWARE\microsoft\Windows\CurrentVersion\Policies\System\' -Name 'LocalAccountTokenFilterPolicy' -Value 1




Write-Output "[+] Creating ACL Vulnerabilities"
(Get-ADGroup -Identity Managers).ObjectGuid
√
$computer_schemaIDGUID = [guid] (Get-ADObject -SearchBase ($rootdse.schemaNamingContext) -LDAPFilter "(LDAPDisplayName=computer)" -Properties schemaIDGUID).schemaIDGUID
$ou = Get-ADOrganizationalUnit -Identity ("OU=Managers,$($rootdse.defaultNamingContext)")
$acl = Get-ACL "AD:\$ou"
$domname = ([ADSI]"").Name   
$who = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList "$domname", "Katie.Haggerty"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    $who,"WriteOwner","Allow"
$acl.AddAccessRule($ace)
Set-ACL "AD:\$ou" -AclObject $acl

$Sid = (Get-ADObject -Identity "CN=Robert Pratt,OU=Dev,DC=adinsecurelab,DC=local").ObjectGUID
$NewAccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, "WriteDacl", "Allow", "Domain Admins")
$Acl.AddAccessRule($NewAccessRule)
Set-ACL "AD:\$ou" -AclObject $acl


# Test with : Get-ObjectAcl -SamAccountName "Managers" -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "WriteOwner"}
# Get-ACL "AD:\OU=Managers,DC=adinsecurelab,DC=local").Access |
# Where-Object {$_.IdentityReference -eq "adinsecurelab\Katie.Haggerty"}  

Write-Output "[+] Creating Passwords in SYSVOL"

new-gpo -name MarketingGPO | new-gplink -target "OU=HR,DC=adinsecurelab,DC=local" | set-gppermissions -permissionlevel gpoedit -targetname "HR" -targettype group

Write-Output "net user /add Olivia.Weidman St4SDFxSS11434DF" > "C:\Windows\SYSVOL\sysvol\adinsecurelab.local\scripts\create_backupuser.ps1"

gpupdate

# Faking creation of Groups.xml since this cannot be done command line
$Groups_xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Katie.H_Backup" image="2" changed="2019-08-27 21:07:40" uid="{0BF14BE4-4AAD-44DD-933C-6DA54774FA2E}"><Properties action="U" newName="" fullName="Katie" description="Katie Backup Admin Account For Temp Use" cpassword="JCzwVAEdHyQeEAHXGNhtuSu9nOdiLr9x3kzmXGWd9xo" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="0" userName="Katie.Hagggerty"/></User>
</Groups>
"@
$groupspath = "C:\Windows\SYSVOL\sysvol\adinsecurelab.local\Policies\"
$filepath = Get-ChildItem "C:\Windows\SYSVOL\sysvol\adinsecurelab.local\Policies\"
$sysvolpath = $filepath.BaseName[1]
$filepath = "$groupspath$sysvolpath\"
mkdir "$filepath\MACHINE\Preferences\Groups\"
Write-Output "$Groups_xml"  > "$filepath\MACHINE\Preferences\Groups\Groups.xml"

echo "[+] Inserting password in registry"
Set-ItemProperty -Path HKLM:\SYSTEM\Setup -Name Pritesh -Value "PaSS12345678:UGFTUzEyMzQ1Njc4"


echo "[+] Enabling AlwaysInstallElevated registry key"

$objUser = New-Object System.Security.Principal.NTAccount("adinsecurelab.local", "Joe.Standing") 
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
$userSID = $strSID.Value
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer 
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 0x00000001 -Force
New-Item -Path HKU:\$userSID\SOFTWARE\Policies\Microsoft\Windows\Installer 
Set-ItemProperty -Path HKU:\$userSID\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 0x00000001 -Force

}
