# Tagged + Uncategorized

## Issue 5 - Feb 2021 pt1

### writeups
- [Blind SSRF Chains (assetnote)](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)
    - tags: web, exploit
- [The Secret Parameter - LFR & Potential RCE in NodeJS Apps](https://blog.shoebpatel.com/2021/01/23/The-Secret-Parameter-LFR-and-Potential-RCE-in-NodeJS-Apps/)
    - tags: web, exploit
- [Relaying 101 (Luemmelsec)](https://luemmelsec.github.io/Relaying-101/)
    - tags: windows, exploit
- [MSBuild without MSBuild](https://www.trustedsec.com/blog/msbuild-a-profitable-sidekick/)
    - tags: windows, exploit
- [Some Ways to Dump Lsass](https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf)
    - tags: windows, post
- [Malicious VBA Macros Trials and Tribulations](https://john-woodman.com/research/malicious-vba-macros-trials-tribulations/)
    - tags: windows, phish
- [One thousand and one ways to copy your shellcode to memory](https://adepts.of0x.cc/alternatives-copy-shellcode/)
    - tags: windows, exploit
- [Malware-Dev Course](https://silentbreaksecurity.com/training/malware-dev/)
- [Laravel <= v8.4.2 debug mode: Remote code execution (ambionics.io)](https://www.ambionics.io/blog/laravel-debug-rce)
    - tags: web, exploit

### tools
- [ComputerDefaults.exe UAC Bypass](https://github.com/0xyg3n/UAC_Exploit)
    - tags:F windows, post
- [RedTeamCCode (Mr-Un1c0d3r)](https://github.com/Mr-Un1k0d3r/RedTeamCCode)
    - tags: windows, exploit, post
- [ScareCrow](https://github.com/optiv/ScareCrow)
    - tags: windows, exploit, redteam
- [microsubs](https://github.com/codingo/microsubs)
    - Collection for interacting with API sources for recon
    - tags: web, recon
- [link (rust-based c2)](https://github.com/postrequest/link/)
    - tags: windows, post, future
- [Dumping Lsass with MiniDumpWriteDump](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass)
    - tags: windows, post
- [physmem2profit (minidump of a target hosts' LSASS process by analysing physical memory remotely )](https://github.com/FSecureLABS/physmem2profit)
    - tags: windows, post
- [OffensivePipeline](https://github.com/Aetsu/OffensivePipeline)
    - tags: windows, devops

## Issue 4 - Jan 2021 pt3
- [VBA-Macro-Reverse-Shell](https://github.com/JohnWoodman/VBA-Macro-Reverse-Shell)
    - pure VBA rev shell, no shellcode injection or powershell
    - tags: windows, exploit, phish
- [Enemies Of Symfony (EOS)](https://github.com/synacktiv/eos)
    - Enemies Of Symfony - Debug mode Symfony looter 
    - tags: web, exploit
- [SpooNmap (trustedsec)](https://github.com/trustedsec/spoonmap)
    - IDS-evading nmap wrapper written in python3
    - related: [https://www.trustedsec.com/blog/get-to-hacking-massively-faster-the-release-of-spoonmap/](https://www.trustedsec.com/blog/get-to-hacking-massively-faster-the-release-of-spoonmap/)
    - tags: enumeration, recon

## Issue 3 - Jan 2021 pt2
- [NetNTLMtoSilverTicket](https://github.com/NotMedic/NetNTLMtoSilverTicket)
    - SpoolSample -> Responder w/NetNTLM Downgrade -> NetNTLMv1 -> NTLM -> Kerberos Silver Ticket
    - tags: windows, post
- [emp3r0r](https://github.com/jm33-m0/emp3r0r)
    - linux post-exploitation framework made by linux user 
    - tags: linux, post
- [SprayKatz](https://github.com/aas-n/spraykatz)
    - Credentials gathering tool automating remote procdump and parse of lsass process.
    - tags: windows, post
- [burp-piper-custom-scripts](https://github.com/righettod/burp-piper-custom-scripts)
    - Custom scripts for the PIPER Burp extensions. 
    - tags: web, tools
- [muraena](https://github.com/muraenateam/muraena)
    - an almost-transparent reverse proxy aimed at automating phishing and post-phishing activities
    - tags: utilities
- [BOFs (ajpc500)](https://github.com/ajpc500/BOFs)
    - Collection of Beacon Object Files 
    - tags: cstrike
- [RogueWinRm (antonioCoco)](https://github.com/antonioCoco/RogueWinRM)
    -  Windows Local Privilege Escalation from Service Account to System. Use if WinRM service is not running (default on Win10 but NOT on Windows Server 2019).
    - tags: windows, post
- [CS-Situational-Awareness-BOF (trustedsec)](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
    - Situational Awareness commands implemented using Beacon Object Files
    - tags: cstrike
- [terraform-phishing (boh)](https://github.com/boh/terraform-phishing)
    - Build a phishing server (Gophish) together with SMTP-redirector (Postfix) automatically in Digital Ocean with terraform and ansible.. 
    - tags: initial compromise, phishing, infra
- [Red-Terroir](https://github.com/b3n-j4m1n/Red-Terroir)
    - Terraform resources for building HTTP, DNS, phishing, and mail server red team infrastructure 
    - tags: initial compromise, phishing, infra
- [SharpShares](https://github.com/mez-0/SharpShares)
    - .NET 4.0 Share Hunting and ACL Mapping 
    - tags: windows, post
- [UltimateWDACBypassList](https://github.com/bohops/UltimateWDACBypassList)
    - A centralized resource for previously documented WDAC bypass techniques 
    - tags: windows, post
    - Related: https://swapcontext.blogspot.com/2020/10/uacme-35-wd-and-ways-of-mitigation.html
    - Related: https://swapcontext.blogspot.com/2020/11/uac-bypasses-from-comautoapprovallist.html
- [Using a C# shellcode runner and confuserex to Bypass uac while evading av](https://hausec.com/2020/10/30/using-a-c-shellcode-runner-and-confuserex-to-bypass-uac-while-evading-av/)
    - tags: windows, post
- [SharpClipHistory](https://github.com/FSecureLABS/SharpClipHistory)
    - C# program used to read contents of a user's clipboard starting from Win 10 1809 build
    - tags: windows, post

## Issue 2 - Jan 2021 pt1
- (SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
    - AV/EDR evasion via direct system calls
- [Red Team Tactics: Utilizing Syscalls in C# - Writing The Code](https://jhalon.github.io/utilizing-syscalls-in-csharp-2/)
- [CrackQ](https://github.com/f0cker/crackq)
    - Web GUI & API for queuing hashcat jobs
- [SharpHandler](https://github.com/jfmaes/SharpHandler)
    - Reuses open handles to lsass to parse or minidump lsass
- [wraith](https://github.com/N0MoreSecr3ts/wraith)
    - Digital Secret finder in golang
- [burp-send-to](https://github.com/bytebutcher/burp-send-to)
    - Customizable 'Send to' context menu
- [New year, new anti-debug: Don't Thread On Me](https://secret.club/2021/01/04/thread-stuff.html)
    - Windows, debugging

## Issue 1 - Dec 2020
- [Purgalicious VBA](https://www.fireeye.com/blog/threat-research/2020/11/purgalicious-vba-macro-obfuscation-with-vba-purging.html) - inverse VBA stomping for Office maldocs
- [netbiosX/Checklists - RedTeam & PenTest Checklists (mostly outdated)](https://github.com/netbiosX/Checklists)
- [sshgobrute - golang ssh brute](https://github.com/aldenso/sshgobrute)
- [FireEye's Red Team Tools - TTPs (PICUS)](https://www.picussecurity.com/resource/blog/techniques-tactics-procedures-utilized-by-fireeye-red-team-tools)
- [DecryptAutoLogon (securesean)](https://github.com/securesean/DecryptAutoLogon) - cobaltstrike autologon extractor
- [Word Doc Video Embed EXE PoC (rvrsh3ll)](https://github.com/rvrsh3ll/Word-Doc-Video-Embed-EXE-POC)
- [NoMSBuild (rvrsh3ll)](https://github.com/rvrsh3ll/NoMSBuild)
    - D/Invoke MSbuild alternative - sleek
- [SharpZipRunner](https://github.com/jfmaes/SharpZipRunner)
    - Executes position independent shellcode from an encrypted zip 
- [SharPyShell](https://github.com/antonioCoco/SharPyShell)
    -  AV-evading asp shell used in SolarWinds breach
- [Direct Sys Calls in Beacon Object Files (BOF)](https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/)