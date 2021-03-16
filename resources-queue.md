# Tagged + Uncategorized

## Issue 7 - Feb 2021 pt3

### writeups

### tools
- [DoppleGate](https://github.com/asaurusrex/DoppelGate)
    - reading ntdll on disk to grab syscall stubs, and patches these syscall stubs into desired functions 
    - tags: windows, exploit, malwaredev, redteam
- [Mod_Rewrite_Automation](https://github.com/cedowens/Mod_Rewrite_Automation)
    - Scripts to automate standing up apache2 with mod_rewrite
    - tags: redteam
- [RunDLL.Net](https://github.com/p3nt4/RunDLL.Net)
    - Execute .NET assemblies using Rundll32.exe
    - tags: windows, exploit, malwaredev
- [AlternativeShellcodeExec](https://github.com/S4R1N/AlternativeShellcodeExec)
    - Alternative Shellcode Execution Via Callbacks
    - tags: exploit, windows, malwaredev

## Issue 7 - Feb 2021 pt3

### writeups
- [Relay Attacks via Cobalt Strike Beacons](https://pkb1s.github.io/Relay-attacks-via-Cobalt-Strike-beacons/)
    - tags: windows, exploit
- [Farmer for Red Teams: Harvesting NetNTLM (MDSEC)](https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/)
    - tags: windows, exploit
- [A Journey Combining Web Hacking and Binary Exploitation in Real World!](https://blog.orange.tw/2021/02/a-journey-combining-web-and-binary-exploitation.html)
    - PHPWind binary exploitation
    - tags: web, exploit
- [Unauthorized RCE in VMware vCenter (PT SWARM)](https://swarm.ptsecurity.com/unauth-rce-vmware/)
    - vcenter rce
    - tags: web, exploit
- [Coff Builder (trustedsec blog)](https://www.trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs/?utm_campaign=Blog%20Posts&utm_content=155025415&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306)
    - BOFs without Cobalt Strike
    - tags: windows, exploit, redteam
- [Lsass Memory Dumps Stealthier than Ever Before Pt2 (deepinstinct)](https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/)
    - tags: windows, post, redteam

### tools
- [CVE-2021-1727 PoC (klinix5)](https://github.com/klinix5/CVE-2021-1727)
    - warning: possibly backdoored
    - tags: windows, privesc
- [CVE-2021-1727 PoC (horizon3ai)](https://github.com/horizon3ai/CVE-2021-21972)
    - better
    - tags: windows, privesc
- [MaliciousClickOnceMSBuild](https://github.com/hausec/MaliciousClickOnceMSBuild)
    - C# automated ClickOnce builder using MSBuild as payload
    - tags: windows, exploit, phish
- [WinAPI-Tricks](https://github.com/vxunderground/WinAPI-Tricks)
    - Collection of WINAPI tricks used by malware
    - tags: windows, exploit, malwaredev
- [BadOutlook](https://github.com/S4R1N/BadOutlook)
    - Outlook Application Interface (COM Interface) execution
    - tags: windows, exploit, redteam
- [tinyPEgen](https://github.com/0xGilda/tinyPEgen)
    - webservice to create tiny windows dropper executables with arbitrary commands using http://winExecGen.py
    - tags: windows, exploit, redteam
- [Callback Shellcode Injection PoC Collection](https://github.com/ChaitanyaHaritash/Callback_Shellcode_Injection)
    - PoC shellcode injection via Callbacks
    - tags: windows, exploit
- [juicy_2 (decoder-it)](https://github.com/decoder-it/juicy_2)
    - tags: windows, post
- [cobalt_strike_extension_kit](https://github.com/josephkingstone/cobalt_strike_extension_kit)
    - All in one Agressor repo
    - tags: windows, redteam
- [AggressivbeGadgetToJScript](https://github.com/EncodeGroup/AggressiveGadgetToJScript)
    - Cobalt Strike GadgetToJScript Agressor script
    - tags: windows, exploit, redteam
- [Priv2Admin](https://github.com/gtworek/Priv2Admin)
    - Exploitation paths abusing Windows privs
    - tags: windows, exploit, privesc

## Issue 6 - Feb 2021 pt2

### writeups
- [One thousand and one ways to copy your shellcode to memory](https://adepts.of0x.cc/alternatives-copy-shellcode/)
    - tags: windows, exploit
- [Malware-Dev Course](https://silentbreaksecurity.com/training/malware-dev/)
    - tags: malwaredev
- [Laravel <= v8.4.2 debug mode: Remote code execution (ambionics.io)](https://www.ambionics.io/blog/laravel-debug-rce)
    - tags: web, exploit
- [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
    - related: https://github.com/visma-prodsec/confused
    - tags: web, exploit
- [Exploiting Out-of-Band XXE](https://dhiyaneshgeek.github.io/web/security/2021/02/19/exploiting-out-of-band-xxe/)
    - exploiting XXE out-of-band with DAV, LOCK methods
    - tags: web, exploit
- [What Should a Hacker Know about WebDav](https://www.slideshare.net/0ang3el/what-should-a-hacker-know-about-webdav)
    - tags: web, exploit
- [UsefulSources (malwarehenri)](https://github.com/malwarehenri/UsefulSources)
    - collection of interesting, malware related, resources
    - tags: malware, collection
- [Middleware Misconfigurations (detectify)](https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/)
    - nginx proxy misconfigurations
    - tags: web, exploit
- [Hijacking connections without injections: a ShadowMoving approach to the art of pivoting](https://adepts.of0x.cc/shadowmove-hijack-socket/)
    - 'ShadowMove' novel technique for alternative to process injection
    - tags: windows, post
- [Lone SharePoint](https://www.crummie5.club/the-lone-sharepoint/)
    - tags: windows, web, exploit
- [Hacking Chess.com (samcurry)](https://samcurry.net/hacking-chesscom/)
    - tags: web, exploit
- [Active C2 IOCs](https://github.com/carbonblack/active_c2_ioc_public)
    - tags: windows, redteam
- [The Anatomy of Deserialization Attacks](https://blog.cobalt.io/the-anatomy-of-deserialization-attacks-b90b56328766)
    - tags: web, exploit
- [OffSecOps Stage Two](https://blog.xenoscr.net/OffSecOps-Stage-Two/)
    - Offensive Pipeline Development
    - related: [OffSecOps Basic Setup](https://blog.xenoscr.net/OffSecOps-Basic-Setup/)
    - tags: windows, malwaredev

### tools
- [OffensivePipeline](https://github.com/Aetsu/OffensivePipeline)
    - tags: windows, devops
- [PEzor Custom Cobalt Strike Artifacts](https://iwantmore.pizza/posts/PEzor3.html)
    - tags: windows, redteam, malwaredev
- [SharpLAPS](https://github.com/swisskyrepo/SharpLAPS)
    - C# for Abusing LAPS
    - tags: windows, post
- [CIMplant (fortynorth)](https://github.com/FortyNorthSecurity/CIMplant)
    - C# port of WMImplant which uses either CIM or WMI to query remote systems
    - tags: windows, exploit
    - related: [CIMplant Part 1: Detection of a C# Implementation of WMImplant](https://fortynorthsecurity.com/blog/cimplant-part-1-detections/)
- [VBA-Macro-Projects](https://github.com/JohnWoodman/VBA-Macro-Projects)
    - Collection of malicious VBA projects
    - tags: windows, exploit, phish
- [SharpEDR](https://github.com/PwnDexter/SharpEDRChecker)
    - C# Port to enumerate EDR present on system
    - tags: windows, post
- [MimiDumpWriteDump BOF](https://github.com/rookuu/BOFs)
    - tags: windows, post
- [SharpSecDump](https://github.com/G0ldenGunSec/SharpSecDump)
    - .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py 
    - tags: windows, post
- [Mose](https://github.com/master-of-servers/mose)
    - Ansible/Puppet/Chef/Salt Post Exploitation Framework
    - tags: exploit, post
- [trigen](https://github.com/karttoon/trigen)
    - Trigen is a Python script which uses different combinations of Win32 function calls in generated VBA to execute shellcode. 
    - tags: windows, phish
- [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg/blob/master/README-en.md)
    - web shell proxy
    - tags: windows, exploit, post
- [RunasCs](https://github.com/antonioCoco/RunasCs)
    - impersonate user in a non-interactive environment
    - tags: windows, exploit, post
- [ThrowBack (silentbreaksec)](https://github.com/silentbreaksec/Throwback)
    - HTTP/S Beaconing Implant 
    - tags: windows, malwaredev
- [Mono](https://github.com/mono/mono)
    - Open Source ECMA CLI, C# and .NET Implementation
    - tags: windows, utilities
- [NTLMRecon](https://github.com/pwnfoo/NTLMRecon)
    - Enumerate information from NTLM authentication enabled web endpoints (OWA)
    - tags: windows, exploit, web, recon
- [LsassSilentProcessExit](https://github.com/deepinstinct/LsassSilentProcessExit)
    - Dump LSASS memory to disk via SilentProcessExit 
    - tags: windows, post

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