# Post Exploitation Resources

## Local Privilege Escalation

### Guides
* Linux
    * [g0tmi1k](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* Windows
    * [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html]) 

### Tools

* [WinPwn (S3cur3Th1sSh1t)](https://github.com/S3cur3Th1sSh1t/WinPwn)
* [PEAS (carlospolop)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)

#### Misc
* [pspy - linux process monitoring](https://github.com/DominicBreuker/pspy)
* [Windows File Type Manager](https://www.nirsoft.net/utils/file_types_manager.html)
* [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
    - alternatives: {hot,juicy}Potato, [RoguePotato](https://github.com/antonioCoco/RoguePotato), [SweetPotato](https://github.com/CCob/SweetPotato)
* [Hwacha (linux ssh swiss army knife)](https://github.com/n00py/Hwacha)
* [sshgobrute (static binary for ssh brute)](https://github.com/aldenso/sshgobrute)

#### Living Off the Land

* [Linux (gtfobins)](https://gtfobins.github.io/)
* [Windows (lolbas)](https://lolbas-project.github.io/)

### Leveraging Password Hashes

- [Practical Usage of NTLM Hashes](https://blog.ropnop.com/practical-usage-of-ntlm-hashes/)
- [Dumping Domain Password Hashes (pentestlab.blog)](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)


## Post Pivot Resources

> "A tarball containing a statically linked copy of nmap and all its scripts that you can upload and run on any box is very useful for this. The various nfs-* and especially smb-* scripts nmap has will be extremely useful." - Phineas Fisher

### Guides
* [practical guide to NTML relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
* [No PSExec Needed](https://www.trustedsec.com/june-2015/no_psexec_needed/)
* [pedantic guide to pivoting - part 1](https://www.jollyfrogs.com/jollyfrogs-pedantic-guide-to-pivoting-part-1-ssh-local-port-forwarding/)
* [Offensive Lateral Movement (SpecterOps)](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f)
* [WMI Persistence (fireeye)](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)

#### port forwarding / proxies

* [ssh remote/local](https://unix.stackexchange.com/questions/115897/whats-ssh-port-forwarding-and-whats-the-difference-between-ssh-local-and-remot)
* [Red Teamer's Pivoting Guide](https://artkond.com/2017/03/23/pivoting-guide/)
* [SCANNING EFFECTIVELY THROUGH A SOCKS PIVOT WITH NMAP AND PROXYCHAINS](https://cybersyndicates.com/2015/12/nmap-and-proxychains-scanning-through-a-socks-piviot/)
* [dynamic port forwarding](https://netsec.ws/?p=278)
* [nmap + tor + proxychains](https://www.shellhacks.com/anonymous-port-scanning-nmap-tor-proxychains/)

### Tips & Tricks

* [the-hackers-choice (thc) favourite tips, tricks, and hacks](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet)