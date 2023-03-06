# Recon Resouces

## Guides
* [Enumeration (0daysecurity)](http://www.0daysecurity.com/penetration-testing/enumeration.html)
* [Asset Discovery - Doing Reconnaissance the Hard Way (Patrick Hudak)](https://0xpatrik.com/asset-discovery/)
* [How to Hunt](https://github.com/KathanP19/HowToHunt)
* [Just Another Recon Guide for Pentesters and Bug Bounty Hunters - Offensity](https://www.offensity.com/de/blog/just-another-recon-guide-pentesters-and-bug-bounty-hunters/)
* [Subdomain Enumeration - 0xpatrik](https://0xpatrik.com/subdomain-enumeration-2019/)

## Methodology
- [Bug Hunting Methodology (Pt 1) - Shankar](https://blog.usejournal.com/bug-hunting-methodology-part-1-91295b2d2066)
- [Bug Hunting Methodology (pt 2) - Shankar](https://blog.usejournal.com/bug-hunting-methodology-part-2-5579dac06150)
### NMAP
- [Nmap limit the scan rate for each host, without limiting the scan rate for the scan as a whole](https://github.com/nmap/nmap/issues/1360#issuecomment-431233462)
- [Nmap Firewall Evasion (infosecinstitute)](https://resources.infosecinstitute.com/nmap-evade-firewall-scripting/)

## Tools

### map
* [nmap](https://nmap.org/)
* [xmap](https://github.com/idealeer/xmap)
* [fi6s](https://github.com/sfan5/fi6s)
* [naabu](https://github.com/projectdiscovery/naabu)
* [RustScan](https://github.com/RustScan/RustScan)

### Call/Ping Back

Useful services for Out of Band exploitation.
1. Burp Collaborator
2. https://webhook.site
3. https://requestcatcher.com
4. https://canarytokens.org/generate
5. http://dnsbin.zhack.ca
6. https://ngrok.com

### DNS
* [rusolver](https://github.com/Edu4rdSHL/rusolver)
* [puredns](https://github.com/d3mondev/puredns)
* [wzrd python3 resolver](https://github.com/thelikes/wzrd/blob/master/dns/wzrd-resolve.py)
* [dnsx](https://github.com/projectdiscovery/dnsx)
* [dnsvalidator](https://github.com/vortexau/dnsvalidator)
* [altdns](https://github.com/infosec-au/altdns)
* [goaltdns](https://github.com/subfinder/goaltdns)
* [dnsgen](https://github.com/ProjectAnte/dnsgen)
* [projectdiscovery/asnmap](https://github.com/projectdiscovery/asnmap)

### Web
* [bluto](https://github.com/darryllane/Bluto)
* [SubDomainizer - search HTML for secrets](https://github.com/nsonaniya2010/SubDomainizer)
* [TurboL1ster - subl1ster+domaintakeover](https://github.com/fleetcaptain/Turbolist3r)
* [subl1ster](https://github.com/aboul3la/Sublist3r)
* [subfinder - subdomains scraper](https://github.com/subfinder/subfinder)
* [massdns](https://github.com/blechschmidt/massdns)
* [httprobe](https://github.com/tomnomnom/httprobe)
* [lazyrecon](https://github.com/nahamsec/lazyrecon)
* [dr. robot](https://github.com/sandialabs/dr_robot)
* [gowitness](https://github.com/sensepost/gowitness)
* [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)
* [github-search](https://github.com/gwen001/github-search)
* [rverton/webanalyze](https://github.com/rverton/webanalyze)
    - desc: Port of Wappalyzer (uncovers technologies used on websites) to automate mass scanning.
* [projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)
    - desc: A high performance go implementation of Wappalyzer Technology Detection Library
* [resyncgg/ripgen](https://github.com/resyncgg/ripgen/)
    - desc: Rust-based high performance domain permutation generator.
      
### OSINT
* [SpiderFoot](https://github.com/smicallef/spiderfoot)
* [ODIN](https://github.com/chrismaddalena/ODIN)
* [list of osint tools - darkweb](https://tomokodiscovery.com/free-tools-osint-socmint-dark-web-darknet-tor-bitcoin/)
* [dnstwist - twist domain name to generate phishing URLs](https://github.com/elceef/dnstwist)

### WAF
* [crimeflare - clouldflare origin search](http://www.crimeflare.biz:82/cfs.htm)
* [waf bypass dns history](https://github.com/vincentcox/bypass-firewalls-by-DNS-history)

### Amazon
* [s3 bucket finder](https://buckets.grayhatwarfare.com/)
* [sandcastle](https://github.com/0xSearches/sandcastle)
* [inSp3ctor](https://github.com/brianwarehime/inSp3ctor)
* [teh_s3_bucketeers](https://github.com/tomdev/teh_s3_bucketeers)
* [slurp](https://github.com/0xbharath/slurp)

### Search Engines
* [shodan](shodan.io)
* [censys](censys.io)
* [binaryedge](https://app.binaryedge.io/)
* [DNSGrep](https://github.com/erbbysam/DNSGrep)

### Content Discovery
* [LinkFinder](https://github.com/anshumanbh/LinkFinder)
* [HUNT](https://github.com/bugcrowd/HUNT)
* [JSParser](https://github.com/nahamsec/JSParser)
* [FFuF](https://github.com/ffuf/ffuf)
* [parameth](https://github.com/maK-/parameth)
* [photon](https://github.com/s0md3v/Photon)
* [recursive-gobuster](https://github.com/epi052/recursive-gobuster)

## Wordlists

### Tools
* [CommonSpeak - Wordlists Generation](https://github.com/pentester-io/commonspeak)
* [CommonSpeak2 - Wordlists Generation](https://github.com/assetnote/commonspeak2)
* [Assetnote Wordlists](https://wordlists.assetnote.io/)
* [fuzzdb](https://github.com/tennc/fuzzdb)
* [alert.js - tomnomnom ways to xss](https://gist.github.com/tomnomnom/14a918f707ef0685fdebd90545580309)
* [random-robbie/bruteforce-lists](https://github.com/random-robbie/bruteforce-lists)
* [the-xentropy/samlists](https://github.com/the-xentropy/samlists)

## Misc
* [FireProx - AWS Proxy for WAF Evasion](https://github.com/ustayready/fireprox)