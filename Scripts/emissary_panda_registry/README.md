# EMISSARY PANDA Registry Search

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Tom Henry <cirt@nccgroup.com>

http://www.github.com/nccgroup/Cyber-Defence

This project is released under the AGPL license.  Please see LICENSE for more information.

## Synopsis

Search your registry for keys created by EMISSARY PANDA and decrypt their contents

## Usage
```
usage: ep_registrysearch.py [-h] [-l] [-f FILE]

optional arguments:
  -h, --help            show this help message and exit
  -l, --local           This option searches the local registry
  -f FILE, --file FILE  This option searches the provided SOFTWARE file
```

## Output
```
[i] Searching the provided registry file - SOFTWARE

[i] Found the following values in:
[-] Classes\VMware Virtual Platform-HjDWr6vsJqfYb89mxxxx

[+] PE: INISafeWebSSO.exe
[+] Dll: inicore_v2.3.30.dll
[+] Bin: sys.bin.url
[+] Path: C:\ProgramData\systemconfig\
[+] Process: svchost.exe
[+] Serv: systemconfig
[+] ServDis: for systemconfig
[+] OnlineHelp: 103.59.144.183:443;
[+] Periodic: 0:1
[+] Group: Default
[+] GUID: 26FB46A0E3834984
[+] Console: helen
[+] MD5: HjDWr6vsJqfYb89mxxxx
```
