# Host Discovery Lab using Nmap

This lab demonstrates techniques to discover hosts behind a firewall using Nmap on a Kali Linux machine.

## Contents
- Basic ping test
- Nmap host discovery with `-Pn`
- Port scan and service version detection
- Understanding filtered ports

## Lab Commands Used
```bash
ping -c 5 demo.ine.local
nmap demo.ine.local
nmap -Pn demo.ine.local
nmap -Pn -p 443 demo.ine.local
nmap -Pn -sV -p 80 demo.ine.local

