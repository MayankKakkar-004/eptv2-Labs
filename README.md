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
```
## Reference
  [Nmap Official Docs](https://nmap.org/)
## Host Discovery Lab using Nmap

This lab demonstrates how to perform host discovery on a network using **Nmap**. It focuses on identifying live hosts behind a firewall that may not respond to traditional ICMP ping requests.

##  Lab Steps Overview

1. **Ping the Target Host**
   ```bash
   ping -c 5 demo.ine.local
   ```
2. **Run Basic Nmap Scan**

```bash
  nmap demo.ine.local
```
3. **Use `-Pn` Option to Skip Host Discovery**

```bash
nmap -Pn demo.ine.local
```
4. **Scan Specific Port (e.g., 443)**

```bash
nmap -Pn -p 443 demo.ine.local
```
5. **Detect Application Version on Port 80**

```bash
nmap -Pn -sV -p 80 demo.ine.local
```
##  References

- [Nmap Official Documentation](https://nmap.org/)
- [Nmap Port Scanning Basics](https://nmap.org/book/man-port-scanning-basics.html)



