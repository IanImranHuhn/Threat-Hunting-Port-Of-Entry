# Threat Hunt: Port of Entry

## INCIDENT RESPONSE REPORT

**Date of Report:** 2026-01-18  
**Severity Level:** ☑ CRITICAL  
**Report Status:** ☑ Contained  
**Escalated To:** Security Operations Team  
**Incident ID:** IR-2025-001  
**Analyst:** SOC Analyst  
**Affected Device:** azuki-sl  
**Incident Timeframe:** 2025-11-19 to 2025-11-20

---

## SUMMARY OF FINDINGS

* Unauthorized Remote Desktop Protocol (RDP) access from external IP address 88.97.178.12 to user account kenji.sato
* Attacker established persistence through scheduled task "Windows Update Check" executing malicious payload from C:\ProgramData\WindowsCache\svchost.exe
* Credential dumping performed using renamed mimikatz (mm.exe) with sekurlsa::logonpasswords module to extract passwords from LSASS memory
* Command and Control (C2) communication established with 78.141.196.6:443 using legitimate-looking svchost.exe process
* Data exfiltration of compressed archive (export-data.zip) to Discord cloud service
* Lateral movement attempted to internal system 10.1.0.188 using mstsc.exe with backdoor account "support" created for future access
* Windows Defender protections disabled through registry modifications excluding 3 file extensions and temporary folder path
* Anti-forensics techniques employed including clearing of Security event logs and use of living-off-the-land binaries (certutil.exe)

---

## WHO, WHAT, WHEN, WHERE, WHY, HOW

### WHO

**Attacker:**
* Source IP: 88.97.178.12
* C2 Infrastructure: 78.141.196.6:443

**Compromised:**
* Account: kenji.sato
* System: azuki-sl
* Created Backdoor Account: support

---

### WHAT

1. Initial RDP access from 88.97.178.12 using compromised credentials for kenji.sato
2. Network reconnaissance using ARP.EXE -a to enumerate network neighbors
3. Created hidden staging directory C:\ProgramData\WindowsCache using attrib command
4. Disabled Windows Defender by adding 3 file extension exclusions and excluded C:\Users\KENJI~1.SAT\AppData\Local\Temp from scanning
5. Downloaded malicious PowerShell script (wupdate.ps1) and tools using certutil.exe
6. Established persistence via scheduled task "Windows Update Check" executing C:\ProgramData\WindowsCache\svchost.exe
7. Deployed credential dumping tool (mm.exe) to extract logon passwords using sekurlsa::logonpasswords
8. Established C2 communication to 78.141.196.6 on port 443
9. Compressed stolen data into export-data.zip archive
10. Exfiltrated data via Discord cloud service
11. Created backdoor administrator account "support"
12. Cleared Security event logs using wevtutil.exe
13. Attempted lateral movement to 10.1.0.188 using mstsc.exe

---

### WHEN

| Date/Time (UTC) | Event |
|-----------------|-------|
| 2025-11-19 | Initial RDP access from 88.97.178.12 |
| 2025-11-19 | Network reconnaissance with ARP enumeration |
| 2025-11-19 | Staging directory creation and Windows Defender exclusions added |
| 2025-11-19 | Malicious tools downloaded using certutil.exe |
| 2025-11-19 | Scheduled task persistence established |
| 2025-11-19 | Credential dumping performed with mm.exe |
| 2025-11-19 | C2 connection established to 78.141.196.6:443 |
| 2025-11-19 | Data collection and compression |
| 2025-11-19 | Data exfiltration to Discord |
| 2025-11-19 | Backdoor account "support" created |
| 2025-11-19 | Security logs cleared |
| 2025-11-19 to 2025-11-20 | Lateral movement attempted to 10.1.0.188 |

---

### WHERE

**Compromised:** azuki-sl

**Infrastructure:**
* Attacker Source IP: 88.97.178.12
* C2 Server: 78.141.196.6:443
* Exfiltration Service: Discord (HTTPS)

**Malware Locations:**
* C:\ProgramData\WindowsCache\ (primary staging directory)
* C:\ProgramData\WindowsCache\svchost.exe (malicious persistence payload)
* C:\Users\KENJI~1.SAT\AppData\Local\Temp\ (excluded from scanning)
* C:\ProgramData\WindowsCache\mm.exe (credential dumping tool)
* C:\ProgramData\WindowsCache\export-data.zip (compressed data for exfiltration)
* wupdate.ps1 (initial PowerShell attack script)

---

### WHY

**Root Cause:**
* Compromised RDP credentials for user kenji.sato allowing direct external access
* Inadequate network segmentation allowing RDP exposure to public internet
* Lack of multi-factor authentication (MFA) on remote access

**Attacker Objective:**
* Credential theft and data exfiltration
* Establishing persistent access for future operations
* Lateral movement to additional internal systems

---

### HOW

1. **Initial Access:** Attacker authenticated via RDP from 88.97.178.12 using compromised credentials for kenji.sato account
2. **Discovery:** Executed ARP.EXE -a to enumerate network topology and identify lateral movement targets
3. **Defense Evasion:** Created hidden staging directory C:\ProgramData\WindowsCache and modified Windows Defender settings to exclude 3 file extensions and temporary folder path
4. **Execution:** Downloaded malicious PowerShell script wupdate.ps1 using certutil.exe to automate attack chain
5. **Persistence:** Created scheduled task "Windows Update Check" to execute C:\ProgramData\WindowsCache\svchost.exe on system startup
6. **Credential Access:** Deployed renamed mimikatz (mm.exe) and executed sekurlsa::logonpasswords to dump credentials from LSASS memory
7. **Command & Control:** Established outbound HTTPS connection to 78.141.196.6:443 using malicious svchost.exe process
8. **Collection:** Compressed stolen data into export-data.zip archive
9. **Exfiltration:** Uploaded export-data.zip to Discord cloud service via HTTPS
10. **Impact:** Created backdoor administrator account "support" for alternative access
11. **Anti-Forensics:** Cleared Security event logs using wevtutil.exe to remove evidence
12. **Lateral Movement:** Attempted to move laterally to 10.1.0.188 using mstsc.exe (Remote Desktop)

---

## IMPACT ASSESSMENT

**Actual Impact:**
* Credential compromise of kenji.sato account and potentially other accounts captured via mimikatz
* Data exfiltration of unknown scope via Discord (contents of export-data.zip)
* Persistent backdoor access established through scheduled task and "support" account
* Loss of forensic evidence due to Security log clearing
* Lateral movement capability demonstrated with targeting of 10.1.0.188
* Windows Defender protections disabled on compromised system

**Risk Level:** CRITICAL

---

## RECOMMENDATIONS

### IMMEDIATE

* Isolate azuki-sl from network and conduct full forensic imaging
* Block external IP 88.97.178.12 and C2 server 78.141.196.6 at perimeter firewall
* Disable and remove backdoor account "support" from all systems
* Force password reset for kenji.sato and all accounts on azuki-sl
* Remove scheduled task "Windows Update Check" and delete C:\ProgramData\WindowsCache directory
* Restore Windows Defender exclusions to default configuration
* Review and restore Security event logs from backup if available
* Monitor Discord traffic for ongoing exfiltration attempts
* Scan network for indicators of compromise on other systems

### SHORT-TERM (1-7 Days)

* Deploy endpoint detection and response (EDR) solution to azuki-sl and all critical systems
* Implement network segmentation to restrict RDP access from internet
* Enable multi-factor authentication (MFA) for all remote access services
* Conduct credential audit and force password resets for all privileged accounts
* Review and harden scheduled task permissions to prevent unauthorized creation
* Implement application whitelisting to block unauthorized executables
* Enable PowerShell logging and script block logging
* Deploy network monitoring for ARP scanning and reconnaissance activity
* Review firewall rules to block unauthorized outbound connections to cloud services
* Conduct compromise assessment on 10.1.0.188 and other systems in lateral movement path

### LONG-TERM

* Implement conditional access policies requiring MFA for all authentication
* Deploy privileged access management (PAM) solution
* Establish security baseline for Windows Defender configuration with monitoring for unauthorized changes
* Implement security information and event management (SIEM) with alerting for mimikatz indicators
* Conduct security awareness training focusing on credential protection
* Implement registry monitoring for defense evasion techniques
* Establish threat hunting program to proactively identify similar intrusions
* Review and update incident response procedures based on lessons learned
* Implement data loss prevention (DLP) controls for cloud service uploads
* Establish baseline for legitimate certutil.exe usage and alert on anomalies

---

## APPENDIX

### A. Indicators of Compromise

| Category | Indicator | Description |
|----------|-----------|-------------|
| Attacker IP | 88.97.178.12 | Source of initial RDP access |
| C2 Server | 78.141.196.6:443 | Command and control infrastructure |
| Malicious Files | C:\ProgramData\WindowsCache\svchost.exe | Persistence payload |
| Malicious Files | C:\ProgramData\WindowsCache\mm.exe | Credential dumping tool (mimikatz) |
| Malicious Files | wupdate.ps1 | PowerShell attack automation script |
| Malicious Files | C:\ProgramData\WindowsCache\export-data.zip | Compressed stolen data |
| Malicious Directory | C:\ProgramData\WindowsCache | Primary staging directory (hidden) |
| Scheduled Task | Windows Update Check | Persistence mechanism |
| Accounts | kenji.sato | Compromised user account |
| Accounts | support | Backdoor administrator account |
| Exfiltration Service | Discord | Cloud service used for data theft |

---

### B. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Remote Services: Remote Desktop Protocol | T1021.001 | RDP connection from 88.97.178.12 to kenji.sato account |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | wupdate.ps1 script execution |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | "Windows Update Check" task executing svchost.exe |
| Persistence | Create Account: Local Account | T1136.001 | Backdoor account "support" created |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Windows Defender exclusions added (3 extensions + temp folder) |
| Defense Evasion | Hide Artifacts: Hidden Files and Directories | T1564.001 | C:\ProgramData\WindowsCache hidden via attrib command |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | Security logs cleared with wevtutil.exe |
| Defense Evasion | System Binary Proxy Execution | T1218 | certutil.exe abused for file downloads |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | mm.exe (mimikatz) with sekurlsa::logonpasswords |
| Discovery | System Network Configuration Discovery | T1016 | ARP.EXE -a execution for network enumeration |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | mstsc.exe targeting 10.1.0.188 |
| Lateral Movement | Use Alternate Authentication Material | T1550 | Cmdkey credential caching for lateral movement |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | export-data.zip creation |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS C2 to 78.141.196.6:443 |
| Exfiltration | Exfiltration Over Web Service | T1567 | Discord used for data upload |

---

### C. Investigation Timeline

| Time (UTC) | Event | Details |
|------------|-------|---------|
| 2025-11-19 | RDP Logon Success | External IP 88.97.178.12 authenticated as kenji.sato |
| 2025-11-19 | Network Discovery | ARP.EXE -a executed to enumerate network neighbors |
| 2025-11-19 | Staging Directory Created | C:\ProgramData\WindowsCache created and hidden |
| 2025-11-19 | Defender Exclusions Added | 3 file extensions and temp folder excluded from scanning |
| 2025-11-19 | Tool Download | certutil.exe used to download wupdate.ps1 and other tools |
| 2025-11-19 | Scheduled Task Created | "Windows Update Check" task configured to run svchost.exe |
| 2025-11-19 | Credential Dumping | mm.exe executed with sekurlsa::logonpasswords |
| 2025-11-19 | C2 Connection | Outbound connection to 78.141.196.6:443 established |
| 2025-11-19 | Data Compression | export-data.zip archive created |
| 2025-11-19 | Data Exfiltration | Upload to Discord via HTTPS |
| 2025-11-19 | Backdoor Account | "support" account created and added to administrators |
| 2025-11-19 | Log Clearing | Security event log cleared first using wevtutil.exe |
| 2025-11-19 - 2025-11-20 | Lateral Movement | mstsc.exe and cmdkey used to target 10.1.0.188 |

---

### D. Investigation Queries

**Query 1: Initial Access - RDP Connection Analysis**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project RemoteIP, AccountName
```
**Result:** Identified external RDP access from 88.97.178.12 using account kenji.sato

---

**Query 2: Discovery - Network Reconnaissance**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where ProcessCommandLine contains "arp"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project ProcessCommandLine, TimeGenerated
| sort by TimeGenerated asc
| summarize count() by ProcessCommandLine
```
**Result:** ARP.EXE -a command executed for network neighbor enumeration

---

**Query 3: Defense Evasion - Staging Directory Creation**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "attrib"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project ProcessCommandLine
| summarize by ProcessCommandLine
```
**Result:** C:\ProgramData\WindowsCache created and hidden using attrib command

---

**Query 4: Defense Evasion - Defender Extension Exclusions**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey has_all ("Exclusions", "Extensions")
```
**Result:** 3 file extensions added to Windows Defender exclusions

---

**Query 5: Defense Evasion - Defender Path Exclusions**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Exclusions" and RegistryKey contains "Paths"
| where PreviousRegistryValueName contains "temp"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project PreviousRegistryValueName
```
**Result:** C:\Users\KENJI~1.SAT\AppData\Local\Temp excluded from scanning

---

**Query 6: Defense Evasion - Living Off The Land Binary Abuse**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where ProcessCommandLine contains "url"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| summarize count() by FileName
```
**Result:** certutil.exe abused for downloading malicious files

---

**Query 7: Persistence - Scheduled Task Creation**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where FileName has "schtasks.exe"
| where ProcessCommandLine contains "/create"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project ProcessCommandLine
```
**Result:** Scheduled task "Windows Update Check" created for persistence

---

**Query 8: Persistence - Scheduled Task Target**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where FileName has "schtasks.exe"
| where ProcessCommandLine contains "/tr"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project ProcessCommandLine
```
**Result:** Task configured to execute C:\ProgramData\WindowsCache\svchost.exe

---

**Query 9: Command & Control - C2 Server Identification**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine contains "url"
| where RemoteIPType == "Public"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project InitiatingProcessCommandLine, RemoteIP
```
**Result:** C2 connection to 78.141.196.6 identified

---

**Query 10: Command & Control - C2 Port Analysis**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where RemoteIP == "78.141.196.6" and InitiatingProcessFileName == "svchost.exe"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| summarize count() by RemotePort
```
**Result:** C2 communication on port 443 (HTTPS)

---

**Query 11: Credential Access - Credential Dumping Tool**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "dump"
| project ProcessCommandLine
```
**Result:** mm.exe (renamed mimikatz) identified

---

**Query 12: Credential Access - Memory Extraction Module**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains ">>" or ProcessCommandLine contains "::"
| project ProcessCommandLine
```
**Result:** sekurlsa::logonpasswords module used for credential extraction

---

**Query 13: Collection - Data Archive Creation**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains ".zip"
| project ProcessCommandLine
```
**Result:** export-data.zip created for exfiltration

---

**Query 14: Exfiltration - Cloud Service Identification**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIPType == "Public"
| where InitiatingProcessCommandLine contains "https"
| project RemoteUrl, InitiatingProcessCommandLine
```
**Result:** Discord identified as exfiltration channel

---

**Query 15: Anti-Forensics - Event Log Clearing**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "wevtutil.exe"
| project ProcessCommandLine, AccountDomain, TimeGenerated
| sort by TimeGenerated asc
```
**Result:** Security log cleared first using wevtutil.exe

---

**Query 16: Impact - Backdoor Account Creation**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/add" and ProcessCommandLine contains "admin"
| project ProcessCommandLine, TimeGenerated
```
**Result:** Backdoor account "support" created with administrator privileges

---

**Query 17: Execution - Malicious Script Identification**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine contains ".ps1" or InitiatingProcessCommandLine contains ".bat"
| where FolderPath contains "temp"
| where InitiatingProcessCommandLine contains "http"
| project InitiatingProcessCommandLine, TimeGenerated
| sort by TimeGenerated asc
```
**Result:** wupdate.ps1 PowerShell script downloaded to automate attack chain

---

**Query 18: Lateral Movement - Target Identification**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "cmdkey" or ProcessCommandLine contains "mstsc"
| project ProcessCommandLine
```
**Result:** 10.1.0.188 targeted for lateral movement

---

**Query 19: Lateral Movement - Remote Access Tool**
```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "10.1.0.188"
| project ProcessCommandLine, FileName
```
**Result:** mstsc.exe (Remote Desktop) used for lateral movement

---

**Query 20: Timeline Scoping**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
```
**Result:** All process events during incident timeframe for comprehensive analysis
