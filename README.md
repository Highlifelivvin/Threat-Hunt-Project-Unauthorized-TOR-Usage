# Official Threat-Hunt-Project Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Highlifelivvin/Threat-Hunt-Project-Unauthorized-TOR-Usage/edit/main/README.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-11T04:46:48.4004333Z`. These events began at `2025-11-11T03:42:08.0794801Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "edr1"  
| where InitiatingProcessAccountName == "edr1"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-11-11T04:26:09.2989933Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1245" height="1017" alt="image" src="https://github.com/user-attachments/assets/24714dba-e32e-4baf-8ce1-5dc9aba4b5ce" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-11-11T04:27:05.4144994Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-15.0.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "edr1"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1277" height="302" alt="image" src="https://github.com/user-attachments/assets/aca14678-caaf-48b2-9a66-b6e8c36b5738" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "edr1" actually opened the TOR browser. There was evidence that they did open it at `2025-11-11T04:26:09.2989933Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "edr1"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1285" height="732" alt="image" src="https://github.com/user-attachments/assets/4e874a5a-f5a7-4f29-b666-91f7d4669c6b" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-11-11T04:27:05.4144994Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `37.120.176.133` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\edr1\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "edr1"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1256" height="380" alt="image" src="https://github.com/user-attachments/assets/b6946723-1fc2-44a4-9b75-80e0a5dd8c1d" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-11-11T04:26:09.2989933Z`
- **Event:** The user "edr1" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\edr1\Downloads\tor-browser-windows-x86_64-portable-15.0.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-11-11T04:27:05.4144994Z`
- **Event:** The user "edr1" executed the file `tor-browser-windows-x86_64-portable-15.0.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.exe /S`
- **File Path:** `C:\Users\edr1\Downloads\tor-browser-windows-x86_64-portable-15.0.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-11-11T04:33:21.9263523Z`
- **Event:** User "edr1" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\edr1\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-11-11T03:42:08.0794801Z`
- **Event:** A network connection to IP `37.120.176.133` on port `9001` by user "edr1" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\edr1\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-11-11T04:27:33Z` - Connected to `127.0.0.1:9150` on port `443`.
  - `2025-11-11T04:27:33Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-11-11T04:46:48.4004333Z`
- **Event:** The user "edr1" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\edr1\Desktop\tor-shopping-list.txt`

---

## Summary

The user "edr1" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `edr1` by the user `edr1`. The device was isolated, and the user's direct manager was notified.

---
