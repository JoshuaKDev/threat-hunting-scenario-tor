# Microsoft Defender Threat Hunt: Unauthorized TOR Usage

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

This project was conducted in a controlled lab environment based on the Josh Madakor Cyber Range.

> **Note:** The VM was originally named `JKVMedr`, but Microsoft Defender telemetry normalized the hostname to lowercase (`jkvmedr`) in log events.

- [Scenario Creation](https://github.com/JoshuaKDev/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

---

## Platforms and Technologies Leveraged

- Microsoft Azure Virtual Machines
- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- Windows 11
- TOR Browser

---

## Scenario

Management suspected that employees may have been using TOR Browser to bypass organizational network controls after unusual encrypted traffic patterns and connections to known TOR entry nodes were observed in network telemetry. Additional anonymous reports suggested employees were discussing methods to access restricted websites during work hours.

The objective of this threat hunt was to identify evidence of TOR installation or usage, determine the scope of activity, and recommend response actions if unauthorized usage was confirmed.

---

## Why TOR Usage Matters

Unauthorized TOR usage may allow users to bypass organizational monitoring controls, evade web filtering policies, and establish anonymous outbound communications that reduce defender visibility.

---

## High-Level TOR IoC Discovery Plan

- Investigate `DeviceFileEvents` for TOR-related file activity
- Investigate `DeviceProcessEvents` for installation or execution behavior
- Investigate `DeviceNetworkEvents` for TOR-related network connections
- Correlate file, process, and network telemetry to confirm usage

---

# Investigation Steps

## 1. Investigated `DeviceFileEvents` for TOR-Related File Activity

Investigated `DeviceFileEvents` for TOR-related file activity associated with endpoint `jkvmedr`. Results confirmed that the user account `joshlab` downloaded a TOR installer and generated multiple TOR-related files on the system.

Additional file creation activity included a file named `tor-shopping-list.txt` on the desktop.

### Findings

- TOR installer downloaded to the endpoint
- Multiple TOR-related files written to disk
- TOR-related text artifact created on the desktop

### KQL Query

```kql
DeviceFileEvents
| where DeviceName == "jkvmedr"
| where InitiatingProcessAccountName == "joshlab"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-08-20T22:14:48.6065231Z)
| order by Timestamp desc
| project Timestamp,
          DeviceName,
          ActionType,
          FileName,
          FolderPath,
          SHA256,
          Account = InitiatingProcessAccountName
```

<img width="1998" height="1244" alt="TOR File Activity" src="https://github.com/user-attachments/assets/0b6e1461-dbe5-4f80-b12c-a32df97d82f6" />

*Figure 1: TOR installer download and TOR-related file creation activity observed in `DeviceFileEvents`.*

---

## 2. Investigated `DeviceProcessEvents` for TOR Installer Execution

Investigated `DeviceProcessEvents` for evidence of TOR installer execution. Results confirmed that the user account `joshlab` executed the TOR installer from the Downloads directory on endpoint `jkvmedr`.

The installer executed in silent mode, reducing user-facing prompts and visibility during installation.

### Findings

- TOR installer execution confirmed
- Silent installation behavior observed
- Installation initiated from the Downloads folder
- Activity consistent with unauthorized software installation

### KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "jkvmedr"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"
| project Timestamp,
          DeviceName,
          AccountName,
          ActionType,
          FileName,
          FolderPath,
          SHA256,
          ProcessCommandLine
```

<img width="1996" height="950" alt="TOR Installer Execution" src="https://github.com/user-attachments/assets/857539c5-f6d7-4f9d-acc7-28db4ccb0175" />

*Figure 2: Silent TOR installer execution detected in `DeviceProcessEvents`.*

---

## 3. Investigated `DeviceProcessEvents` for TOR Browser Execution

Investigated `DeviceProcessEvents` for evidence of active TOR Browser execution. Results confirmed that the user account `joshlab` launched the TOR Browser successfully.

Additional `firefox.exe` and `tor.exe` child processes were observed following execution, confirming active TOR Browser usage.

### Findings

- TOR Browser launch confirmed
- `firefox.exe` and `tor.exe` processes observed
- Multiple TOR-related child processes spawned
- Active TOR usage confirmed on endpoint

### KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "jkvmedr"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp,
          DeviceName,
          AccountName,
          ActionType,
          FileName,
          FolderPath,
          SHA256,
          ProcessCommandLine
| order by Timestamp desc
```

<img width="2022" height="1244" alt="TOR Browser Execution" src="https://github.com/user-attachments/assets/e4840d07-1fc7-4da5-8acc-d053f6992f75" />

*Figure 3: TOR-related process execution observed, including `firefox.exe` and `tor.exe`.*

---

## 4. Investigated `DeviceNetworkEvents` for TOR Network Connections

Investigated `DeviceNetworkEvents` for evidence of TOR-related network communication over known TOR ports.

Results confirmed that the endpoint established outbound connections associated with TOR infrastructure. A successful connection to remote IP `176.198.159.33` over port `9001` was observed, initiated by `tor.exe`.

Additional encrypted outbound connections over port `443` and localhost communication over port `9150` were also identified.

### Findings

- TOR network communication confirmed
- Outbound connection to known TOR-related port `9001`
- Additional encrypted outbound traffic observed
- Local TOR proxy communication over port `9150` observed

### KQL Query

```kql
DeviceNetworkEvents
| where DeviceName == "jkvmedr"
| where InitiatingProcessAccountName == "joshlab"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp,
          DeviceName,
          InitiatingProcessAccountName,
          ActionType,
          RemoteIP,
          RemotePort,
          RemoteUrl,
          InitiatingProcessFileName,
          InitiatingProcessFolderPath
| order by Timestamp desc
```

<img width="2022" height="1244" alt="TOR Network Connections" src="https://github.com/user-attachments/assets/7204eb63-6921-4de8-9414-652c45b7030a" />

*Figure 4: TOR-related outbound network communication observed in `DeviceNetworkEvents`.*

---

## Chronological Event Timeline

### 1. TOR Installer Download

- **Timestamp:** `2026-08-20T22:14:48.6065231Z`
- **Event:** User account `joshlab` downloaded the TOR installer to the Downloads directory.
- **Action:** File download detected
- **File Path:** `C:\Users\joshlab\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

---

### 2. TOR Installer Execution

- **Timestamp:** `2026-08-20T22:16:47.4484567Z`
- **Event:** User account `joshlab` executed the TOR installer in silent mode.
- **Action:** Process creation detected
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\joshlab\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

---

### 3. TOR Browser Launch

- **Timestamp:** `2026-08-20T22:17:21.6357935Z`
- **Event:** TOR Browser launched successfully on endpoint `jkvmedr`.
- **Action:** TOR-related process execution detected
- **Processes Observed:** `firefox.exe`, `tor.exe`
- **File Path:** `C:\Users\joshlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 4. TOR Network Connection Established

- **Timestamp:** `2026-08-20T22:18:01.1246358Z`
- **Event:** Outbound TOR network connection established to remote IP `176.198.159.33` over port `9001`.
- **Action:** Successful network connection detected
- **Process:** `tor.exe`
- **File Path:** `C:\Users\joshlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 5. Additional TOR Network Activity

- **Timestamp:** `2026-08-20T22:18:08Z`
- **Event:** Additional encrypted outbound connection established over port `443`.

- **Timestamp:** `2026-08-20T22:18:16Z`
- **Event:** Localhost communication established over port `9150`.

- **Action:** Multiple TOR-related network connections detected

---

### 6. TOR-Related File Creation

- **Timestamp:** `2026-08-20T22:27:19.7259964Z`
- **Event:** User account `joshlab` created the file `tor-shopping-list.txt` on the desktop.
- **Action:** File creation detected
- **File Path:** `C:\Users\joshlab\Desktop\tor-shopping-list.txt`

---

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Proxy: Multi-hop Proxy | T1090.003 |
| Ingress Tool Transfer | T1105 |
| Command and Scripting Interpreter | T1059 |
| Masquerading | T1036 |

---

## Detection Opportunities

The following detection improvements could help identify similar activity earlier in the future:

- Create Microsoft Defender custom detection rules for TOR-related process execution
- Alert on outbound connections to known TOR ports
- Monitor for silent installer execution behavior
- Block unauthorized privacy tools through application control policies
- Create watchlists for known TOR infrastructure IP addresses

---

## Summary

The investigation confirmed unauthorized TOR Browser installation and usage on endpoint `jkvmedr`. Evidence included installer downloads, silent process execution, TOR-related child processes, and outbound network connections associated with known TOR infrastructure.

The observed activity demonstrated an attempt to establish anonymous outbound communications capable of bypassing organizational monitoring and acceptable-use policies.

---

## Response Taken

- Endpoint isolated from the network
- TOR-related binaries identified for removal
- User activity escalated to management
- Recommended review of application control policies
- Recommended review of web filtering controls
- Suggested continued monitoring for repeat behavior

---

## Skills Demonstrated

- Threat Hunting
- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- Endpoint Telemetry Analysis
- Process Investigation
- Network Connection Analysis
- IOC Identification
- MITRE ATT&CK Mapping
- Incident Documentation

---

## Lessons Learned

This investigation reinforced the importance of correlating file, process, and network telemetry when validating suspicious activity. It also demonstrated how privacy-focused applications such as TOR can be identified through behavioral indicators even when encrypted traffic is present.
