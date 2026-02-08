# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

> **Defensive Security Notice**  
> This content is for defensive security research, detection engineering, and threat-hunting education only.  
> It documents simulated adversary activity for the purpose of generating logs and indicators of compromise (IoCs).

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: `hxxps://www[.]torproject[.]org/download/`
2. Install it silently: `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites.
   - Current Dread Forum: `g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd[.]onion`
   - Dark Markets Forum: `g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd[.]onion/d/DarkNetMarkets`
   - Current Elysium Market: `hxxps://elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad[.]top/login`
   - **It's possible the onion link for Dread Forum has changed; updated references can be found via public reporting sources**
6. Create a folder on your desktop called `tor-shopping-list.txt` and put a few fake (simulated illicit) items in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter** | **Description** |
|---|---|
| **Name** | DeviceFileEvents |
| **Info** | `hxxps://learn[.]microsoft[.]com/en-us/defender-xdr/advanced-hunting-deviceinfo-table` |
| **Purpose** | Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter** | **Description** |
|---|---|
| **Name** | DeviceProcessEvents |
| **Info** | `hxxps://learn[.]microsoft[.]com/en-us/defender-xdr/advanced-hunting-deviceinfo-table` |
| **Purpose** | Used to detect the silent installation of TOR as well as the TOR browser and service launching. |

| **Parameter** | **Description** |
|---|---|
| **Name** | DeviceNetworkEvents |
| **Info** | `hxxps://learn[.]microsoft[.]com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table` |
| **Purpose** | Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports commonly associated with TOR (9001, 9030, 9040, 9050, 9051, 9150). |

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where DeviceName == "donnytorbrowser"
| where FileName startswith "tor"

// TOR Browser being silently installed
// Note: double space before /S observed in command line
DeviceProcessEvents
| where DeviceName == "donnytorbrowser"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where DeviceName == "donnytorbrowser"
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where DeviceName == "donnytorbrowser"
| where ProcessCommandLine has_any ("tor.exe","firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where DeviceName == "donnytorbrowser"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
