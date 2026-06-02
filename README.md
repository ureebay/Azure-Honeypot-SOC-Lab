# Azure Honeypot SOC Lab

> A home Security Operations Center built entirely in Microsoft Azure using a free-tier subscription.

---

## Overview

A Windows 10 virtual machine was intentionally exposed to the public internet as a honeypot with all firewalls disabled to attract real-world attackers. Failed login attempts were captured, forwarded to a central log repository, enriched with geographic data, and visualized on a live attack map inside Microsoft Sentinel.

---

## Architecture

Internet Attackers
       ↓
FINCORP-NET-EAST-1 (Windows 10 VM - Honeypot)
       ↓
Azure Monitor Agent
       ↓
LAW-soc-lab-0001 (Log Analytics Workspace)
       ↓
Microsoft Sentinel (SIEM)
       ↓
GeoIP Watchlist Enrichment
       ↓
Live Attack Map (Sentinel Workbook)

---

## Technologies Used

| Tool | Purpose |
|------|---------|
| Microsoft Azure | Cloud infrastructure hosting |
| Windows 10 VM | Honeypot exposed to internet |
| Network Security Group | Cloud firewall opened to all traffic |
| Log Analytics Workspace | Central log repository |
| Microsoft Sentinel | SIEM for querying and visualization |
| KQL | Querying security events |
| GeoIP Watchlist | Enriching IPs with location data |

---

## Steps

### 1. Create Resource Group
Created `RG-SOC-Lab` in East US 2 as a container for all lab resources.

### 2. Deploy Virtual Network
Deployed `Vnet-Soc-Lab` to provide network fabric for the honeypot VM.

### 3. Deploy Honeypot VM
Deployed a Windows 10 VM named `FINCORP-NET-EAST-1` with a public IP address. Hostname mimics a corporate financial server to attract targeted attackers.

### 4. Open the Network Security Group
Deleted the default RDP-only rule and created `DANGER-AllowAnyCustomAnyInbound` allowing all traffic from any source on any port. This is intentionally insecure and done only for lab purposes. Never do this in production.

### 5. Disable Windows Defender Firewall
Logged into the VM via RDP and disabled Windows Defender Firewall across all profiles (Domain, Private, Public) using `wf.msc`.

### 6. Verify Public Reachability
ping <VM_PUBLIC_IP>
Successful replies confirmed the VM is reachable from the public internet.

### 7. Deploy Log Analytics Workspace
Created `LAW-soc-lab-0001` inside `RG-SOC-Lab` as the central log repository.

### 8. Connect Sentinel and Install Windows Security Events Connector
Linked Sentinel to the Log Analytics Workspace, installed the Windows Security Events solution from Content Hub, and created a Data Collection Rule to forward all security events from the VM.

### 9. Query Security Events with KQL

SecurityEvent
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress

SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress, Activity

| Event ID | Meaning |
|----------|---------|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |
| 4672 | Special privileges assigned |
| 5379 | Credential Manager read |

### 10. Upload GeoIP Watchlist
Created a watchlist named `geoip` in Sentinel with approximately 55,000 records mapping IP blocks to city, country, latitude, and longitude.

_GetWatchlist("geoip")
| take 5

### 11. Enrich Logs with Geographic Data

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
| project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, latitude, longitude

### 12. Build the Attack Map

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")")

---

## Attack Map

Map will be updated after 24 hours of operation.

---

## Observations

- The VM was discovered and attacked within minutes of going live
- Majority of early traffic originated from Tambov, Russia with 248 failed login attempts
- Attackers used automated credential stuffing with common usernames
- NT AUTHORITY\SYSTEM events (4624, 4672) are benign Windows background processes and not attacker activity
- Real attacker events are identified by external IPs in 4625 records

---

## Cleanup

To avoid unexpected charges delete the RG-SOC-Lab resource group when done, deallocate the VM when not in use, and set a budget alert in Azure Cost Management. Estimated cost for 48 hours with Standard_DS1_v2 is approximately $3-5 USD.

---

## 🎯 Skills Demonstrated

- Microsoft Azure (resource groups, VNets, VMs, NSGs)
- Microsoft Sentinel (SIEM setup, data connectors, workbooks, watchlists)
- Log Analytics (KQL querying, SecurityEvent table, ipv4_lookup)
- Windows Security (Event IDs, firewall management, RDP)
- Threat intelligence (GeoIP enrichment, attacker IP analysis)
- SOC fundamentals (distinguishing real attacks from system noise)
