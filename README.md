# SOC Homelab — AD, Splunk, Sysmon, Kali & FortiGate (Full Implementation)
## Project Overview

Build a compact, reproducible Security Operations lab for detection of Windows authentication attacks (brute force/password-spray) and endpoint activity using Splunk.
This project demonstrates a real-world SIEM implementation using Splunk Enterprise, Windows Event Logs, Sysmon, and FortiGate firewall logs.
What you’ll learn: Active Directory basics, Splunk ingestion and searches, Sysmon configuration, forwarding logs from Windows to Splunk, network log ingestion (FortiGate), attack simulation with Kali, building dashboards & alerts, troubleshooting.


The result: a hands-on lab showing how to detect and investigate brute-force attacks end-to-end.

## 🚀 Architecture
### Components

- 🖥 Attacker Machine (Kali Linux) → generates brute-force attempts.

- 🔥 FortiGate Firewall → filters traffic & forwards logs to Splunk.

- 🏰 Active Directory Domain Controller (WIN-DC01) → authentication service, logs security events (4624/4625).

- 💻 Target Windows Machine (Workstation) → endpoint under attack, running Sysmon.

- 📊 Splunk Enterprise Server → central log collector, dashboards, and alerting.

## Data Flow

- Attacker → Target (brute-force traffic)

- Target + DC + Standalone_PC→ Splunk (Windows Event Logs + Sysmon)

- Firewall → Splunk (syslog logs)

- Splunk → Security Analyst (dashboards + alerts)

## Objective & high-level design — (What & Why)

- What: I built a small lab: Windows Server 2022 as Active Directory Domain Controller (ADDC), a Windows 10 target workstation joined to the domain, Kali Linux as an attacker, Splunk Enterprise on Ubuntu as the SIEM and Windows Universal Forwarder (UF) + Sysmon on Windows to provide telemetry. FortiGate sends network logs to Splunk for correlation.

- Why: This replicates a small enterprise environment to:

- Generate attacker telemetry (failed logins, successes, suspicious process execution).

- Capture high-resolution endpoint events (Sysmon) and security events (Windows Security logs).

- Visualize and alert in Splunk, practice triage and response.

- Learn correlation of endpoint + network logs (Splunk + FortiGate).

| VM name     |                       OS | Role                                    | Primary logs                                  |     vCPU / RAM / Disk (recommended) |
| ----------- | -----------------------: | --------------------------------------- | --------------------------------------------- | ----------------------------------: |
| `SPLUNK`    |  Ubuntu Server 22.04 LTS | Splunk Enterprise (Indexer/Search Head) | All indexed logs (windows, sysmon, fortigate) | 4 vCPU / 8 GB RAM / 80+ GB disk |
| `ADDC01`    |      Windows Server 2022 | Active Directory Domain Controller      | Windows Security logs, AD events              | 2 vCPU / 8 GB RAM / 70 GB disk |
| `TARGET-PC` |            Windows 10/11 | Domain-joined workstation               | Windows Security logs, Sysmon logs            | 2 vCPU / 4 GB RAM / 60 GB disk |
| `KALI`      |               Kali Linux | Attacker (Hydra, other tools)           | n/a (attacker side)                           | 2 vCPU / 2 GB RAM / 20 GB disk |
| `FortiGate` | FortiGate VM             | Edge firewall                           | Syslog for traffic                            | hardware-varying |
| `Stand_alone_PC` | Windowa 10          | Test_Connectivity                       | Windows Security logs, Sysmon logs            | 2 vCPU / 4 GB RAM / 60 GB disk|


# Hyper-V & networking notes

I used a single NAT/bridged vSwitch (LabNAT) so VMs can talk to each other and the internet. If you want isolation, use multiple vSwitches with routing rules.

Snapshots / Checkpoints: Always create a checkpoint before major changes. Before expanding a VHDX you must delete/merge checkpoints or Hyper-V will not allow editing the disk.

Dynamic disks: When creating VMs, choose dynamically expanding VHDX to save host space. You can expand later via Hyper-V Manager → Edit Disk → Expand, then extend LVM inside the Linux VM if needed.

Enhanced session mode (host) allows clipboard / file transfer for Windows guests.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a4141b4945197f8e4e51039e6be43f6fbe823243/New%20folder%20(2)/Screenshot%202025-08-26%20123118.png)

Splunk Enterprise on Ubuntu (Detailed)
What & Why

Splunk acts as the central collector & analytics engine. We install Splunk Enterprise and open listening for forwarders (port 9997 default).

Install steps (concise)

Upload .deb to your Ubuntu Splunk VM (or wget from Splunk site).

Install:
