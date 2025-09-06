# Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate
## Project Overview

This project demonstrates a real-world SIEM implementation using Splunk Enterprise, Windows Event Logs, Sysmon, and FortiGate firewall logs.

We simulate an attacker (Kali Linux) brute-forcing a Windows domain, capture logs from the Domain Controller, Target endpoint, and Firewall, then forward them to Splunk for correlation, visualization, and alerts.

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

- Target + DC → Splunk (Windows Event Logs + Sysmon)

- Firewall → Splunk (syslog logs)

- Splunk → Security Analyst (dashboards + alerts)
