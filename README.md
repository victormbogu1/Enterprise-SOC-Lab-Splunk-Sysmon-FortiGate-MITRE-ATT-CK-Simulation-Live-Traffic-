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


## Testing VM Machines, if they all reachable:
The Kali , Target, Domain and Splunk server all able to communicate together.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Confirm%20pinging.png)

# Configure and confirm if splung is working

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/095872da4a5fd5b88b16886796e37d01c40f4b5b/New%20folder%20(3)/Corming%20Symon%20installation.png)

# Configure my Kali Machine that will serve as attcking machine

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/095872da4a5fd5b88b16886796e37d01c40f4b5b/New%20folder%20(3)/Kali%20Machine.png)

Configure my Ubutun that server as Splunk server
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/095872da4a5fd5b88b16886796e37d01c40f4b5b/New%20folder%20(3)/SplunkIP.png)


# Hyper-V & networking notes

I used a single NAT/bridged vSwitch (LabNAT) so VMs can talk to each other and the internet. If you want isolation, use multiple vSwitches with routing rules.

Snapshots / Checkpoints: Always create a checkpoint before major changes. Before expanding a VHDX you must delete/merge checkpoints or Hyper-V will not allow editing the disk.

Dynamic disks: When creating VMs, choose dynamically expanding VHDX to save host space. You can expand later via Hyper-V Manager → Edit Disk → Expand, then extend LVM inside the Linux VM if needed.

Enhanced session mode (host) allows clipboard / file transfer for Windows guests.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a4141b4945197f8e4e51039e6be43f6fbe823243/New%20folder%20(2)/Screenshot%202025-08-26%20123118.png)


## Splunk Enterprise on Ubuntu (Detailed)
What & Why

Splunk acts as the central collector & analytics engine. We install Splunk Enterprise and open listening for forwarders (port 9997 default).


Upload .deb to your Ubuntu Splunk VM (or wget from Splunk site).

Install:
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Installing%20Splung.png)

Now able see splunk web interface on my broswer
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(3)/web%20interface.png)

# Disk issues & expansion (Linux LVM)
I ran into error because of disk space and i'd to fix it.

### Check current VG/LV
sudo lvdisplay
### Extend logical volume using free space
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
### Resize filesystem (ext4 example)
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
df -h

Confirm splung is listening - 9997

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Confirm%20listening%20port.png)


# Splunk Universal Forwarder on Windows — (Full explanation)
## What & Why

- UF is a light-weight Splunk agent that forwards Windows Event Logs and local files to the Splunk indexer.
- Provide receiving indexer IP: 192.168.10.60:9997.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Splunk%20forward%20events.png)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Config%20File.png)

Checked and Confirm splunk forwarder is running in Target and domain Pc
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Confirm%20splunk%20is%20running.png)

## Corming client is receiving data
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/39db47e2a10198db6f5f4e40744147f6a090cf03/New%20folder%20(3)/ConfirmingClient.png)

# Check if i can see my two host machine (DC & Target Machine)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/095872da4a5fd5b88b16886796e37d01c40f4b5b/New%20folder%20(3)/Two_Host.png)

## Key config files (where to put them & what they do)
Configure the forwaders on both the Target and DC.

- outputs.conf (Where does the UF send data)
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/output.png)

- inputs.conf (What logs to forward)
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/inputforward.png)


- Attack simulation with Kali (hydra) — do this only in your lab.
- I tested by acttacking the Target machine by brute forcing using the Hydra with serveral login attempt and successfull login which took place you can see it showned in the diagram

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Hydra%20to%20attack.png)

The below show the faied and successful logs in splunk 
Why: Generate failed & successful logons to see which events are generated and how Splunk detects them.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Count%20by%20Event_Host.png)

You can see the Attacker machine diplay event code 4625 which reconignises as failed attempt with ip 192.168.10.50 trying to login failed and this as showned over time because i tried severally 

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Attacker%20failed%204625.png)

The below shows Event code 4624 which indicate the attacker machine loged in successfully on Target machine

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Successful%20logon%20by%20the%20attacker.png)

Created a table which display high brute force attack coming from Kali Attacker Machine with IP 192.168.100.50, you can see the amount of brute force attcak that took place.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/show%20persistent%20log.png)


## Install via CLI - Fortinet FortiGate Add-on for Splunk and Extract it:

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/4030babe196167315aedc4024fecbbead56c4ca0/New%20folder%20(3)/Extract%20fortigate.png)

Couldn't find it in my app directory so I'd to cd /opt/splunk/etc/apps/ and copy extracted Fortinet Add-On folder into this directory - sudo cp -r ~/Downloads/TA-fortinet_fortigate /opt/splunk/etc/apps/

## Restart Splunk:

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/4030babe196167315aedc4024fecbbead56c4ca0/New%20folder%20(3)/Copy%20to%20splunk%20app.png)

Installing Atomic Red Team, Performing a Test, and Reviewing Events in Splunk Atomic Red Team is an open-source project that offers a collection of tests to simulate cyberattacks based on the MITRE ATT&CK framework. Before installing Atomic Red Team (ATR) on target_PC, I excluded the C: drive (where ATR will be installed) from Microsoft Defender Anti-Virus scans. Note: This exclusion is not recommended for normal circumstances. To allow PowerShell scripts to run without restrictions for the current user, I used the command: Set-ExecutionPolicy Bypass -Scope CurrentUser Next, I installed ATR using the following commands:

## Created Atomic folder in C:drive

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/e88c710edcb2a30cd86d7a37a3821bff3a40df40/New%20folder%20(3)/AtomicRed%20local%20folder.png)

Set Defender exclusion on C:\AtomicRedTeam.:

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/5ee5fdbebae56a714ad29efd5deaeedc17656481/New%20folder%20(4)/Screenshot%202025-08-29%20093808.png)

I'll be able to simulate attacks (Atomic Red Team), forward logs, and analyze them in Splunk just like a SOC would.
Allow PowerShell scripts to run Run this in PowerShell as Administrator and also run the the github script which puts the Atomic Red Team repo directly into the Atomic folder we created in the c:drive.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(3)/Git%20Clone.png)

Now we can view all the tests available in Atomic Red Team. Each test is named after the corresponding MITRE ATT&CK technique. For example, I ran the T1136.001 test, which corresponds to the "Create Account: Local Account" persistence technique in MITRE ATT&CK.
Run as Administrator on the Target_PC. Splunk Forwarder should automatically capture these events and send them to the Splunk server.
The following Windows Security events will be generated:

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/e88c710edcb2a30cd86d7a37a3821bff3a40df40/New%20folder%20(3)/Atomicred.png)

Created new user called Newlocaluser and a user called Crowr
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(3)/New%20local%20user%20created.png)

Local user -Newuser was removed 

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(3)/remove%20local%20user.png)

In splunk it shows the Newlocal user that was created in the client machine
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(3)/Newlocaluser%20MATT.png)

Shows the second uer created - Cowerr
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(3)/Coweruser.png)

Atomic red showing different activities taken place

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(4)/MATT%20logon.png)
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(4)/Matt%20user.png)

The diagram Shows user account was deleted theres been an intrusion which occured by the user

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(4)/Matt%20user2.png)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/5ee5fdbebae56a714ad29efd5deaeedc17656481/New%20folder%20(4)/Screenshot%202025-08-29%20122720.png)

## Results:
### EventCode	Description

4720	User account created
4722	User account enabled
4724	Password reset attempt
4726	User account deleted
4738	User account changed
4798	Local group membership enumerated

## Created a attble for it to visualise the attack
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(4)/Mittattack.png)

## Quick recap of what you accomplished:

- Created a local user (NewLocalUser) via PowerShell.

- Added the user to the Administrators group.

- Deleted the user after a few seconds.

- Splunk Forwarder on Target_PC collected the events.

- Splunk server indexed them and you confirmed the events appear.

- MITRE ATT&CK mapping is now visible for the simulated attack.

### Observed Outcome: 
- The user NewLocalUser was created, added to the Administrators group, and deleted as expected.
- Corresponding events were captured by Splunk and indexed in the endpoint index.
- Event codes aligned with MITRE ATT&CK T1136.001, demonstrating successful simulation and monitoring of the attack.

# FortiGate config
For me to integrate fortigate logs into splunk i had to configure the splunk network setting, i had to change the host to be on the same network so they can communicate together splunk previously 192.168.10.60 changes to 192.168.100.60

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Fortigate%20pinging%20splunk.png)

# After downloading fortigate add on, I'd Configure the syslog server Configure the syslog server Ensure syslog forwarding is enabled
config log syslogd setting
set status enable
set server 192.168.100.60
set mode udp
set port 514
set facility local7
set source-ip 192.168.100.1
end

Also did the configuration in the fortigate web interface 

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/8100ef16e67c1acd4af128d0b34e078f2c6f26ef/New%20folder%20(4)/configuring%20syslog%20on%20fortigate.png)

I confirmed the Fortigate Add on, if is showing in splunk  
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/e88c710edcb2a30cd86d7a37a3821bff3a40df40/New%20folder%20(3)/Confirm%20Fortigate%20add%20on%20isinstalled.png)

Enable logging for different events For example, enable logging for traffic, security, and VPN events:

config log setting
set fwpolicy-implicit-log enable
set local-in-allow enable
end

After this, syslog logging is configured, and logs will be sent to Splunk (assuming UDP 514 is reachable).

# Next was to set up Splunk to ingest FortiGate logs via UDP 514. You’ll need to create or edit an inputs.conf in the Fortinet Add-On and after that restart splunk:

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/335ad021691b935952bb8ee38538d7430d619cb6/New%20folder%20(3)/inputsconf%20for%20fortigate.png)

Verify if firewall policy is been configured or applied
Testpc-firewall → policy ID 2
LAN-to-WAN → policy ID 1

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/56e7298a5a59c4df0ef22288e6d6bf3b9b541cb5/New%20folder%20(3)/show%20is%20enable.png)

## Enable traffic logging for the policy so web filter events are generated and forwarded to Splunk.

config firewall policy
edit 2
set logtraffic all
next
edit 1
set logtraffic all
next
end

Notes:
set logtraffic all logs all traffic matched by this policy, including web filter blocks.

You see all logs displayed including the webfiltering 

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/8100ef16e67c1acd4af128d0b34e078f2c6f26ef/New%20folder%20(4)/log%20types%20(traffic%2C%20VPN%2C%20virus%2C%20etc.)..png)

Fortigate showing in splunk

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(3)/firewal.png)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Screenshot%202025-09-03%20203209.png)

showing the Test Machine IP address

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Logs%20from%20web.png)

Generate a test log to verify fortigate logs is sent to splunk 
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/56e7298a5a59c4df0ef22288e6d6bf3b9b541cb5/New%20folder%20(3)/firewall%20sending%20log.png)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Screenshot%202025-09-03%20223140.png)

Showing the webfilering working blocked the web application that are not needed

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/main/New%20folder%20(4)/Screenshot%202025-09-06%20212541.png)




