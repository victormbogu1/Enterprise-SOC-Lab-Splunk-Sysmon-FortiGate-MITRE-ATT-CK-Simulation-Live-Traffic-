# 🛡️ SOC Homelab — Windows AD, Splunk, Sysmon, Kali & FortiGate (End-to-End Implementation with MITRE ATT&CK)

## Project Overview

This project is all about building a hands-on Security Operations Center (SOC) homelab where I simulate real-world attacks, collect logs, and analyze them inside Splunk.

The idea was to replicate a mini-enterprise environment:

I set up:  
- **Windows Server 2022** (Active Directory Domain Controller)  
- **Windows 10 workstation** (joined to the domain)  
- **Splunk Enterprise on Ubuntu** (SIEM)  
- **Sysmon + Universal Forwarder** on endpoints for telemetry  
- **FortiGate Firewall** forwarding logs to Splunk  
- **Kali Linux attacker** generating brute-force & MITRE ATT&CK simulation attacks  
The result: a hands-on lab showing how to detect and investigate brute-force attacks end-to-end.

The **goal** was to:  
- Detect brute-force authentication attempts  
- Capture process and endpoint telemetry with Sysmon  
- Collect firewall traffic logs (FortiGate)  
- Simulate adversary behaviors using **Atomic Red Team**  
- Build Splunk **dashboards + alerts** for detection and investigation

👉 By the end, I had a fully working SOC lab that detects failed logons, successful brute force, suspicious processes, and firewall activity.

## 🚀 Architecture
### Components
- 🖥 **Kali Linux (Attacker)** → brute force with Hydra, run adversary simulations.  
- 🔥 **FortiGate Firewall** → edge firewall, forwards logs (syslog UDP/514) to Splunk.  
- 🏰 **Active Directory DC (WIN-DC01)** → authenticates domain logons, generates Windows Security events.  
- 💻 **Windows 10 Workstation** → target machine, running Sysmon + Splunk UF.  
- 📊 **Splunk Enterprise Server (Ubuntu)** → SIEM, log collection, dashboards, and alerts.

### Data Flow
- Attacker (Kali) → Target/DC (brute force, PowerShell, process creation)  
- Target + DC → Splunk (Windows Security + Sysmon logs via UF)  
- FortiGate → Splunk (network logs via syslog)  
- Splunk → Security Analyst (dashboards, alerts, investigation) 

## ⚙️ Virtual Machine Setup

| VM name     |                       OS | Role                                    | Primary logs                                  |     vCPU / RAM / Disk (recommended) |
| ----------- | -----------------------: | --------------------------------------- | --------------------------------------------- | ----------------------------------: |
| `SPLUNK`    |  Ubuntu Server 22.04 LTS | Splunk Enterprise (Indexer/Search Head) | All indexed logs (windows, sysmon, fortigate) | 4 vCPU / 8 GB RAM / 80+ GB disk |
| `ADDC01`    |      Windows Server 2022 | Active Directory Domain Controller      | Windows Security logs, AD events              | 2 vCPU / 8 GB RAM / 70 GB disk |
| `TARGET-PC` |            Windows 10/11 | Domain-joined workstation               | Windows Security logs, Sysmon logs            | 2 vCPU / 4 GB RAM / 60 GB disk |
| `KALI`      |               Kali Linux | Attacker (Hydra, ART tests)             | n/a (attacker side)                           | 2 vCPU / 2 GB RAM / 20 GB disk |
| `FortiGate` | FortiGate VM             | Firewall                                | Syslog for traffic                            | hardware-varying |
| `Stand_alone_PC` | Windowa 10          | Test_Connectivity                       | Windows Security logs, Sysmon logs            | 2 vCPU / 4 GB RAM / 60 GB disk|

## Diagram

## 🌐 Hyper-V Networking Notes
- Used a **NAT/bridged vSwitch (LabNAT)** for VM-to-VM + internet connectivity.  
- Could also isolate traffic with multiple vSwitches + routing rules.  
- Best practice: **create checkpoints** before major changes.  
- **Dynamic disks** used (expandable VHDX). Expanded Ubuntu LVM when Splunk disk filled up.  
- **Enhanced session mode** enabled for clipboard/file sharing.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a4141b4945197f8e4e51039e6be43f6fbe823243/New%20folder%20(2)/Screenshot%202025-08-26%20123118.png)

## Testing VM Machines, if they all reachable:
The Kali , Target, Domain, and Splunk server all able to communicate together.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Confirm%20pinging.png)

# Configure and confirm if sysmon is working after installation

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/095872da4a5fd5b88b16886796e37d01c40f4b5b/New%20folder%20(3)/Corming%20Symon%20installation.png)

# Configure my Kali Machine that will serve as attcking machine

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/095872da4a5fd5b88b16886796e37d01c40f4b5b/New%20folder%20(3)/Kali%20Machine.png)

Configure my Ubutun that server as Splunk server
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/095872da4a5fd5b88b16886796e37d01c40f4b5b/New%20folder%20(3)/SplunkIP.png)

## 📊 Splunk Enterprise on Ubuntu
### Why Splunk?
Splunk acts as the **SIEM**, centralizing logs, allowing us to:  
- Ingest security logs  
- Write correlation searches  
- Build dashboards + alerts
   
### Setup
1. Install `.deb` package from Splunk site.  
2. Start Splunk → Web GUI on `http://<splunk_ip>:8000`.  
3. Open port **9997** for Universal Forwarders.

Install:
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Installing%20Splung.png)

Confirm splung is listening - 9997

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Confirm%20listening%20port.png)

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


## 📥 Splunk Universal Forwarder (Windows + Sysmon)
### Why UF?
The **Universal Forwarder** is a lightweight Splunk agent. It:  
- Forwards Windows Security logs + Sysmon logs to Splunk.  
- Keeps Splunk server lean by offloading collection to endpoints.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Splunk%20forward%20events.png)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Config%20File.png)

Checked and Confirm splunk forwarder is running in Target and domain Pc
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/Confirm%20splunk%20is%20running.png)

## Corming client is receiving data

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/39db47e2a10198db6f5f4e40744147f6a090cf03/New%20folder%20(3)/ConfirmingClient.png)

# Check if i can see my two host machine (DC & Target Machine)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/095872da4a5fd5b88b16886796e37d01c40f4b5b/New%20folder%20(3)/Two_Host.png)

### Config
- **outputs.conf** → defines Splunk Indexer destination (`192.168.10.60:9997`).  
- **inputs.conf** → selects which logs to forward (Security, Sysmon, Application).  
- Installed on **Target-PC** and **Domain Controller**.
  
#### Configure the forwaders on both the Target and DC.

- outputs.conf (Where does the UF send data)
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/output.png)

- inputs.conf (What logs to forward)
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/261569f373dec8813673ea83d429ca1bd678b3ab/New%20folder%20(3)/inputforward.png)

## 🐉 Attacker Simulation with Kali (Hydra)
### Why Hydra?
Hydra is a fast password-cracking tool. In this lab:  
- Simulated **RDP brute force** against the target.  
- Generated **Event ID 4625** (failed logons) and **4624** (successful logons).

### Example Command:

- hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.10.40 -t 4 -W 1

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


## 🧪 Atomic Red Team (MITRE ATT&CK Simulation)

### 📌 Why Atomic Red Team?
Atomic Red Team (ART) is an **open-source project** that provides lightweight tests mapped directly to the **MITRE ATT&CK framework**.  
Instead of running a real attacker toolkit, ART lets us **safely simulate adversary techniques** and validate whether our detection pipeline (Sysmon → UF → Splunk) catches them.

This was a crucial part of the lab because:
- It validated that **Windows Security Events + Sysmon telemetry** were being forwarded correctly.
- It proved Splunk could **detect & map adversary behavior** in line with ATT&CK techniques.
- It helped practice **incident triage**: which logs appear, how to search, how to visualize.

---

### ⚙️ Setup
1. On **Target-PC**, created a folder `C:\AtomicRedTeam`.
2. Excluded the folder from **Microsoft Defender AV** (⚠️ only for lab purposes).
3. Allowed PowerShell scripts to run:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope CurrentUser

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

Atomic red showing different event codes taken place

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(4)/MATT%20logon.png)
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(4)/Matt%20user.png)

## Results:
### EventCode	Description
###🔹 Logs Captured in Splunk

- Event ID 4720 – User account created
- Event ID 4722 – User account enabled
- Event ID 4724 – Password reset
- Event ID 4726 – User deleted
- Event ID 4738 – Account changed
- Event ID 4798 – Group membership enumerated

### Splunk Forwarder sent these to Splunk Indexer where I confirmed indexing as showed aboved


## The diagram Shows Cowerr user account was deleted theres been an intrusion which occured by the user

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(4)/Matt%20user2.png)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/5ee5fdbebae56a714ad29efd5deaeedc17656481/New%20folder%20(4)/Screenshot%202025-08-29%20122720.png)


## Created a attble for it to visualise the attack

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/1b97def7e0f6bdd1aad7d86d56951dd3599491df/New%20folder%20(4)/Mittattack.png)


### Observed Outcome: 
- The user NewLocalUser was created, added to the Administrators group, and deleted as expected.
- Corresponding events were captured by Splunk and indexed in the endpoint index.
- Event codes aligned with MITRE ATT&CK T1136.001, demonstrating successful simulation and monitoring of the attack.

# FortiGate config
##🔹 Setup Steps

Change Splunk Server IP, Originally Splunk was on 192.168.10.60. To match FortiGate’s network, I changed it to 192.168.100.60.

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Fortigate%20pinging%20splunk.png)

# Install Fortinet Add-On for Splunk

- Download TA-fortinet_fortigate.
- Extract to /opt/splunk/etc/apps/.
- Restart Splunk.
  
## Install via CLI - Fortinet FortiGate Add-on for Splunk and Extract it:

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/4030babe196167315aedc4024fecbbead56c4ca0/New%20folder%20(3)/Extract%20fortigate.png)

Couldn't find it in my app directory so I'd to cd /opt/splunk/etc/apps/ and copy extracted Fortinet Add-On folder into this directory - sudo cp -r ~/Downloads/TA-fortinet_fortigate /opt/splunk/etc/apps/

## Restart Splunk:

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/4030babe196167315aedc4024fecbbead56c4ca0/New%20folder%20(3)/Copy%20to%20splunk%20app.png)

# After downloading fortigate add on, I'd Configure the syslog server Configure the syslog server Ensure syslog forwarding is enabled. 
config log syslogd setting
set status enable
set server 192.168.100.60
set mode udp
set port 514
set facility local7
set source-ip 192.168.100.1
end
**(Screenshot Missing)**

## Also did the configuration in the fortigate web interface 

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/8100ef16e67c1acd4af128d0b34e078f2c6f26ef/New%20folder%20(4)/configuring%20syslog%20on%20fortigate.png)

I confirmed the Fortigate Add on, if is showing in splunk  
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/e88c710edcb2a30cd86d7a37a3821bff3a40df40/New%20folder%20(3)/Confirm%20Fortigate%20add%20on%20isinstalled.png)

## Enable logging for different events For example, enable logging for traffic, security, and VPN events:

config log setting
set fwpolicy-implicit-log enable
set local-in-allow enable
end

## Enable traffic logging for the policy so web filter events are generated and forwarded to Splunk.

config firewall policy
edit 2
set logtraffic all
next
edit 1
set logtraffic all
next
end

## Notes:
- set logtraffic all logs all traffic matched by this policy, including web filter blocks.

## After this, syslog logging is configured, and logs will be sent to Splunk (assuming UDP 514 is reachable).

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Screenshot%202025-09-03%20203209.png)

# Next was to set up Splunk to ingest FortiGate logs via UDP 514. You’ll need to create or edit an inputs.conf in the Fortinet Add-On and after that restart splunk:

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/335ad021691b935952bb8ee38538d7430d619cb6/New%20folder%20(3)/inputsconf%20for%20fortigate.png)

Verified if firewall policy is been configured or applied
Testpc-firewall → policy ID 2
LAN-to-WAN → policy ID 1

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/56e7298a5a59c4df0ef22288e6d6bf3b9b541cb5/New%20folder%20(3)/show%20is%20enable.png)


You see all logs displayed including the webfiltering 

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/8100ef16e67c1acd4af128d0b34e078f2c6f26ef/New%20folder%20(4)/log%20types%20(traffic%2C%20VPN%2C%20virus%2C%20etc.)..png)

Fortigate showing in splunk

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(3)/firewal.png)

showing the Test Machine IP address

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Logs%20from%20web.png)

Generate a test log to verify fortigate logs is sent to splunk 
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/56e7298a5a59c4df0ef22288e6d6bf3b9b541cb5/New%20folder%20(3)/firewall%20sending%20log.png)

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/a17912a36a48903868eff50066db41e724c56239/New%20folder%20(4)/Screenshot%202025-09-03%20223140.png)

Showing the webfilering working blocked the web application that are not needed

![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/main/New%20folder%20(4)/Screenshot%202025-09-06%20212541.png)

Created a table to show the high impact of webfiletering, blocking web application these shows the logs from fortigate where it displace instagram, facebbok, twitter were been blocked, you can see instagram where the highest blocked  all this shown in splunk
![Nat_Created](https://github.com/victormbogu1/Windows-Brute-Force-Detection-Monitoring-with-Splunk-Sysmon-and-FortiGate/blob/b618a777451cf1cece36440e3dcae5d2b8d061e5/New%20folder%20(3)/webfirewalchart.png)

#🟣 Results & Conclusion
##🔹 What I Accomplished

- Built a full SOC lab:
- AD DC + Target Workstation + Kali Attacker + FortiGate Firewall + Splunk Server.
- Configured Splunk UF + Sysmon for endpoint telemetry.
- Simulated brute-force attacks with Hydra.
- Detected and visualized failed and successful logons.
- Simulated adversary techniques with Atomic Red Team (MITRE ATT&CK).
- Integrated FortiGate firewall logs for network visibility.
- Created Splunk dashboards + alerts for security monitoring.

##🎯 Key Learnings

- SIEM setup (Splunk Enterprise + UF).
- Correlating endpoint + firewall logs.
- MITRE ATT&CK-based detections (Atomic Red Team).
- Hands-on attacker simulation with Hydra.
- Hyper-V VM management + troubleshooting (disk expansion, networking).

##🚀 Next Steps

- Add DNS, FTP, Proxy logs.
- Expand detections to persistence & lateral movement.
- Automate responses with SOAR.
- Map detections more deeply to MITRE ATT&CK.

## 🏁 Conclusion

- This lab gave me real SOC analyst experience:
- Building a detection pipeline from endpoint → SIEM → analyst.
- Simulating real-world attacks.
- Investigating events with Splunk queries, dashboards, and alerts.

## 👉 This repo is both a reference guide for me and a tutorial for others who want to learn SOC operations in a home lab.
