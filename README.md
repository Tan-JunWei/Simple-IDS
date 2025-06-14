# 🛡️ Intrusion Detection System (IDS)

This repository is an extension of an Intrusion Detection System (IDS) developed as part of the Network Forensics module within the Sentinel Programme.

> Network Forensics Repository: [Sentinel-PS5PI-Network-Forensics](https://github.com/Tan-JunWei/Sentinel-PS5PI-Network-Forensics)

The IDS scripts are written in Python and tested using publicly available `.pcap` files to detect and report suspicious network activities.

---

## Detection Modes

<div align="center">
    <img src="assets/manual.png" alt="Online vs Offline Detection" width="600"/>
    <h4>Online vs Offline Detection Modes</h4>
</div>

This IDS supports two modes of operation:

### 🔴 Online Detection (Real-Time)
- Monitors live network traffic on a selected interface.
- Ideal for active monitoring and immediate response in real-world environments.
- Captures and analyzes packets in real-time using libraries such as **Scapy** or **PyShark**.

### 🔵 Offline Detection (PCAP Analysis)
- Analyzes pre-captured packet data from `.pcap` files.
- Useful for post-incident forensic investigation and testing detection logic.
- Supports batch processing of various attack samples.

---

## 🔍 Detection Modules

>[!NOTE]
>
>This project is intentionally kept **lightweight and focused** for clarity and learning.
>
>It currently supports detection of **three fundamental attack types**:  
>- ARP Spoofing  
>- DNS Spoofing  
>- Port Scanning  
>
>This minimal design makes it easier to understand and extend for educational use or prototyping.

### Address Resolution Protocol (ARP) Spoofing

ARP spoofing is a network attack in which a malicious actor sends fake ARP messages to associate their MAC address with the IP address of another device, usually a gateway. This allows the attacker to intercept, monitor, or manipulate traffic between devices. The IDS detects this behavior by identifying inconsistent ARP mappings, duplicate IP-to-MAC relationships, and abnormal ARP activity patterns.

<div align="center">
    <img src="assets/arpspoof_example.png" alt="ARP Spoofing Example Usage" width="750"/>
    <h4>Example: ARP Spoofing Detection in Action</h4>
</div>

<div align="center">
    <img src="assets/arpspoof_report.png" alt="ARP Spoofing Report" width="750"/>
    <h4>Generated Report for ARP Spoofing</h4>
</div>

---

### Domain Name System (DNS) Spoofing

DNS spoofing, also known as DNS cache poisoning, tricks a system into resolving domain names to incorrect IP addresses. This type of attack is often used to redirect users to fake or malicious websites. The IDS detects DNS spoofing by analyzing domain resolution inconsistencies, suspicious DNS responses, and mismatches between request and response sources.

<div align="center">
    <img src="assets/dnsspoof_example.png" alt="DNS Spoofing Example Usage" width="750"/>
    <h4>Example: DNS Spoofing Detection in Action</h4>
</div>

<div align="center">
    <img src="assets/dnsspoof_report.png" alt="DNS Spoofing Report" width="750"/>
    <h4>Generated Report for DNS Spoofing</h4>
</div>

---

### Port Scanning

Port scanning is a technique used by attackers to discover open ports and active services on a target system. It is commonly used during the reconnaissance phase of an attack. The IDS identifies port scanning by detecting a high number of connection attempts across multiple ports from a single source within a short period of time.

<div align="center">
    <img src="assets/portscan_example.png" alt="Port Scanning Example Usage" width="750"/>
    <h4>Example: Port Scanning Detection in Action</h4>
</div>

---

## Sample PCAP Files

Example `.pcap` files were sourced from reputable online repositories to validate the IDS detection capabilities:

| Attack Type     | Source Link |
|------------------|-------------|
| **ARP Spoofing** | [asecuritysite.com](https://asecuritysite.com/forensics/pcap?infile=arp_spoof.pcap) |
| **DNS Spoofing** | [ManOnTheSideAttack-DNS-Spoofing](https://github.com/waytoalpit/ManOnTheSideAttack-DNS-Spoofing/blob/master/capture.pcap) |
| **Port Scanning**| [markofu/pcaps](https://github.com/markofu/pcaps/blob/master/PracticalPacketAnalysis/ppa-capture-files/portscan.pcap) |

