import pyshark
from rich.console import Console
from rich.table import Table
from collections import defaultdict, deque
from colorama import Fore, Style
from datetime import datetime
import time
import argparse

incident_log = []
ip_mapping = defaultdict(list)
flagged_ips = set()
scan_attempts = defaultdict(lambda: {'tcp_ports': set(),'udp_ports': set(), 'timestamps': deque()}) # Dictionary to track unique ports and timestamps for each IP
threshold = 15
time_window = 5
dns_records = defaultdict(set)
logged_domains = set() 

def log_incident(ip, anomaly_type, description, timestamp):
    incident = {
        'IP': ip,
        'Type': anomaly_type,
        'Timestamp': timestamp,
        'Details': description
    }
    incident_log.append(incident)

def detect_arp_spoofing(packet):
    '''
    ARP Spoofing is an attack where an attacker sends fake ARP replies on a local network.
    This allows the attacker to associate their MAC address with the IP address of another host,
    allowing them to intercept traffic meant for that host.

    To detect ARP Spoofing, we can monitor ARP replies and check if the MAC address associated with an IP address changes.
    '''
    try:
        if hasattr(packet, 'arp') and packet.arp.opcode == '2':  # ARP reply
            ip_address = packet.arp.src_proto_ipv4
            mac_address = packet.arp.src_hw_mac
            timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S')

            # Check if a MAC address is already mapped to this IP
            if mac_address not in ip_mapping[ip_address]:
                # If this MAC address is new, and the IP address is already mapped to another MAC address, flag it
                if len(ip_mapping[ip_address]) > 0:
                    log_incident(
                        ip=ip_address,
                        anomaly_type="ARP Spoofing",
                        description=f"Multiple MACs: {ip_mapping[ip_address] + [mac_address]}",
                        timestamp=timestamp
                    )
                    print(
                        f"{Fore.RED}\nARP Spoofing Check {Style.RESET_ALL}"
                        f"[{Fore.MAGENTA}{Style.BRIGHT}{len(ip_mapping[ip_address]) + 1}{Style.RESET_ALL} MAC address(es) for {Fore.CYAN}{Style.BRIGHT}{ip_address}{Style.RESET_ALL}]"
                    )
                    print(f"New Claim: {mac_address}")
                    print(f"Previous MAC address(es): {', '.join(ip_mapping[ip_address])}")

                # Add the new MAC address to the mapping
                ip_mapping[ip_address].append(mac_address)
    except Exception as e:
        # Handle any exceptions that may arise from packet processing
        print(f"Error processing packet: {e}")

def display_arp_mapping():
    # Only include IPs with multiple MACs as join is used to convert list to string
    rows = [[ip, ", ".join(mac)] for ip, mac in ip_mapping.items()] 
    columns = ["IP Address", "MAC Addresses recorded"]

    if len(rows) == 0: # If no rows are found, then no ARP Spoofing occurred
        print(f"{Fore.GREEN}No ARP Spoofing detected!{Style.RESET_ALL}") 
        return

    else:
        print(f"\n{Fore.RED}{Style.BRIGHT}Potential ARP Spoofing detected!{Style.RESET_ALL}")
        arp_mapping_table = Table(title="List of IP addresses with more than 1 MAC address recorded", caption="ARP Mapping Table", safe_box=True, show_lines=True, min_width=65)

        # Populate the table with the data
        # For every IP address, list all the MAC addresses that have been claimed
        for column in columns:
            arp_mapping_table.add_column(column)

        for row in rows:
            arp_mapping_table.add_row(*row, style='bright_cyan')

        console = Console()
        console.print(arp_mapping_table)

def detect_port_scan(packet):
    '''
    Port scanning is a technique used to identify open ports and services available on a networked device.
    Attackers often use port scanning to find vulnerabilities in a system.
    
    Detecting port scanning can be done by monitoring the number of unique ports accessed by a single IP address within a specific time window.
    If the number of unique ports accessed exceeds a certain threshold, it may indicate a port scanning attempt.
    '''
    try:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_port = packet.tcp.dstport
            timestamp = float(packet.sniff_timestamp)
            
            # Check for TCP port scanning
            if hasattr(packet, 'tcp'):
                dst_port = packet.tcp.dstport
                scan_attempts[src_ip]['tcp_ports'].add(dst_port)
                scan_attempts[src_ip]['timestamps'].append(timestamp)

            # Check for UDP port scanning
            elif hasattr(packet, 'udp'):
                dst_port = packet.udp.dstport
                scan_attempts[src_ip]['udp_ports'].add(dst_port)
                scan_attempts[src_ip]['timestamps'].append(timestamp)
            
            # Remove old attempts outside the specified time window
            while (timestamp - scan_attempts[src_ip]['timestamps'][0]) > time_window:
                scan_attempts[src_ip]['timestamps'].popleft()    
    except Exception as e:
        pass
    
def display_port_scan_results():
    print("\nPotential port scanners found")
    print("-----------------------------")
    found_scanners = False
    
    for ip, data in scan_attempts.items():
        total_ports = len(data['tcp_ports']) + len(data['udp_ports']) 
        if total_ports >= threshold:
            time_diff = data['timestamps'][-1] - data['timestamps'][0] if len(data['timestamps']) > 1 else 0
            scan_rate = total_ports / max(1, time_diff)
            timestamp = datetime.fromtimestamp(data['timestamps'][-1]).strftime('%Y-%m-%d %H:%M:%S')

            log_incident(
                ip=ip,
                anomaly_type="Port Scanning",
                description=f"Scanned {total_ports} ports in {time_diff:.2f}s ({scan_rate:.2f} ports/sec)",
                timestamp=timestamp
            )

            print(f"{Fore.RED}IP address: {ip}{Style.RESET_ALL}")
            print(f"    TCP Ports Scanned: {len(data['tcp_ports'])}")
            print(f"    UDP Ports Scanned: {len(data['udp_ports'])}")
            print(f"    Total Unique Ports: {total_ports}")
            print(f"    Time Window: {time_diff:.2f} seconds")
            print(f"    Scan Rate: {scan_rate:.2f} ports/second")
            found_scanners = True

    if not found_scanners:
        print(f"{Fore.GREEN}No potential port scanning activity detected.{Style.RESET_ALL}")

def detect_dns_spoofing(packet):
    '''
    DNS Spoofing is an attack where an attacker tricks a DNS resolver into returning an incorrect IP address for a domain name.
    Instead of the legitimate IP address, the attacker provides a malicious IP address.
    This can lead to users being redirected to malicious websites or services.

    To detect DNS Spoofing, we can monitor DNS responses and check if multiple IP addresses are associated with the same domain name.
    If a domain name resolves to multiple IP addresses, it may indicate DNS Spoofing.
    '''
    try:
        if hasattr(packet.dns, 'qry_name') and hasattr(packet.dns, 'a'):
            domain = packet.dns.qry_name
            ip_address = packet.dns.a
            previous_count = len(dns_records[domain])
            dns_records[domain].add(ip_address)
    except AttributeError:
        pass
    
def display_dns_spoofing_results():
    # Log all suspicious DNS records (even if detected early)
    for domain, ips in dns_records.items():
        if len(ips) > 1 and domain not in logged_domains:
            log_incident(
                ip="N/A",
                anomaly_type="DNS Spoofing",
                description=f"{domain} resolved to multiple IPs: {', '.join(ips)}",
                timestamp="N/A"
            )
            logged_domains.add(domain)

    rows = [[domain, ", ".join(ip)] for domain, ip in dns_records.items()] 
    columns = ["Domain", "IP Addresses recorded"]

    if len(rows) == 0: # If no rows are found, then no ARP Spoofing occurred
        print(f"\n{Fore.GREEN}No DNS Spoofing detected!{Style.RESET_ALL}") 
        return

    else:        
        print(f"\n{Fore.RED}{Style.BRIGHT}Potential DNS Spoofing detected!{Style.RESET_ALL}")
        dns_mapping_table = Table(title="List of domains with more than 1 IP address recorded", caption="DNS Mapping Table", safe_box=True, show_lines=True, min_width=65)

        # Populate the table with the data
        # For every domain, list all the IP addresses that have been claimed
        for column in columns:
            dns_mapping_table.add_column(column)

        for row in rows:
            dns_mapping_table.add_row(*row, style='bright_cyan')

        console = Console()
        console.print(dns_mapping_table)

def generate_report(output_file):
    with open(output_file, 'w') as f:
        f.write("Network Anomaly Report\n")
        f.write("="*60 + "\n")
        for incident in incident_log:
            f.write(f"Time: {incident['Timestamp']}\n")
            f.write(f"Type: {incident['Type']}\n")
            f.write(f"IP: {incident['IP']}\n")
            f.write(f"Details: {incident['Details']}\n")
            f.write("-"*60 + "\n")
    print(f"[*] Report saved to {output_file}")

def parse_args():
    parser = argparse.ArgumentParser(description="Simple Intrusion Detection System (IDS) Script")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", metavar="PCAP_FILE", help="run detection on a PCAP file")
    mode.add_argument("--online", action="store_true", help="run live detection")

    return parser.parse_args()

def main():
    args = parse_args()
    output_file = 'report.txt'

    if args.offline:
        capture_file = args.offline

        capture = pyshark.FileCapture(capture_file)

        for packet in capture:
            detect_arp_spoofing(packet)
            detect_port_scan(packet)
            detect_dns_spoofing(packet)
    
    elif args.online:
        try:
            print("Starting live capture...(CTRL+C to quit)")
            print("Any detected anomalies will be displayed in the console.")

            capture = pyshark.LiveCapture() 

            for packet in capture.sniff_continuously():
                detect_arp_spoofing(packet)
                detect_port_scan(packet)
                detect_dns_spoofing(packet)
        except KeyboardInterrupt:
            print("\nStopping live capture...")
            capture.clear()
            capture.close()
        except Exception as e:
            print(f"Error: {e}")
    
    display_arp_mapping()
    display_port_scan_results()
    display_dns_spoofing_results()
    generate_report(output_file)

if __name__ == "__main__":
    main()
