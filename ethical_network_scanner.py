import scapy.all as scapy
import socket
import threading
import argparse
import sys
from datetime import datetime
from queue import Queue

def get_arguments():
    parser = argparse.ArgumentParser(description="Powerful Network Scanner by Ethical Hacker")
    parser.add_argument("-t", "--target", dest="target", help="Target IP or IP range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", dest="ports", help="Port range to scan (e.g., 1-1000)", default="1-1000")
    parser.add_argument("-s", "--scan", dest="scan_type", help="Scan type: ping, port, or sniff", default="port")
    return parser.parse_args()

def ping_scan(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff: ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        clients = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients.append(client_dict)
        return clients
    except Exception as e:
        print(f"[!] Error in ping scan: {e}")
        return []

def port_scan(target, ports):
    print(f"[*] Starting port scan on {target} at {datetime.now()}")
    open_ports = []
    port_range = parse_ports(ports)
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                print(f"[+] Port {port} open - Service: {service}")
            sock.close()
        except Exception as e:
            pass
    
    threads = []
    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return sorted(open_ports)

def parse_ports(ports):
    if '-' in ports:
        start, end = map(int, ports.split('-'))
        return range(start, end + 1)
    return [int(ports)]

def packet_sniffer(interface="eth0"):
    print(f"[*] Starting packet sniffer on {interface} at {datetime.now()}")
    try:
        scapy.sniff(iface=interface, store=False, prn=process_packet, count=10)
    except Exception as e:
        print(f"[!] Error in packet sniffer: {e}")

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto
        print(f"[*] Packet: {ip_src} -> {ip_dst} | Protocol: {proto}")
        if packet.haslayer(scapy.TCP):
            print(f"    TCP: {packet[scapy.TCP].sport} -> {packet[scapy.TCP].dport}")
        elif packet.haslayer(scapy.UDP):
            print(f"    UDP: {packet[scapy.UDP].sport} -> {packet[scapy.UDP].dport}")

def main():
    args = get_arguments()
    if not args.target:
        print("[!] Please specify a target IP or IP range with -t")
        sys.exit(1)
    
    print("[*] Network Scanner by Ethical Hacker")
    print(f"[*] Target: {args.target}")
    
    if args.scan_type == "ping":
        print("[*] Performing ping scan...")
        clients = ping_scan(args.target)
        for client in clients:
            print(f"[+] Host Up: {client['ip']} - MAC: {client['mac']}")
    
    elif args.scan_type == "port":
        print("[*] Performing port scan...")
        open_ports = port_scan(args.target, args.ports)
        if open_ports:
            print(f"[*] Open ports: {', '.join(map(str, open_ports))}")
        else:
            print("[*] No open ports found.")
    
    elif args.scan_type == "sniff":
        print("[*] Performing packet sniffing...")
        packet_sniffer()
    
    else:
        print("[!] Invalid scan type. Use ping, port, or sniff.")
        sys.exit(1)

if __name__ == "__main__":
    main()