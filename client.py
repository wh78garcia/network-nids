#!/usr/bin/env python3
"""
NIDS Test Client
Generates normal and malicious network traffic for testing
"""

import time
import random
import string
from scapy.all import *

class TrafficGenerator:
    def __init__(self, target_ip="127.0.0.1"):
        """
        Initialize traffic generator
        :param target_ip: Target IP address for test traffic
        """
        self.target_ip = target_ip
        self.dns_server = "8.8.8.8"  # Default to Google DNS

    def send_packet(self, packet):
        """Safely send network packet with error handling"""
        try:
            send(packet, verbose=0)
        except Exception as e:
            print(f"[WARNING] Packet send failed: {str(e)}")

    def generate_http_traffic(self, count=5):
        """Generate normal HTTP traffic"""
        print(f"[+] Generating HTTP traffic to {self.target_ip}:80")
        for _ in range(count):
            http_pkt = IP(dst=self.target_ip)/TCP(dport=80, flags="A")/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            self.send_packet(http_pkt)
            time.sleep(0.5)

    def generate_dns_traffic(self, count=3):
        """Generate normal DNS queries"""
        print(f"[+] Generating DNS queries to {self.dns_server}:53")
        for _ in range(count):
            dns_pkt = IP(dst=self.dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
            self.send_packet(dns_pkt)
            time.sleep(1)

    def generate_icmp_traffic(self, count=3):
        """Generate normal ICMP ping traffic"""
        print(f"[+] Generating ICMP to {self.target_ip}")
        for _ in range(count):
            # Normal ping packet
            self.send_packet(IP(dst=self.target_ip)/ICMP())
            time.sleep(1)

    def generate_port_scan_attack(self):
        """Simulate port scanning attack"""
        print(f"[+] Simulating port scan attack to {self.target_ip}")
        for port in [21, 22, 80, 443, 3306, 8080]:  # Common service ports
            scan_pkt = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
            self.send_packet(scan_pkt)
            time.sleep(0.2)

    def generate_icmp_attack(self):
        """Generate malicious ICMP traffic"""
        print(f"[+] Simulating ICMP attack to {self.target_ip}")
        # Large ICMP packet
        self.send_packet(IP(dst=self.target_ip)/ICMP()/("X"*1200))

    def generate_dns_tunneling_attack(self):
        """Simulate DNS tunneling attack"""
        print(f"[+] Simulating DNS tunneling attack to {self.dns_server}:53")
        domain = f"{''.join(random.choices(string.ascii_lowercase, k=30))}.example.com"
        tunnel_pkt = IP(dst=self.dns_server)/UDP(dport=53)/DNS(qd=DNSQR(qname=domain))
        self.send_packet(tunnel_pkt)

    def run_test(self):
        """Execute complete test sequence"""
        print("[+] Starting test traffic generation...")
        
        # Generate normal traffic
        self.generate_http_traffic()
        self.generate_dns_traffic()
        self.generate_icmp_traffic()
        
        # Generate attack traffic
        self.generate_port_scan_attack()
        self.generate_icmp_attack()
        self.generate_dns_tunneling_attack()
        
        print("[+] Test traffic generation complete")

if __name__ == "__main__":
    # Usage example:
    # client = TrafficGenerator(target_ip="192.168.1.100")
    client = TrafficGenerator()
    client.run_test()