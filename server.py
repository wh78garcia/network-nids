#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS) Server
Monitors network traffic and detects suspicious activities
"""

import os
import sys
import time
import threading
import logging
from datetime import datetime
from scapy.all import *
from scapy.config import conf

class NIDSServer:
    def __init__(self, interface=None):
        """
        Initialize NIDS server
        :param interface: Network interface to monitor
        """
        self.check_root()
        self.setup_logging()
        self.interface = interface
        self.stop_sniffing = False
        self.alarm_count = {
            'port_scan': 0,
            'dns_tunneling': 0,
            'large_icmp': 0
        }
        self.stats_interval = 10  # Statistics interval in seconds
        self._init_stats_thread()

        # Define detection rules
        self.rules = {
            'port_scan': lambda pkt: pkt.haslayer(TCP) and pkt[TCP].flags == 'S',
            'dns_tunneling': lambda pkt: (pkt.haslayer(DNS) and 
                                        len(pkt[DNS].qd.qname) > 30 if pkt.haslayer(DNSQR) else False),
            'large_icmp': lambda pkt: pkt.haslayer(ICMP) and len(raw(pkt)) > 1000
        }

    def check_root(self):
        """Verify root privileges"""
        if os.geteuid() != 0:
            print("[ERROR] Requires root privileges. Run with: sudo python3 server.py")
            sys.exit(1)

    def setup_logging(self):
        """Configure logging system"""
        logging.basicConfig(
            filename='nids.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def packet_handler(self, packet):
        """Process captured packets and apply detection rules"""
        if not packet.haslayer(IP):
            return
            
        for rule_name, rule_func in self.rules.items():
            if rule_func(packet):
                self.alarm_count[rule_name] += 1
                self.trigger_alert(packet, rule_name)
                break

    def trigger_alert(self, packet, rule_name):
        """Trigger and log security alerts"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src = packet[IP].src
        dst = packet[IP].dst
        
        alert_msg = f"Suspicious activity detected: {rule_name} | Source IP: {src} | Target IP: {dst}"
        print(f"[{timestamp}] {alert_msg}")
        logging.warning(alert_msg)

    def start(self):
        """Start NIDS monitoring"""
        print("[+] Starting Network Intrusion Detection System...")
        print("[+] Press Ctrl+C to stop monitoring\n")
        
        sniff_params = {
            'prn': self.packet_handler,
            'store': 0,
            'stop_filter': lambda x: self.stop_sniffing,
        }
        
        if self.interface:
            sniff_params['iface'] = self.interface
            print(f"[+] Monitoring interface: {self.interface}")
        
        try:
            sniff(**sniff_params)
        except KeyboardInterrupt:
            self.show_stats()
        except Exception as e:
            logging.error(f"Monitoring error: {str(e)}")
            print(f"[ERROR] {str(e)}")

    def show_stats(self):
        """Display final statistics (on exit)"""
        self._log_and_print_stats()

    def _init_stats_thread(self):
        """Initialize statistics thread"""
        self.stats_thread = threading.Thread(target=self._run_stats_collector)
        self.stats_thread.daemon = True
        self.stats_thread.start()

    def _run_stats_collector(self):
        """Periodically collect and output statistics"""
        while not self.stop_sniffing:
            time.sleep(self.stats_interval)
            self._log_and_print_stats()

    def _log_and_print_stats(self):
        """Log and print current statistics"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        stats_msg = f"Periodic statistics | {timestamp}\n"
        stats_msg += "\n".join([f"  - {rule}: {count} alerts" 
                               for rule, count in self.alarm_count.items()])
        
        # Print to console
        print(f"\n[STATS] {stats_msg}")
        
        # Log to file
        logging.info(f"Periodic statistics\n{stats_msg}")

if __name__ == "__main__":
    # Example: Monitor specific interface
    # server = NIDSServer(interface="eth0")
    server = NIDSServer()
    server.start()