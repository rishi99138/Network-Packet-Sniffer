#!/usr/bin/env python3
"""
Network Packet Sniffer - Fixed Version
Captures and analyzes TCP, UDP, ICMP packets with real-time filtering
"""

import time
import csv
import json
import argparse
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import threading
import queue
import signal

class PacketSniffer:
    def __init__(self, interface=None, bpf_filter="tcp or udp or icmp", 
                 output_format="csv", output_file="capture"):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.output_format = output_format
        self.output_file = output_file
        self.packet_count = 0
        self.start_time = time.time()
        self.packet_queue = queue.Queue()
        self.running = True
        self.writer_thread = None
        
        # Performance tracking
        self.latencies = []
        self.last_callback_time = time.perf_counter()
        
    def packet_to_record(self, packet):
        """Extract structured data from packet with improved IP handling"""
        record = {
            'timestamp': datetime.now().isoformat(),
            'protocol': 'Unknown',
            'src_ip': '',
            'dst_ip': '',
            'src_port': '',
            'dst_port': '',
            'packet_size': 0,
            'flags': '',
            'icmp_type': '',
            'icmp_code': '',
            'payload_length': 0
        }
        
        try:
            record['packet_size'] = len(packet)
            
            # Check for IP layer first (IPv4)
            if packet.haslayer(IP):
                record['src_ip'] = str(packet[IP].src)
                record['dst_ip'] = str(packet[IP].dst)
            # Also check for IPv6
            elif hasattr(packet, 'IPv6') and packet.haslayer('IPv6'):
                record['src_ip'] = str(packet['IPv6'].src)
                record['dst_ip'] = str(packet['IPv6'].dst)
            
            # TCP layer parsing
            if packet.haslayer(TCP):
                record['protocol'] = 'TCP'
                record['src_port'] = int(packet[TCP].sport)
                record['dst_port'] = int(packet[TCP].dport)
                record['payload_length'] = len(packet[TCP].payload) if hasattr(packet[TCP], 'payload') and packet[TCP].payload else 0
                
                # TCP flags with safe access
                flags = []
                tcp_flags = packet[TCP].flags
                if tcp_flags & 0x02: flags.append('SYN')  # SYN flag
                if tcp_flags & 0x10: flags.append('ACK')  # ACK flag  
                if tcp_flags & 0x01: flags.append('FIN')  # FIN flag
                if tcp_flags & 0x04: flags.append('RST')  # RST flag
                if tcp_flags & 0x08: flags.append('PSH')  # PSH flag
                if tcp_flags & 0x20: flags.append('URG')  # URG flag
                record['flags'] = '|'.join(flags) if flags else str(tcp_flags)
                
            # UDP layer parsing
            elif packet.haslayer(UDP):
                record['protocol'] = 'UDP'
                record['src_port'] = int(packet[UDP].sport)
                record['dst_port'] = int(packet[UDP].dport)
                record['payload_length'] = len(packet[UDP].payload) if hasattr(packet[UDP], 'payload') and packet[UDP].payload else 0
                
            # ICMP layer parsing
            elif packet.haslayer(ICMP):
                record['protocol'] = 'ICMP'
                record['icmp_type'] = int(packet[ICMP].type)
                record['icmp_code'] = int(packet[ICMP].code)
                
        except Exception as e:
            print(f"Error parsing packet: {e}")
            # Print packet layers for debugging
            print(f"Packet layers: {packet.layers()}")
            record['protocol'] = 'Error'
            
        return record
    
    def packet_handler(self, packet):
        """Process each captured packet with error handling"""
        try:
            capture_time = time.perf_counter()
            
            # Calculate callback latency
            latency = (capture_time - self.last_callback_time) * 1000  # ms
            if latency > 0:  # Avoid negative or zero latencies
                self.latencies.append(latency)
            self.last_callback_time = capture_time
            
            # Convert packet to structured record
            record = self.packet_to_record(packet)
            
            # Add to queue for processing
            self.packet_queue.put(record)
            self.packet_count += 1
            
            # Real-time feedback every 50 packets
            if self.packet_count % 50 == 0:
                print(f"Captured {self.packet_count} packets...")
            elif self.packet_count <= 10:  # Show first 10 for immediate feedback
                print(f"Packet {self.packet_count}: {record['protocol']} "
                      f"{record['src_ip']}:{record['src_port']} -> "
                      f"{record['dst_ip']}:{record['dst_port']}")
                
        except Exception as e:
            print(f"Error in packet handler: {e}")
    
    def writer_thread_func(self):
        """Background thread to write packets to file"""
        try:
            if self.output_format == "csv":
                filename = f"{self.output_file}.csv"
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['timestamp', 'protocol', 'src_ip', 'dst_ip', 
                                'src_port', 'dst_port', 'packet_size', 'flags', 
                                'icmp_type', 'icmp_code', 'payload_length']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    batch_count = 0
                    while self.running or not self.packet_queue.empty():
                        try:
                            record = self.packet_queue.get(timeout=1)
                            writer.writerow(record)
                            batch_count += 1
                            
                            # Flush every 10 records for better performance
                            if batch_count % 10 == 0:
                                csvfile.flush()
                                
                        except queue.Empty:
                            csvfile.flush()  # Ensure data is written on timeout
                            continue
                    
                    csvfile.flush()  # Final flush
                    
            elif self.output_format == "json":
                filename = f"{self.output_file}.jsonl"
                with open(filename, 'w', encoding='utf-8') as jsonfile:
                    batch_count = 0
                    while self.running or not self.packet_queue.empty():
                        try:
                            record = self.packet_queue.get(timeout=1)
                            jsonfile.write(json.dumps(record) + '\n')
                            batch_count += 1
                            
                            # Flush every 10 records
                            if batch_count % 10 == 0:
                                jsonfile.flush()
                                
                        except queue.Empty:
                            jsonfile.flush()
                            continue
                    
                    jsonfile.flush()  # Final flush
                    
        except Exception as e:
            print(f"Error in writer thread: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print("\nReceived interrupt signal. Stopping capture...")
        self.running = False
    
    def start_capture(self, count=None, timeout=None):
        """Start packet capture with improved error handling"""
        print(f"Starting packet capture...")
        print(f"Interface: {self.interface or 'Default (all interfaces)'}")
        print(f"Filter: {self.bpf_filter}")
        print(f"Output: {self.output_file}.{self.output_format}")
        
        if timeout:
            print(f"Timeout: {timeout} seconds")
        if count:
            print(f"Max packets: {count}")
            
        print("Press Ctrl+C to stop\n")
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Start writer thread
        self.writer_thread = threading.Thread(target=self.writer_thread_func)
        self.writer_thread.daemon = True
        self.writer_thread.start()
        
        try:
            # Start packet capture with error suppression for the warning
            print("Starting packet capture... (warnings about socket comparisons are normal)")
            
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.packet_handler,
                store=False,  # Don't store packets in memory
                count=count,
                timeout=timeout,
                stop_filter=lambda p: not self.running  # Stop when running=False
            )
            
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received...")
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            print("Stopping capture...")
            self.running = False
            if self.writer_thread:
                self.writer_thread.join(timeout=5)
            self.print_stats()
    
    def print_stats(self):
        """Print capture statistics"""
        duration = time.time() - self.start_time
        print(f"\n=== Capture Statistics ===")
        print(f"Total packets captured: {self.packet_count}")
        print(f"Capture duration: {duration:.2f} seconds")
        
        if duration > 0:
            print(f"Average packets per second: {self.packet_count/duration:.2f}")
        
        if self.latencies:
            avg_latency = sum(self.latencies) / len(self.latencies)
            max_latency = max(self.latencies)
            min_latency = min(self.latencies)
            p95_latency = sorted(self.latencies)[int(len(self.latencies) * 0.95)]
            
            print(f"Callback latencies (ms):")
            print(f"  Average: {avg_latency:.2f}")
            print(f"  Min: {min_latency:.2f}")
            print(f"  Max: {max_latency:.2f}")
            print(f"  95th percentile: {p95_latency:.2f}")
            
        print(f"Output file: {self.output_file}.{self.output_format}")

def main():
    parser = argparse.ArgumentParser(description='Network Packet Sniffer')
    parser.add_argument('--interface', '-i', help='Network interface to capture on')
    parser.add_argument('--filter', '-f', default='tcp or udp or icmp', 
                       help='BPF filter (default: tcp or udp or icmp)')
    parser.add_argument('--count', '-c', type=int, help='Number of packets to capture')
    parser.add_argument('--timeout', '-t', type=int, help='Capture timeout in seconds')
    parser.add_argument('--format', choices=['csv', 'json'], default='csv',
                       help='Output format (default: csv)')
    parser.add_argument('--output', '-o', default='capture',
                       help='Output filename prefix (default: capture)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        print("Available network interfaces:")
        try:
            for iface in get_if_list():
                print(f"  {iface}")
        except Exception as e:
            print(f"Error listing interfaces: {e}")
        return
    
    # Check if running as administrator
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("WARNING: Not running as Administrator. Packet capture may not work properly.")
            print("Try: Run as Administrator or use 'sudo' on Linux/Mac")
    except:
        pass
    
    # Create and start sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        bpf_filter=args.filter,
        output_format=args.format,
        output_file=args.output
    )
    
    sniffer.start_capture(count=args.count, timeout=args.timeout)

if __name__ == "__main__":
    main()
