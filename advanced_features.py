#!/usr/bin/env python3
"""
Advanced Packet Analysis Features - Fixed Version
Deep packet inspection, protocol analysis, and filtering with proper error handling
"""

from scapy.all import *
import json
import csv
from datetime import datetime
import re

class AdvancedPacketAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.packet_stats = {
            'TCP': {'count': 0, 'bytes': 0, 'connections': set()},
            'UDP': {'count': 0, 'bytes': 0, 'flows': set()},
            'ICMP': {'count': 0, 'bytes': 0, 'types': {}},
            'Other': {'count': 0, 'bytes': 0}
        }
        self.suspicious_activity = []
        self.http_requests = []
        
    def deep_packet_inspection(self, packet):
        """Perform deep inspection with proper error handling"""
        self.packet_count += 1
        
        try:
            # Only process packets with IP layer
            if not packet.haslayer(IP):
                self.packet_stats['Other']['count'] += 1
                self.packet_stats['Other']['bytes'] += len(packet)
                if self.packet_count <= 5:  # Show first few non-IP packets
                    print(f"Packet {self.packet_count}: Non-IP packet ({packet.summary()})")
                return None
            
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'packet_number': self.packet_count,
                'basic_info': self.extract_basic_info(packet),
                'protocol_analysis': self.analyze_protocol(packet),
                'payload_analysis': self.analyze_payload(packet),
                'security_analysis': self.security_check(packet)
            }
            
            # Print interesting packets
            if self.packet_count <= 10 or analysis['security_analysis']['alerts'] or analysis['payload_analysis']['http_info']:
                self.print_packet_summary(analysis)
                
            return analysis
            
        except Exception as e:
            print(f"Error analyzing packet {self.packet_count}: {e}")
            return None
    
    def extract_basic_info(self, packet):
        """Extract basic packet information safely"""
        info = {
            'size': len(packet),
            'layers': [layer.name for layer in packet.layers()],
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'ttl': packet[IP].ttl,
            'protocol': 'IP'
        }
        return info
    
    def analyze_protocol(self, packet):
        """Protocol-specific analysis with safe access"""
        analysis = {}
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            analysis['TCP'] = {
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'seq': tcp.seq,
                'ack': tcp.ack,
                'flags': {
                    'SYN': bool(tcp.flags & 0x02),
                    'ACK': bool(tcp.flags & 0x10),
                    'FIN': bool(tcp.flags & 0x01),
                    'RST': bool(tcp.flags & 0x04),
                    'PSH': bool(tcp.flags & 0x08),
                    'URG': bool(tcp.flags & 0x20)
                },
                'window': tcp.window
            }
            
            # Track connection
            conn = f"{packet[IP].src}:{tcp.sport}->{packet[IP].dst}:{tcp.dport}"
            self.packet_stats['TCP']['connections'].add(conn)
            self.packet_stats['TCP']['count'] += 1
            self.packet_stats['TCP']['bytes'] += len(packet)
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            analysis['UDP'] = {
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'length': udp.len
            }
            
            flow = f"{packet[IP].src}:{udp.sport}->{packet[IP].dst}:{udp.dport}"
            self.packet_stats['UDP']['flows'].add(flow)
            self.packet_stats['UDP']['count'] += 1
            self.packet_stats['UDP']['bytes'] += len(packet)
            
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            analysis['ICMP'] = {
                'type': icmp.type,
                'code': icmp.code
            }
            
            icmp_type = icmp.type
            if icmp_type not in self.packet_stats['ICMP']['types']:
                self.packet_stats['ICMP']['types'][icmp_type] = 0
            self.packet_stats['ICMP']['types'][icmp_type] += 1
            self.packet_stats['ICMP']['count'] += 1
            self.packet_stats['ICMP']['bytes'] += len(packet)
            
        return analysis
    
    def analyze_payload(self, packet):
        """Analyze packet payload safely"""
        payload_info = {
            'has_payload': False,
            'payload_size': 0,
            'content_type': 'binary',
            'http_info': None,
            'dns_info': None
        }
        
        try:
            # Check for HTTP traffic
            if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    payload_info['has_payload'] = True
                    payload_info['payload_size'] = len(payload)
                    
                    # Try to decode as text
                    try:
                        payload_text = payload.decode('utf-8', errors='ignore')
                        payload_info['content_type'] = 'text'
                        
                        # Parse HTTP requests
                        if payload_text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                            http_info = self.parse_http_request(payload_text)
                            if http_info:
                                payload_info['http_info'] = http_info
                                self.http_requests.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'src_ip': packet[IP].src,
                                    'dst_ip': packet[IP].dst,
                                    **http_info
                                })
                    except UnicodeDecodeError:
                        payload_info['content_type'] = 'binary'
            
            # Check for DNS traffic
            elif packet.haslayer(UDP) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
                if packet.haslayer(DNS):
                    dns_info = self.parse_dns_packet(packet[DNS])
                    payload_info['dns_info'] = dns_info
                    
        except Exception as e:
            print(f"Error analyzing payload: {e}")
            
        return payload_info
    
    def parse_http_request(self, payload_text):
        """Parse HTTP request safely"""
        try:
            lines = payload_text.split('\r\n')
            if not lines:
                return None
                
            # Parse request line
            request_parts = lines[0].split(' ')
            if len(request_parts) >= 3:
                method, path, version = request_parts[0], request_parts[1], request_parts[2]
            else:
                return None
                
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            return {
                'method': method,
                'path': path,
                'version': version,
                'host': headers.get('host', ''),
                'user_agent': headers.get('user-agent', '')[:100]  # Truncate long user agents
            }
        except Exception as e:
            print(f"Error parsing HTTP: {e}")
            return None
    
    def parse_dns_packet(self, dns):
        """Parse DNS packet safely"""
        try:
            return {
                'id': dns.id,
                'qr': dns.qr,
                'opcode': dns.opcode,
                'query_count': dns.qdcount,
                'answer_count': dns.ancount
            }
        except Exception as e:
            print(f"Error parsing DNS: {e}")
            return None
    
    def security_check(self, packet):
        """Basic security analysis"""
        alerts = []
        
        try:
            # Check for suspicious ports
            suspicious_ports = [135, 139, 445, 1433, 3389, 5900]
            
            if packet.haslayer(TCP):
                if packet[TCP].dport in suspicious_ports or packet[TCP].sport in suspicious_ports:
                    alerts.append(f"Suspicious port: {packet[TCP].dport}")
            
            # Check for large packets
            if len(packet) > 1400:
                alerts.append(f"Large packet: {len(packet)} bytes")
            
            if alerts:
                self.suspicious_activity.append({
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'alerts': alerts
                })
        except Exception as e:
            print(f"Error in security check: {e}")
        
        return {
            'alerts': alerts,
            'risk_level': 'HIGH' if len(alerts) > 2 else 'MEDIUM' if alerts else 'LOW'
        }
    
    def print_packet_summary(self, analysis):
        """Print a summary of interesting packets"""
        basic = analysis['basic_info']
        print(f"[{analysis['packet_number']:3d}] {basic['src_ip']} -> {basic['dst_ip']} "
              f"({basic['size']} bytes)")
        
        if analysis['security_analysis']['alerts']:
            print(f"      ALERTS: {', '.join(analysis['security_analysis']['alerts'])}")
            
        if analysis['payload_analysis']['http_info']:
            http = analysis['payload_analysis']['http_info']
            print(f"      HTTP: {http['method']} {http['path']} (Host: {http['host']})")
    
    def export_analysis_results(self):
        """Export analysis results"""
        results = {
            'summary': {
                'total_packets_analyzed': self.packet_count,
                'packets_with_ip': sum(proto['count'] for proto_name, proto in self.packet_stats.items() if proto_name != 'Other'),
                'non_ip_packets': self.packet_stats['Other']['count'],
                'tcp_packets': self.packet_stats['TCP']['count'],
                'udp_packets': self.packet_stats['UDP']['count'],
                'icmp_packets': self.packet_stats['ICMP']['count'],
                'unique_tcp_connections': len(self.packet_stats['TCP']['connections']),
                'unique_udp_flows': len(self.packet_stats['UDP']['flows']),
                'http_requests_captured': len(self.http_requests),
                'security_alerts': len(self.suspicious_activity)
            },
            'protocol_breakdown': {
                'TCP': f"{self.packet_stats['TCP']['count']} packets, {self.packet_stats['TCP']['bytes']} bytes",
                'UDP': f"{self.packet_stats['UDP']['count']} packets, {self.packet_stats['UDP']['bytes']} bytes",
                'ICMP': f"{self.packet_stats['ICMP']['count']} packets, {self.packet_stats['ICMP']['bytes']} bytes",
                'Other': f"{self.packet_stats['Other']['count']} packets, {self.packet_stats['Other']['bytes']} bytes"
            }
        }
        
        # Save results
        with open('advanced_analysis.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        return results

def main():
    print("=== Advanced Packet Analysis Demo (Fixed) ===")
    print("Capturing packets for 30 seconds with deep inspection...")
    print("This version properly handles all packet types.\n")
    
    analyzer = AdvancedPacketAnalyzer()
    
    try:
        sniff(
            filter="",  # Capture all packets, filter in handler
            prn=analyzer.deep_packet_inspection,
            store=False,
            timeout=30
        )
    except KeyboardInterrupt:
        print("\nCapture interrupted by user")
    except Exception as e:
        print(f"Capture error: {e}")
    
    print("\n" + "="*50)
    results = analyzer.export_analysis_results()
    
    print("ANALYSIS RESULTS:")
    print(f"• Total packets: {results['summary']['total_packets_analyzed']}")
    print(f"• IP packets: {results['summary']['packets_with_ip']}")
    print(f"• Non-IP packets: {results['summary']['non_ip_packets']}")
    print(f"• TCP connections: {results['summary']['unique_tcp_connections']}")
    print(f"• HTTP requests: {results['summary']['http_requests_captured']}")
    print(f"• Security alerts: {results['summary']['security_alerts']}")
    print(f"\nDetailed results saved to: advanced_analysis.json")

if __name__ == "__main__":
    main()
