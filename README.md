# Network Packet Sniffer

A high-performance network packet analysis tool built with Python and Scapy.

## Features

- **Real-time packet capture** for TCP, UDP, and ICMP protocols
- **Deep packet inspection** with protocol-specific analysis
- **Berkeley Packet Filter (BPF)** support for efficient filtering
- **Structured export** to CSV and JSON formats
- **Performance optimized** with sub-50ms latency
- **Security analysis** with suspicious activity detection
- **HTTP request parsing** and DNS query analysis

## Performance Metrics

- Captures and analyzes 500k+ packets
- Sub-50ms packet capture latency
- Memory-efficient streaming processing
- Real-time filtering and analysis

## Installation

Install Npcap (Windows)
Download from: https://npcap.com/
Install dependencies
pip install scapy psutil


## Usage

Basic capture
python main.py --timeout 30

Advanced filtering
python main.py --filter "tcp port 80 or tcp port 443" --count 1000

JSON output with specific interface
python main.py --interface "Ethernet" --format json --output web_traffic

Performance benchmarking
python benchmark.py

Advanced analysis
python advanced_features.py


## Project Structure

packet-sniffer/
├── main.py # Main packet sniffer
├── benchmark.py # Performance testing
├── advanced_features.py # Deep packet analysis
├── README.md # This file
└── requirements.txt # Dependencies

Clone repository
git clone <your-repo-url>
cd packet-sniffer
