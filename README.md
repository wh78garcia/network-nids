# Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

This project implements a Network Intrusion Detection System (NIDS) server with an accompanying test client that generates both normal and malicious network traffic for testing purposes. The system is designed to detect various types of suspicious network activities in real-time.

## Table of Contents
- [Features](#features)
- [Components](#components)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Capabilities](#detection-capabilities)
- [Project Structure](#project-structure)


## Features

- Real-time network traffic monitoring
- Detection of multiple attack patterns
- Configurable detection rules
- Periodic statistics reporting
- Comprehensive logging system
- Test traffic generation

## Components

### NIDS Server (`server.py`)
- Monitors specified network interfaces
- Detects and logs suspicious activities
- Provides periodic statistics (every 10 seconds)
- Runs with root privileges

### Test Client (`client.py`)
- Generates both normal and malicious traffic:
  - HTTP requests
  - DNS queries
  - ICMP packets
  - Port scanning attempts
  - DNS tunneling attempts
  - Large ICMP packets

## Installation

1.Prerequisites
```
Python 3.8

Scapy library (pip install scapy)

Root/Administrator privileges
```

2. Clone the repository:

```bash
git clone https://github.com/yourusername/network-nids.git
cd network-nids
```

3.Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1.Start the NIDS server (requires root):
```bash
sudo python server.py
```

2.Run the test client (in another terminal):
```bash
python client.py
or
sudo python client.py
```


## Detection Capabilities
| Attack Type     | Detection Method     |
|---------|---------|
| Port Scanning | Multiple TCP SYN packets |
| DNS Tunneling | Abnormally long DNS queries (>30 chars) |
| Large ICMP Packets | ICMP packets >1000 bytes |



## Project Structure
```
network-nids/
├── server.py           # NIDS monitoring server
├── client.py           # Traffic generation client
├── requirements.txt    # Python dependencies
├── nids.log            # Generated log file
└── README.md           # Documentation
```