# CodeAlpha_NIDS

## Network Intrusion Detection System - Task 4

A Python-based Network Intrusion Detection System (NIDS) that monitors network traffic in real-time and detects suspicious activities.

## Features

- ✅ Real-time network traffic monitoring
- ✅ Port scan detection
- ✅ SYN flood attack detection
- ✅ Suspicious port access detection
- ✅ Threat intelligence integration
- ✅ Packet rate anomaly detection
- ✅ Alert generation and logging
- ✅ Visualization dashboard with graphs

## Detection Capabilities

### 1. Port Scanning
Detects when an IP scans multiple ports (potential reconnaissance)

### 2. SYN Flood Attacks
Identifies DDoS attempts through excessive SYN packets

### 3. Suspicious Ports
Monitors access to commonly exploited ports (Telnet, SMB, RDP, etc.)

### 4. Malicious IPs
Checks traffic against threat intelligence database

### 5. Traffic Anomalies
Detects abnormal packet rates from single sources

## Requirements
```
Python 3.8+
scapy
matplotlib
pandas
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/CodeAlpha_NIDS.git
cd CodeAlpha_NIDS
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Run IDS Monitor
```bash
# Windows (Run as Administrator)
python nids.py

# Linux/Mac
sudo python3 nids.py
```

### Generate Visualizations

After running the IDS and generating alerts:
```bash
python visualizer.py
```

## Configuration

### Detection Rules (rules.json)
```json
{
    "port_scan_threshold": 10,
    "syn_flood_threshold": 50,
    "packet_rate_threshold": 100,
    "suspicious_ports": [23, 135, 139, 445, 3389],
    "time_window": 10
}
```

### Threat Intelligence (threat_intel.json)

Add known malicious IPs:
```json
{
    "malicious_ips": [
        "192.0.2.1",
        "198.51.100.1"
    ]
}
```

## Output

### Console Alerts
Real-time alerts displayed in console with severity levels

### Log File (alerts.log)
JSON-formatted alerts for analysis

### Visualizations
- Alert type distribution
- Severity distribution pie chart
- Alert timeline
- Top source IPs

## Sample Output
```
==================================================
🚨 ALERT: PORT_SCAN - HIGH
==================================================
Timestamp: 2024-02-14T10:30:45
Source IP: 192.168.1.100
Details: Port scan detected from 192.168.1.100. Scanned 15 ports
==================================================
```

## Architecture
```
┌─────────────────┐
│  Network Traffic│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Packet Capture │
│   (Raw Socket)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Packet Analysis │
│  & Parsing      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Detection Rules │
│   & Checks      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Alert Generation│
│   & Logging     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Visualization  │
│   Dashboard     │
└─────────────────┘
```

## Learning Outcomes

- Network traffic analysis
- Intrusion detection techniques
- Real-time monitoring systems
- Threat intelligence integration
- Security alert management
- Data visualization

## Author

**[Your Name]**  
CodeAlpha Cybersecurity Intern

## Acknowledgments

Thank you to CodeAlpha for this learning opportunity!

## License

Educational project - CodeAlpha Internship Program