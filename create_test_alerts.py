# create_test_alerts.py - Generate test alerts for visualization
import json
from datetime import datetime, timedelta

def create_sample_alerts():
    """Create sample alerts for testing visualizer"""
    
    alerts = []
    base_time = datetime.now()
    
    # Sample alert 1: Port Scan
    alerts.append({
        'type': 'PORT_SCAN',
        'severity': 'HIGH',
        'src_ip': '192.168.1.100',
        'timestamp': (base_time - timedelta(minutes=10)).isoformat(),
        'details': 'Port scan detected from 192.168.1.100. Scanned 15 ports: [22, 80, 443, 8080, 3389, ...]'
    })
    
    # Sample alert 2: SYN Flood
    alerts.append({
        'type': 'SYN_FLOOD',
        'severity': 'CRITICAL',
        'src_ip': '203.0.113.5',
        'timestamp': (base_time - timedelta(minutes=8)).isoformat(),
        'details': 'SYN flood attack detected from 203.0.113.5. 75 SYN packets in 10 seconds'
    })
    
    # Sample alert 3: Malicious IP
    alerts.append({
        'type': 'MALICIOUS_IP',
        'severity': 'CRITICAL',
        'src_ip': '45.142.120.10',
        'timestamp': (base_time - timedelta(minutes=6)).isoformat(),
        'details': 'Traffic from known malicious IP: 45.142.120.10'
    })
    
    # Sample alert 4: Suspicious Port
    alerts.append({
        'type': 'SUSPICIOUS_PORT',
        'severity': 'MEDIUM',
        'src_ip': '192.168.1.105',
        'timestamp': (base_time - timedelta(minutes=5)).isoformat(),
        'details': 'Access to suspicious port 445 from 192.168.1.105'
    })
    
    # Sample alert 5: High Packet Rate
    alerts.append({
        'type': 'HIGH_PACKET_RATE',
        'severity': 'MEDIUM',
        'src_ip': '192.168.1.100',
        'timestamp': (base_time - timedelta(minutes=4)).isoformat(),
        'details': 'Abnormal packet rate from 192.168.1.100: 150 packets in 10 seconds'
    })
    
    # Sample alert 6: Another Port Scan
    alerts.append({
        'type': 'PORT_SCAN',
        'severity': 'HIGH',
        'src_ip': '192.168.1.110',
        'timestamp': (base_time - timedelta(minutes=3)).isoformat(),
        'details': 'Port scan detected from 192.168.1.110. Scanned 20 ports'
    })
    
    # Sample alert 7: Another SYN Flood
    alerts.append({
        'type': 'SYN_FLOOD',
        'severity': 'CRITICAL',
        'src_ip': '198.51.100.15',
        'timestamp': (base_time - timedelta(minutes=2)).isoformat(),
        'details': 'SYN flood attack detected from 198.51.100.15. 120 SYN packets in 10 seconds'
    })
    
    # Sample alert 8: Suspicious Port
    alerts.append({
        'type': 'SUSPICIOUS_PORT',
        'severity': 'MEDIUM',
        'src_ip': '192.168.1.100',
        'timestamp': (base_time - timedelta(minutes=1)).isoformat(),
        'details': 'Access to suspicious port 3389 from 192.168.1.100'
    })
    
    # Write alerts to file
    with open('alerts.log', 'w') as f:
        for alert in alerts:
            f.write(json.dumps(alert) + '\n')
    
    print(f"✅ Created {len(alerts)} sample alerts in alerts.log")
    print("\nAlert Summary:")
    print(f"  PORT_SCAN: 2 alerts")
    print(f"  SYN_FLOOD: 2 alerts")
    print(f"  MALICIOUS_IP: 1 alert")
    print(f"  SUSPICIOUS_PORT: 2 alerts")
    print(f"  HIGH_PACKET_RATE: 1 alert")
    print("\nNow run: python visualizer.py")

if __name__ == "__main__":
    create_sample_alerts()