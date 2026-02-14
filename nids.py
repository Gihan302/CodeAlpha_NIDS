# nids.py - Network Intrusion Detection System
import socket
import struct
import json
import time
from datetime import datetime
from collections import defaultdict, Counter
import threading

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'

class NetworkIDS:
    def __init__(self):
        self.alerts = []
        self.packet_count = 0
        self.start_time = time.time()
        
        # Track connections for detection
        self.connection_tracker = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)
        self.syn_flood_tracker = defaultdict(int)
        self.packet_rate_tracker = defaultdict(list)
        
        # Load configuration
        self.load_rules()
        self.load_threat_intel()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'alerts_generated': 0,
            'port_scans_detected': 0,
            'syn_floods_detected': 0,
            'suspicious_ips': set()
        }
        
    def load_rules(self):
        """Load detection rules from file"""
        try:
            with open('rules.json', 'r') as f:
                self.rules = json.load(f)
        except FileNotFoundError:
            # Default rules
            self.rules = {
                "port_scan_threshold": 10,  # ports per IP
                "syn_flood_threshold": 50,   # SYN packets per second
                "packet_rate_threshold": 100, # packets per second
                "suspicious_ports": [23, 135, 139, 445, 3389],  # Telnet, NetBIOS, SMB, RDP
                "time_window": 10  # seconds
            }
            self.save_rules()
            
    def save_rules(self):
        """Save detection rules to file"""
        with open('rules.json', 'w') as f:
            json.dump(self.rules, f, indent=4)
            
    def load_threat_intel(self):
        """Load known malicious IPs"""
        try:
            with open('threat_intel.json', 'r') as f:
                data = json.load(f)
                self.malicious_ips = set(data.get('malicious_ips', []))
        except FileNotFoundError:
            # Sample malicious IPs (for demonstration)
            self.malicious_ips = {
                '192.0.2.1',  # Example malicious IP
                '198.51.100.1'
            }
            self.save_threat_intel()
            
    def save_threat_intel(self):
        """Save threat intelligence to file"""
        with open('threat_intel.json', 'w') as f:
            json.dump({'malicious_ips': list(self.malicious_ips)}, f, indent=4)
    
    def create_socket(self):
        """Create raw socket for packet capture"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            host = socket.gethostbyname(socket.gethostname())
            s.bind((host, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return s
        except PermissionError:
            print(f"{Colors.RED}Error: Administrator privileges required!{Colors.END}")
            exit(1)
            
    def parse_ip_header(self, data):
        """Parse IP header from packet"""
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_ihl = ip_header[0]
        ihl = (version_ihl & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_addr = socket.inet_ntoa(ip_header[8])
        dst_addr = socket.inet_ntoa(ip_header[9])
        return ihl, protocol, src_addr, dst_addr, data[ihl:]
    
    def parse_tcp_header(self, data):
        """Parse TCP header from packet"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        offset_reserved = tcp_header[4]
        tcp_flags = tcp_header[5]
        
        # Extract flags
        flag_syn = (tcp_flags & 0x02) != 0
        flag_ack = (tcp_flags & 0x10) != 0
        flag_fin = (tcp_flags & 0x01) != 0
        flag_rst = (tcp_flags & 0x04) != 0
        
        return src_port, dst_port, flag_syn, flag_ack, flag_fin, flag_rst
    
    def detect_port_scan(self, src_ip, dst_port):
        """Detect port scanning activity"""
        self.port_scan_tracker[src_ip].add(dst_port)
        
        if len(self.port_scan_tracker[src_ip]) >= self.rules['port_scan_threshold']:
            ports = list(self.port_scan_tracker[src_ip])
            alert = {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'src_ip': src_ip,
                'timestamp': datetime.now().isoformat(),
                'details': f'Port scan detected from {src_ip}. Scanned {len(ports)} ports: {ports[:10]}...'
            }
            self.generate_alert(alert)
            self.stats['port_scans_detected'] += 1
            self.port_scan_tracker[src_ip].clear()
            return True
        return False
    
    def detect_syn_flood(self, src_ip, is_syn, is_ack):
        """Detect SYN flood attack"""
        current_time = time.time()
        
        if is_syn and not is_ack:
            self.syn_flood_tracker[src_ip] += 1
            
            # Check rate within time window
            if self.syn_flood_tracker[src_ip] >= self.rules['syn_flood_threshold']:
                alert = {
                    'type': 'SYN_FLOOD',
                    'severity': 'CRITICAL',
                    'src_ip': src_ip,
                    'timestamp': datetime.now().isoformat(),
                    'details': f'SYN flood attack detected from {src_ip}. {self.syn_flood_tracker[src_ip]} SYN packets in {self.rules["time_window"]} seconds'
                }
                self.generate_alert(alert)
                self.stats['syn_floods_detected'] += 1
                self.syn_flood_tracker[src_ip] = 0
                return True
        return False
    
    def detect_suspicious_port(self, dst_port):
        """Detect access to suspicious ports"""
        if dst_port in self.rules['suspicious_ports']:
            return True
        return False
    
    def detect_malicious_ip(self, src_ip):
        """Check if IP is in threat intelligence database"""
        if src_ip in self.malicious_ips:
            alert = {
                'type': 'MALICIOUS_IP',
                'severity': 'CRITICAL',
                'src_ip': src_ip,
                'timestamp': datetime.now().isoformat(),
                'details': f'Traffic from known malicious IP: {src_ip}'
            }
            self.generate_alert(alert)
            self.stats['suspicious_ips'].add(src_ip)
            return True
        return False
    
    def detect_packet_rate_anomaly(self, src_ip):
        """Detect abnormal packet rates"""
        current_time = time.time()
        self.packet_rate_tracker[src_ip].append(current_time)
        
        # Remove old timestamps
        self.packet_rate_tracker[src_ip] = [
            t for t in self.packet_rate_tracker[src_ip]
            if current_time - t <= self.rules['time_window']
        ]
        
        packet_rate = len(self.packet_rate_tracker[src_ip])
        
        if packet_rate >= self.rules['packet_rate_threshold']:
            alert = {
                'type': 'HIGH_PACKET_RATE',
                'severity': 'MEDIUM',
                'src_ip': src_ip,
                'timestamp': datetime.now().isoformat(),
                'details': f'Abnormal packet rate from {src_ip}: {packet_rate} packets in {self.rules["time_window"]} seconds'
            }
            self.generate_alert(alert)
            self.packet_rate_tracker[src_ip].clear()
            return True
        return False
    
    def generate_alert(self, alert):
        """Generate and log security alert"""
        self.alerts.append(alert)
        self.stats['alerts_generated'] += 1
        
        # Print alert to console
        severity_colors = {
            'LOW': Colors.YELLOW,
            'MEDIUM': Colors.MAGENTA,
            'HIGH': Colors.RED,
            'CRITICAL': f"{Colors.BOLD}{Colors.RED}"
        }
        
        color = severity_colors.get(alert['severity'], Colors.WHITE)
        
        print(f"\n{color}{'='*70}{Colors.END}")
        print(f"{color}🚨 ALERT: {alert['type']} - {alert['severity']}{Colors.END}")
        print(f"{color}{'='*70}{Colors.END}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Source IP: {alert['src_ip']}")
        print(f"Details: {alert['details']}")
        print(f"{color}{'='*70}{Colors.END}")
        
        # Log to file
        self.log_alert(alert)
    
    def log_alert(self, alert):
        """Write alert to log file"""
        with open('alerts.log', 'a') as f:
            f.write(f"{json.dumps(alert)}\n")
    
    def analyze_packet(self, data):
        """Analyze packet and run detection rules"""
        self.packet_count += 1
        self.stats['total_packets'] += 1
        
        try:
            # Parse IP header
            ihl, protocol, src_ip, dst_ip, remaining_data = self.parse_ip_header(data)
            
            # Track packet rate
            self.detect_packet_rate_anomaly(src_ip)
            
            # Check threat intelligence
            self.detect_malicious_ip(src_ip)
            
            # TCP packet analysis
            if protocol == 6 and len(remaining_data) >= 20:
                src_port, dst_port, is_syn, is_ack, is_fin, is_rst = self.parse_tcp_header(remaining_data)
                
                # Run detection rules
                self.detect_port_scan(src_ip, dst_port)
                self.detect_syn_flood(src_ip, is_syn, is_ack)
                
                # Check for suspicious ports
                if self.detect_suspicious_port(dst_port):
                    if dst_port not in [80, 443]:  # Don't alert on common ports
                        alert = {
                            'type': 'SUSPICIOUS_PORT',
                            'severity': 'MEDIUM',
                            'src_ip': src_ip,
                            'timestamp': datetime.now().isoformat(),
                            'details': f'Access to suspicious port {dst_port} from {src_ip}'
                        }
                        self.generate_alert(alert)
                
                # Print packet info (limited to avoid spam)
                if self.packet_count % 50 == 0:
                    print(f"{Colors.CYAN}[{self.packet_count}] {src_ip}:{src_port} → {dst_ip}:{dst_port}{Colors.END}")
        
        except Exception as e:
            pass  # Silently ignore malformed packets
    
    def print_statistics(self):
        """Print IDS statistics"""
        runtime = time.time() - self.start_time
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}📊 NIDS STATISTICS{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Runtime: {runtime:.2f} seconds")
        print(f"Total Packets Analyzed: {self.stats['total_packets']}")
        print(f"Alerts Generated: {self.stats['alerts_generated']}")
        print(f"Port Scans Detected: {self.stats['port_scans_detected']}")
        print(f"SYN Floods Detected: {self.stats['syn_floods_detected']}")
        print(f"Suspicious IPs: {len(self.stats['suspicious_ips'])}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")
    
    def start_monitoring(self, duration=60):
        """Start IDS monitoring"""
        print(f"{Colors.GREEN}{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}🛡️  NETWORK INTRUSION DETECTION SYSTEM{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"Starting monitoring for {duration} seconds...")
        print(f"Host: {socket.gethostbyname(socket.gethostname())}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.GREEN}{'='*70}{Colors.END}\n")
        
        sock = self.create_socket()
        end_time = time.time() + duration
        
        try:
            while time.time() < end_time:
                raw_data, addr = sock.recvfrom(65535)
                self.analyze_packet(raw_data)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⚠️  Monitoring stopped by user{Colors.END}")
        finally:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            self.print_statistics()
            print(f"{Colors.GREEN}✅ IDS monitoring completed!{Colors.END}")
            print(f"Alerts logged to: alerts.log\n")

if __name__ == "__main__":
    import sys
    
    # Check admin privileges
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print(f"{Colors.RED}⚠️  Please run as Administrator!{Colors.END}\n")
            sys.exit(1)
    except:
        pass
    
    # Create and start IDS
    ids = NetworkIDS()
    
    # Monitor for 2 minutes (120 seconds) - adjust as needed
    ids.start_monitoring(duration=120)