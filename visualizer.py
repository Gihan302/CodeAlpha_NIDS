# visualizer.py - Alert Visualization Dashboard
import json
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter
import pandas as pd

class IDSVisualizer:
    def __init__(self, log_file='alerts.log'):
        self.log_file = log_file
        self.alerts = self.load_alerts()
    
    def load_alerts(self):
        """Load alerts from log file"""
        alerts = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        alerts.append(json.loads(line))
        except FileNotFoundError:
            print("No alerts found. Run the IDS first to generate alerts.")
            return []
        return alerts
    
    def plot_alert_types(self):
        """Plot distribution of alert types"""
        if not self.alerts:
            print("No alerts to visualize")
            return
        
        alert_types = [alert['type'] for alert in self.alerts]
        type_counts = Counter(alert_types)
        
        plt.figure(figsize=(10, 6))
        plt.bar(type_counts.keys(), type_counts.values(), color='#667eea')
        plt.xlabel('Alert Type', fontsize=12)
        plt.ylabel('Count', fontsize=12)
        plt.title('Distribution of Alert Types', fontsize=14, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig('alert_types.png', dpi=300)
        plt.show()
        print("✅ Saved: alert_types.png")
    
    def plot_severity_distribution(self):
        """Plot distribution of alert severities"""
        if not self.alerts:
            return
        
        severities = [alert['severity'] for alert in self.alerts]
        severity_counts = Counter(severities)
        
        colors = {
            'LOW': '#FCD34D',
            'MEDIUM': '#FB923C',
            'HIGH': '#EF4444',
            'CRITICAL': '#991B1B'
        }
        
        plt.figure(figsize=(8, 8))
        plt.pie(
            severity_counts.values(),
            labels=severity_counts.keys(),
            autopct='%1.1f%%',
            colors=[colors.get(sev, '#999') for sev in severity_counts.keys()],
            startangle=90
        )
        plt.title('Alert Severity Distribution', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig('severity_distribution.png', dpi=300)
        plt.show()
        print("✅ Saved: severity_distribution.png")
    
    def plot_timeline(self):
        """Plot alerts over time"""
        if not self.alerts:
            return
        
        timestamps = [datetime.fromisoformat(alert['timestamp']) for alert in self.alerts]
        timestamps.sort()
        
        # Count alerts per minute
        alert_counts = Counter([ts.strftime('%H:%M') for ts in timestamps])
        
        plt.figure(figsize=(12, 6))
        plt.plot(list(alert_counts.keys()), list(alert_counts.values()), 
                marker='o', linewidth=2, markersize=8, color='#667eea')
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Number of Alerts', fontsize=12)
        plt.title('Alert Timeline', fontsize=14, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('alert_timeline.png', dpi=300)
        plt.show()
        print("✅ Saved: alert_timeline.png")
    
    def plot_top_ips(self, top_n=10):
        """Plot top source IPs generating alerts"""
        if not self.alerts:
            return
        
        ips = [alert['src_ip'] for alert in self.alerts]
        ip_counts = Counter(ips).most_common(top_n)
        
        ips_list = [ip for ip, _ in ip_counts]
        counts = [count for _, count in ip_counts]
        
        plt.figure(figsize=(10, 6))
        plt.barh(ips_list, counts, color='#EF4444')
        plt.xlabel('Number of Alerts', fontsize=12)
        plt.ylabel('Source IP', fontsize=12)
        plt.title(f'Top {top_n} IPs Generating Alerts', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig('top_ips.png', dpi=300)
        plt.show()
        print("✅ Saved: top_ips.png")
    
    def generate_report(self):
        """Generate comprehensive visualization report"""
        if not self.alerts:
            print("No alerts to visualize. Run the IDS first!")
            return
        
        print(f"\n{'='*60}")
        print("📊 GENERATING VISUALIZATION REPORT")
        print(f"{'='*60}")
        print(f"Total Alerts: {len(self.alerts)}\n")
        
        self.plot_alert_types()
        self.plot_severity_distribution()
        self.plot_timeline()
        self.plot_top_ips()
        
        print(f"\n{'='*60}")
        print("✅ All visualizations generated successfully!")
        print(f"{'='*60}\n")

if __name__ == "__main__":
    visualizer = IDSVisualizer()
    visualizer.generate_report()