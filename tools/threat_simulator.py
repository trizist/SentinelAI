#!/usr/bin/env python3
"""
CyberCare Threat Simulator

This script generates synthetic security threats and submits them to
the CyberCare API for analysis. It's useful for testing and demonstrating
the threat detection and response capabilities of the system.
"""

import requests
import random
import time
import ipaddress
import argparse
import json
from datetime import datetime, timedelta

# Default configuration
DEFAULT_CONFIG = {
    "api_url": "http://localhost:8005/api/v1/threats/analyze",
    "batch_url": "http://localhost:8005/api/v1/threats/batch-analyze",
    "interval_min": 5,
    "interval_max": 15,
    "batch_size": 5
}

# Attack patterns with realistic signatures
ATTACK_PATTERNS = {
    "port_scan": {
        "description": "Systematic probing of network ports",
        "protocols": ["TCP", "UDP"],
        "techniques": ["T1046"],
        "additional_data": {
            "scan_type": ["SYN", "FIN", "XMAS", "NULL"],
            "ports": [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
        }
    },
    "sql_injection": {
        "description": "Attempt to inject SQL commands",
        "protocols": ["HTTP"],
        "techniques": ["T1190"],
        "additional_data": {
            "method": "POST",
            "target_path": ["/login", "/search", "/admin", "/api/data"],
            "payloads": ["' OR 1=1 --", "'; DROP TABLE users; --", "1'; SELECT * FROM users; --"]
        }
    },
    "brute_force": {
        "description": "Repeated login attempts",
        "protocols": ["HTTP", "SSH", "FTP", "SMTP"],
        "techniques": ["T1110"],
        "additional_data": {
            "target_service": ["ssh", "ftp", "smtp", "web_login"],
            "username": ["admin", "root", "user", "administrator"],
            "attempts": lambda: random.randint(10, 100)
        }
    },
    "malware_communication": {
        "description": "Communication with known malicious domains",
        "protocols": ["HTTP", "HTTPS", "DNS"],
        "techniques": ["T1071"],
        "additional_data": {
            "domains": ["malicious-domain.com", "evil-server.net", "data-exfil.xyz"],
            "data_size": lambda: random.randint(1024, 10240)
        }
    },
    "ddos_attack": {
        "description": "Distributed Denial of Service attack pattern",
        "protocols": ["TCP", "UDP", "ICMP"],
        "techniques": ["T1498"],
        "additional_data": {
            "packets_per_second": lambda: random.randint(10000, 1000000),
            "attack_type": ["SYN flood", "UDP flood", "HTTP flood", "ICMP flood"]
        }
    },
    "xss_attempt": {
        "description": "Cross-site scripting attack attempt",
        "protocols": ["HTTP"],
        "techniques": ["T1059.007"],
        "additional_data": {
            "method": "GET",
            "target_path": ["/comment", "/profile", "/message"],
            "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        }
    },
    "data_exfiltration": {
        "description": "Suspicious data transfer",
        "protocols": ["HTTP", "HTTPS", "DNS", "FTP"],
        "techniques": ["T1048"],
        "additional_data": {
            "data_type": ["database", "documents", "source_code", "credentials"],
            "data_size_mb": lambda: round(random.uniform(0.5, 50), 2)
        }
    }
}

class ThreatSimulator:
    def __init__(self, config=None):
        """Initialize the threat simulator with configuration"""
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
        
        # Stats tracking
        self.stats = {
            "threats_sent": 0,
            "successful_submissions": 0,
            "failed_submissions": 0,
            "start_time": datetime.now(),
            "by_type": {}
        }
    
    def random_ip(self, internal=False):
        """Generate a random IP address"""
        if internal:
            # Generate internal network IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
            prefix = random.choice([
                "10.",
                "192.168.",
                f"172.{random.randint(16, 31)}."
            ])
            
            if prefix.startswith("10."):
                return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            elif prefix.startswith("192.168."):
                return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                return f"{prefix}{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            # Generate external IPs (avoiding private ranges)
            while True:
                ip = str(ipaddress.IPv4Address(random.randint(0, 2**32-1)))
                addr = ipaddress.IPv4Address(ip)
                # Skip private, loopback, and reserved addresses for external IPs
                if not (addr.is_private or addr.is_loopback or addr.is_reserved):
                    return ip
    
    def generate_threat(self, attack_type=None):
        """Generate a single threat of specified or random type"""
        if not attack_type or attack_type not in ATTACK_PATTERNS:
            attack_type = random.choice(list(ATTACK_PATTERNS.keys()))
            
        attack = ATTACK_PATTERNS[attack_type]
        
        # Common threat data
        destination_ip = self.random_ip(internal=True)
        source_ip = self.random_ip(internal=False)
        protocol = random.choice(attack["protocols"])
        
        # Process additional data
        additional_data = {}
        for key, values in attack["additional_data"].items():
            if callable(values):
                additional_data[key] = values()
            elif isinstance(values, list):
                additional_data[key] = random.choice(values)
            else:
                additional_data[key] = values
        
        # Create threat data structure
        threat_data = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "behavior": attack_type,
            "timestamp": datetime.utcnow().isoformat(),
            "additional_data": additional_data
        }
        
        return threat_data
    
    def send_threat(self, threat_data):
        """Send a single threat to the API and return the result"""
        try:
            response = requests.post(self.config["api_url"], json=threat_data, timeout=10)
            
            if response.status_code in (200, 202):
                print(f"✅ Threat sent: {threat_data['behavior']} from {threat_data['source_ip']}")
                print(f"   Response: {response.status_code}")
                print(f"   Details: {json.dumps(response.json(), indent=2)[:200]}...")
                return True
            else:
                print(f"❌ Failed to send threat: {response.status_code}")
                print(f"   Error: {response.text[:100]}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending threat: {str(e)}")
            return False
    
    def send_batch(self, count=None):
        """Send a batch of threats for analysis"""
        if not count:
            count = self.config["batch_size"]
            
        threats = []
        for _ in range(count):
            threats.append(self.generate_threat())
            
        try:
            response = requests.post(self.config["batch_url"], json=threats, timeout=30)
            
            if response.status_code in (200, 202):
                print(f"✅ Batch of {count} threats sent")
                print(f"   Response: {response.status_code}")
                print(f"   Details: {json.dumps(response.json(), indent=2)}")
                self.stats["threats_sent"] += count
                self.stats["successful_submissions"] += 1
                return response.json().get("job_id")
            else:
                print(f"❌ Failed to send batch: {response.status_code}")
                print(f"   Error: {response.text[:100]}")
                self.stats["failed_submissions"] += 1
                return None
                
        except Exception as e:
            print(f"❌ Error sending batch: {str(e)}")
            self.stats["failed_submissions"] += 1
            return None
    
    def check_job_status(self, job_id):
        """Check the status of a batch job"""
        try:
            status_url = f"{self.config['api_url'].rsplit('/', 1)[0]}/status/{job_id}"
            response = requests.get(status_url, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ Failed to check job status: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Error checking job status: {str(e)}")
            return None
    
    def run_continuous(self, duration_minutes=None, max_threats=None):
        """Run a continuous simulation for a specified duration or count"""
        print(f"🚀 Starting continuous threat simulation")
        print(f"   API endpoint: {self.config['api_url']}")
        
        count = 0
        start_time = datetime.now()
        end_time = None
        
        if duration_minutes:
            end_time = start_time + timedelta(minutes=duration_minutes)
            print(f"   Will run until: {end_time}")
        
        if max_threats:
            print(f"   Will generate {max_threats} threats")
        
        try:
            while True:
                # Check if we should stop
                if max_threats and count >= max_threats:
                    break
                    
                if end_time and datetime.now() >= end_time:
                    break
                
                # Generate and send a threat
                threat = self.generate_threat()
                success = self.send_threat(threat)
                
                # Update stats
                count += 1
                self.stats["threats_sent"] += 1
                
                if success:
                    self.stats["successful_submissions"] += 1
                    attack_type = threat["behavior"]
                    if attack_type not in self.stats["by_type"]:
                        self.stats["by_type"][attack_type] = 0
                    self.stats["by_type"][attack_type] += 1
                else:
                    self.stats["failed_submissions"] += 1
                
                # Wait before next threat
                sleep_time = random.randint(
                    self.config["interval_min"], 
                    self.config["interval_max"]
                )
                print(f"⏱️  Waiting {sleep_time} seconds before next threat...")
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            print("\n⚠️  Simulation interrupted by user")
        
        # Print final stats
        self.print_stats()
    
    def print_stats(self):
        """Print simulation statistics"""
        duration = datetime.now() - self.stats["start_time"]
        duration_str = str(duration).split('.')[0]  # Remove microseconds
        
        print("\n📊 Simulation Statistics:")
        print(f"   Duration: {duration_str}")
        print(f"   Total threats sent: {self.stats['threats_sent']}")
        print(f"   Successful submissions: {self.stats['successful_submissions']}")
        print(f"   Failed submissions: {self.stats['failed_submissions']}")
        
        if self.stats['by_type']:
            print("\n   Threats by type:")
            for attack_type, count in self.stats['by_type'].items():
                print(f"     - {attack_type}: {count}")

def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(description="CyberCare Threat Simulator")
    
    parser.add_argument("--url", help="API URL for threat analysis", 
                        default=DEFAULT_CONFIG["api_url"])
    parser.add_argument("--batch-url", help="API URL for batch analysis", 
                        default=DEFAULT_CONFIG["batch_url"])
    parser.add_argument("--batch", help="Send threats in batch mode", 
                        action="store_true")
    parser.add_argument("--batch-size", help="Number of threats in each batch", 
                        type=int, default=DEFAULT_CONFIG["batch_size"])
    parser.add_argument("--continuous", help="Run in continuous mode", 
                        action="store_true")
    parser.add_argument("--min-interval", help="Minimum seconds between threats", 
                        type=int, default=DEFAULT_CONFIG["interval_min"])
    parser.add_argument("--max-interval", help="Maximum seconds between threats", 
                        type=int, default=DEFAULT_CONFIG["interval_max"])
    parser.add_argument("--duration", help="Duration to run in minutes", 
                        type=int)
    parser.add_argument("--count", help="Number of threats to generate", 
                        type=int, default=1)
    parser.add_argument("--attack-type", help="Specific attack type to simulate",
                        choices=ATTACK_PATTERNS.keys())
    
    args = parser.parse_args()
    
    config = {
        "api_url": args.url,
        "batch_url": args.batch_url,
        "interval_min": args.min_interval,
        "interval_max": args.max_interval,
        "batch_size": args.batch_size
    }
    
    simulator = ThreatSimulator(config)
    
    if args.continuous:
        simulator.run_continuous(args.duration, args.count)
    elif args.batch:
        simulator.send_batch(args.count)
    else:
        # Single threat mode
        for _ in range(args.count):
            threat = simulator.generate_threat(args.attack_type)
            simulator.send_threat(threat)
            if args.count > 1 and _ < args.count - 1:
                sleep_time = random.randint(args.min_interval, args.max_interval)
                print(f"⏱️  Waiting {sleep_time} seconds before next threat...")
                time.sleep(sleep_time)
    
    print("✨ Simulation complete")

if __name__ == "__main__":
    main()