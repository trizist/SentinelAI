#!/usr/bin/env python3
"""
CyberCare IDS Connector for Snort

This script monitors Snort IDS logs and forwards alerts to the CyberCare API.
It translates Snort alerts into the CyberCare threat format.
"""

import argparse
import json
import os
import re
import requests
import time
import traceback
import datetime
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from db_connector import DatabaseConnector

# Load environment variables if .env exists
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
if os.path.exists(env_path):
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split('=', 1)
                os.environ[key] = value

# Default configuration
DEFAULT_CONFIG = {
    "log_path": "/var/log/snort/alert",
    "api_url": "http://localhost:8000/api/v1/threats/analyze",
    "poll_interval": 10,  # seconds
    "batch_size": 10,
    "batch_mode": False,
    "db_path": os.environ.get("SNORT_DB_PATH", "snort_threats.db"),
    "retry_unsent": os.environ.get("RETRY_UNSENT", "False").lower() in ('true', '1', 't'),
    "retry_interval": int(os.environ.get("RETRY_INTERVAL", "60")),
    "retry_limit": int(os.environ.get("RETRY_LIMIT", "3"))
}

# Behavior mapping based on Snort classification
BEHAVIOR_MAPPING = {
    "Attempted Information Leak": "data_exfiltration",
    "Attempted User Privilege Gain": "privilege_escalation",
    "Web Application Attack": "web_attack",
    "Potential Corporate Privacy Violation": "data_exfiltration",
    "Executable Code was Detected": "malware",
    "A Network Trojan was Detected": "malware",
    "Attempted Denial of Service": "dos",
    "Attempted Administrator Privilege Gain": "privilege_escalation",
    "Successful Administrator Privilege Gain": "privilege_escalation",
    "Successful User Privilege Gain": "privilege_escalation",
    "Potentially Bad Traffic": "malware_c2",
    "Information Leak": "data_exfiltration",
    "Network Scan": "port_scan",
    "Suspicious Login": "brute_force",
    "Unknown Traffic": "suspicious_traffic",
    "Access to a Potentially Vulnerable Web Application": "web_attack",
    "Generic Protocol Command Decode": "protocol_violation"
}

# Fallback behavior patterns based on signature name
BEHAVIOR_PATTERNS = {
    r"SQL[_ ]Injection": "sql_injection",
    r"XSS|Cross[- ]Site": "xss",
    r"Directory[_ ]Traversal": "path_traversal",
    r"Port[_ ]Scan": "port_scan",
    r"Brute[_ ]Force": "brute_force",
    r"DoS|Denial[_ ]of[_ ]Service": "dos",
    r"DNS[_ ]Tunnel": "dns_tunneling",
    r"Command[_ ]Injection": "command_injection",
    r"Data[_ ]Exfiltration": "data_exfiltration",
    r"Malware": "malware",
    r"C2|Command[_ ]and[_ ]Control": "malware_c2"
}

class SnortAlert:
    """Represents a parsed Snort alert"""
    
    # Regular expressions for parsing Snort log entries
    ALERT_PATTERN = r'\[\*\*\] \[(.*?)\] (.*?) \[\*\*\]'
    CLASSIFICATION_PATTERN = r'\[Classification: (.*?)\] \[Priority: (\d+)\]'
    IP_PATTERN = r'(\d+/\d+-\d+:\d+:\d+\.\d+) ([\d\.]+):(\d+) -> ([\d\.]+):(\d+)'
    
    def __init__(self, log_entry):
        self.raw_log = log_entry
        self.timestamp = None
        self.signature = None
        self.signature_id = None
        self.signature_rev = None
        self.classification = None
        self.priority = None
        self.source_ip = None
        self.source_port = None
        self.dest_ip = None
        self.dest_port = None
        self.protocol = None
        self.parse_alert(log_entry)
    
    def parse_alert(self, log_entry):
        """Parse a Snort log entry into structured data"""
        lines = log_entry.strip().split('\n')
        
        # Parse alert header
        alert_match = re.search(self.ALERT_PATTERN, lines[0])
        if alert_match:
            sid_str = alert_match.group(1)
            self.signature = alert_match.group(2)
            
            # Parse Snort signature ID and revision
            sid_parts = sid_str.split(':')
            if len(sid_parts) >= 3:
                try:
                    self.signature_id = sid_parts[1]
                    self.signature_rev = sid_parts[2]
                except (IndexError, ValueError) as e:
                    print(f"Error parsing SID parts: {e}")
        
        # Parse classification and priority
        if len(lines) > 1:
            class_match = re.search(self.CLASSIFICATION_PATTERN, lines[1])
            if class_match:
                self.classification = class_match.group(1)
                self.priority = int(class_match.group(2))
        
        # Parse IP addresses, ports, and timestamp
        if len(lines) > 2:
            ip_match = re.search(self.IP_PATTERN, lines[2])
            if ip_match:
                self.timestamp = ip_match.group(1)
                self.source_ip = ip_match.group(2)
                self.source_port = int(ip_match.group(3))
                self.dest_ip = ip_match.group(4)
                self.dest_port = int(ip_match.group(5))
                
                # Infer protocol based on port numbers
                if self.dest_port == 80 or self.dest_port == 443:
                    self.protocol = "HTTP" if self.dest_port == 80 else "HTTPS"
                elif self.dest_port == 22:
                    self.protocol = "SSH"
                elif self.dest_port == 21:
                    self.protocol = "FTP"
                elif self.dest_port == 25 or self.dest_port == 587:
                    self.protocol = "SMTP"
                else:
                    # Default to TCP
                    self.protocol = "TCP"
    
    def to_cybercare_threat(self):
        """Convert Snort alert to CyberCare threat format"""
        # Determine behavior based on classification or signature name
        behavior = "unknown"
        
        # 1. Check if classification directly maps to a known behavior
        if self.classification and self.classification in BEHAVIOR_MAPPING:
            behavior = BEHAVIOR_MAPPING[self.classification]
        else:
            # 2. Try to match signature name against behavior patterns
            for pattern, b_type in BEHAVIOR_PATTERNS.items():
                if self.signature and re.search(pattern, self.signature, re.IGNORECASE):
                    behavior = b_type
                    break
        
        # Additional data to include
        additional_data = {
            "snort_signature_id": self.signature_id,
            "snort_signature_name": self.signature,
            "snort_classification": self.classification,
            "snort_priority": self.priority,
            "source_port": self.source_port,
            "destination_port": self.dest_port,
        }
        
        # Create threat data in CyberCare format
        threat_data = {
            "source_ip": self.source_ip,
            "destination_ip": self.dest_ip,
            "protocol": self.protocol,
            "behavior": behavior,
            "timestamp": self.timestamp,
            "additional_data": additional_data
        }
        
        return threat_data


class SnortLogWatcher:
    """Watches Snort log files and processes new alerts"""
    
    def __init__(self, log_path, api_url, batch_size=10, batch_mode=False, db_path=DEFAULT_CONFIG["db_path"]):
        super().__init__()
        self.log_path = log_path
        self.api_url = api_url
        self.batch_size = batch_size
        self.batch_mode = batch_mode
        self.batch_url = api_url.replace('/analyze', '/batch-analyze') if '/analyze' in api_url else f"{api_url.rstrip('/')}/batch-analyze"
        self.last_position = 0
        self.pending_alerts = []
        
        # Initialize database connector for persistent storage
        try:
            self.db = DatabaseConnector(db_path)
            print(f"Using persistent storage at {db_path}")
        except Exception as e:
            print(f"ERROR: Failed to initialize database: {str(e)}. Using in-memory storage only.")
            self.db = None
        
        # Initialize by checking current file size
        if os.path.exists(log_path):
            self.last_position = 0  # Start from beginning to process all alerts
            print(f"Log path exists: {log_path}, size: {os.path.getsize(log_path)} bytes")
        else:
            print(f"Warning: Log file {log_path} not found")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.src_path == self.log_path:
            print(f"File modified: {event.src_path}")
            self.process_new_alerts()
    
    def process_new_alerts(self):
        """Read and process new alerts from the log file"""
        if not os.path.exists(self.log_path):
            print(f"WARNING: Log file {self.log_path} not found")
            return
        
        # Get current file size
        current_size = os.path.getsize(self.log_path)
        print(f"DEBUG: Processing new alerts. Current file size: {current_size}, last position: {self.last_position}")
        
        # If file was truncated, reset position
        if current_size < self.last_position:
            print(f"DEBUG: Log file was truncated, resetting position from {self.last_position} to 0")
            self.last_position = 0
        
        # If no new content, return
        if current_size == self.last_position:
            print(f"DEBUG: No new content in log file. Size: {current_size}")
            return
        
        # Read new content
        try:
            with open(self.log_path, 'r') as f:
                f.seek(self.last_position)
                new_content = f.read()
                print(f"DEBUG: Read {len(new_content)} bytes of new content from log file")
                self.last_position = current_size
            
            # Process each alert (split by blank lines)
            alerts = [a.strip() for a in new_content.split('\n\n') if a.strip()]
            print(f"DEBUG: Found {len(alerts)} new alerts in content")
            
            batch_threats = []
            
            for alert_text in alerts:
                print(f"DEBUG: Processing alert: {alert_text[:100]}...")
                try:
                    alert = SnortAlert(alert_text)
                    
                    # Convert to CyberCare threat format
                    threat_data = alert.to_cybercare_threat()
                    
                    # If any required fields are missing, skip this alert
                    if not threat_data["source_ip"] or not threat_data["destination_ip"]:
                        print(f"Skipping alert due to missing required fields: {alert_text[:50]}...")
                        continue
                    
                    # Store in persistent storage if available
                    if self.db:
                        try:
                            threat_id = self.db.store_threat(threat_data)
                            print(f"DEBUG: Stored threat {threat_id} in database")
                        except Exception as e:
                            print(f"ERROR: Failed to store threat in database: {str(e)}")
                    
                    if self.batch_mode:
                        # Add to pending alerts for batch processing
                        self.pending_alerts.append(threat_data)
                        
                        # For database batch processing
                        batch_threats.append(threat_data)
                        
                        # If batch size reached, send the batch
                        if len(self.pending_alerts) >= self.batch_size:
                            self.send_batch()
                    else:
                        # Send individual alert
                        self.send_alert(threat_data)
                except Exception as e:
                    print(f"Error processing alert: {str(e)}")
                    print(f"DEBUG: Traceback: {traceback.format_exc()}")
            
            # Store batch in database if in batch mode and database is available
            if self.batch_mode and self.db and batch_threats:
                try:
                    self.db.store_batch(batch_threats)
                    print(f"DEBUG: Stored batch of {len(batch_threats)} threats in database")
                except Exception as e:
                    print(f"ERROR: Failed to store threat batch in database: {str(e)}")
                
        except Exception as e:
            print(f"Error reading log file: {str(e)}")
            print(f"DEBUG: Traceback: {traceback.format_exc()}")
    
    def send_alert(self, threat_data):
        """Send a single alert to the API"""
        try:
            print(f"DEBUG: Sending alert to {self.api_url}")
            print(f"DEBUG: Alert data: {json.dumps(threat_data, indent=2)}")
            
            # Store the threat ID if it exists
            threat_id = threat_data.get('id', None)
            
            response = requests.post(self.api_url, json=threat_data)
            
            if response.status_code == 200:
                print(f"SUCCESS: Alert sent successfully: {response.status_code}")
                print(f"DEBUG: Response data: {json.dumps(response.json(), indent=2)}")
                
                # Update database if available
                if self.db and threat_id:
                    try:
                        self.db.mark_as_submitted(threat_id, True, response.json())
                    except Exception as e:
                        print(f"ERROR: Failed to update threat submission status: {str(e)}")
            else:
                print(f"ERROR: Failed to send alert: HTTP {response.status_code}")
                print(f"DEBUG: Response text: {response.text}")
                
                # Update database if available
                if self.db and threat_id:
                    try:
                        self.db.mark_as_submitted(threat_id, False, None, f"HTTP {response.status_code}: {response.text}")
                    except Exception as e:
                        print(f"ERROR: Failed to update threat submission status: {str(e)}")
                        
        except Exception as e:
            print(f"ERROR: Exception sending alert: {str(e)}")
            print(f"DEBUG: Traceback: {traceback.format_exc()}")
            
            # Update database if available
            if self.db and threat_id:
                try:
                    self.db.mark_as_submitted(threat_id, False, None, str(e))
                except Exception as db_e:
                    print(f"ERROR: Failed to update threat submission status: {str(db_e)}")
    
    def send_batch(self):
        """Send pending alerts as a batch"""
        if not self.pending_alerts:
            return
        
        try:
            print(f"Sending batch of {len(self.pending_alerts)} alerts to {self.batch_url}")
            
            # Store threat IDs for database updates
            threat_ids = [threat.get('id') for threat in self.pending_alerts if 'id' in threat]
            
            response = requests.post(self.batch_url, json=self.pending_alerts)
            
            if response.status_code in (200, 202):
                print(f"Successfully sent batch of {len(self.pending_alerts)} alerts")
                
                # Update database if available
                if self.db and threat_ids:
                    for threat_id in threat_ids:
                        try:
                            self.db.mark_as_submitted(threat_id, True, {'status': 'success', 'batch_size': len(self.pending_alerts)})
                        except Exception as e:
                            print(f"ERROR: Failed to update threat submission status for {threat_id}: {str(e)}")
                
                # Clear pending alerts after successful submission
                self.pending_alerts = []
            else:
                print(f"Failed to send batch: HTTP {response.status_code}, {response.text}")
                
                # Update database if available
                if self.db and threat_ids:
                    error_msg = f"HTTP {response.status_code}: {response.text}"
                    for threat_id in threat_ids:
                        try:
                            self.db.mark_as_submitted(threat_id, False, None, error_msg)
                        except Exception as e:
                            print(f"ERROR: Failed to update threat submission status for {threat_id}: {str(e)}")
        except Exception as e:
            print(f"Error sending batch: {str(e)}")
            print(f"DEBUG: Traceback: {traceback.format_exc()}")
            
            # Update database if available
            if self.db and threat_ids:
                for threat_id in threat_ids:
                    try:
                        self.db.mark_as_submitted(threat_id, False, None, str(e))
                    except Exception as db_e:
                        print(f"ERROR: Failed to update threat submission status for {threat_id}: {str(db_e)}")

class SnortLogEventHandler(FileSystemEventHandler):
    """Event handler to detect log file changes"""
    
    def __init__(self, watcher):
        super().__init__()
        self.watcher = watcher
    
    def on_modified(self, event):
        """Handle file modification events"""
        self.watcher.on_modified(event)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Snort IDS Connector for CyberCare")
    
    parser.add_argument("--log-path", dest="log_path", 
                        default=DEFAULT_CONFIG["log_path"],
                        help=f"Path to Snort alert log file (default: {DEFAULT_CONFIG['log_path']})")
    
    parser.add_argument("--api-url", dest="api_url", 
                        default=DEFAULT_CONFIG["api_url"],
                        help=f"CyberCare API endpoint for threat submission (default: {DEFAULT_CONFIG['api_url']})")
    
    parser.add_argument("--poll-interval", dest="poll_interval", 
                        type=int, default=DEFAULT_CONFIG["poll_interval"],
                        help=f"Polling interval in seconds (default: {DEFAULT_CONFIG['poll_interval']})")
    
    parser.add_argument("--batch", dest="batch_mode", 
                        action="store_true",
                        help="Enable batch mode for alert submission")
    
    parser.add_argument("--batch-size", dest="batch_size", 
                        type=int, default=DEFAULT_CONFIG["batch_size"],
                        help=f"Batch size for alert submission (default: {DEFAULT_CONFIG['batch_size']})")
    
    parser.add_argument("--debug-mode", dest="debug_mode",
                        action="store_true",
                        help="Enable debug mode with verbose logging")
                        
    parser.add_argument("--db-path", dest="db_path",
                        default=DEFAULT_CONFIG["db_path"],
                        help=f"Path to database file for persistent storage (default: {DEFAULT_CONFIG['db_path']})")
    
    parser.add_argument("--stats", dest="show_stats",
                        action="store_true",
                        help="Show statistics from the database and exit")
    
    args = parser.parse_args()
    
    # Check if just showing stats
    if args.show_stats:
        try:
            db = DatabaseConnector(args.db_path)
            stats = db.get_stats()
            print("\n📊 CyberCare Snort Connector Statistics")
            print(f"   Database path: {stats['database_path']}")
            print(f"   Total threats: {stats.get('total_threats', 'N/A')}")
            print(f"   Submitted threats: {stats.get('submitted_threats', 'N/A')}")
            print(f"   Pending threats: {stats.get('pending_threats', 'N/A')}")
            
            if 'behavior_counts' in stats:
                print("\n   Behavior counts:")
                for behavior, count in stats['behavior_counts'].items():
                    print(f"     - {behavior}: {count}")
            
            if 'recent_submission_stats' in stats:
                print("\n   Recent submission stats (24h):")
                print(f"     - Success: {stats['recent_submission_stats'].get('success', 0)}")
                print(f"     - Failure: {stats['recent_submission_stats'].get('failure', 0)}")
            
            return
        except Exception as e:
            print(f"Error getting statistics: {str(e)}")
            return
    
    # Print banner
    print("🚀 Starting CyberCare Snort Connector")
    print(f"   API URL: {args.api_url}")
    print(f"   Log file: {args.log_path}")
    print(f"   Mode: {'Batch' if args.batch_mode else 'Single alert'}")
    print(f"   Debug mode: {'Enabled' if args.debug_mode else 'Disabled'}")
    print(f"   Database: {args.db_path}")
    
    # Create watcher
    watcher = SnortLogWatcher(args.log_path, args.api_url, args.batch_size, args.batch_mode, args.db_path)
    
    # Check database connectivity
    if watcher.db and watcher.db.initialized:
        print("   Database initialized successfully")
        
        # Check for unsent threats
        try:
            unsent = watcher.db.get_unsent_threats()
            if unsent:
                print(f"   Found {len(unsent)} unsent threats in database")
                if args.batch_mode and len(unsent) >= args.batch_size:
                    print(f"   Will attempt to send unsent threats in batches")
                    for i in range(0, len(unsent), args.batch_size):
                        batch = unsent[i:i+args.batch_size]
                        watcher.pending_alerts = batch
                        watcher.send_batch()
                elif not args.batch_mode and len(unsent) > 0:
                    print(f"   Will attempt to send unsent threats individually")
                    for threat in unsent[:10]:  # Limit to first 10 to avoid flooding
                        watcher.send_alert(threat)
        except Exception as e:
            print(f"   Error checking for unsent threats: {str(e)}")
    
    # Special debug test mode - process all alerts immediately
    if args.debug_mode:
        print("DEBUG MODE: Processing log file immediately")
        print(f"DEBUG MODE: Log file exists: {os.path.exists(args.log_path)}")
        if os.path.exists(args.log_path):
            print(f"DEBUG MODE: Log file size: {os.path.getsize(args.log_path)} bytes")
            with open(args.log_path, 'r') as f:
                content = f.read()
                print(f"DEBUG MODE: Read {len(content)} bytes from log file")
            
            # Process all alerts immediately
            watcher.process_new_alerts()
            
            # Process once more to make sure we caught everything
            time.sleep(1)
            watcher.process_new_alerts()
            
            print("DEBUG MODE: Processing complete, exiting")
            return
        else:
            print(f"DEBUG MODE: Error - Log file {args.log_path} does not exist")
            return
    
    # Check if log path exists
    if not os.path.exists(args.log_path):
        print(f"WARNING: Log file {args.log_path} does not exist")
    
    # If log file directory exists, use watchdog for monitoring
    log_dir = os.path.dirname(args.log_path)
    if os.path.isdir(log_dir):
        print(f"   Using filesystem monitoring")
        # Create event handler
        event_handler = SnortLogEventHandler(watcher)
        
        # Set up observer
        observer = Observer()
        observer.schedule(event_handler, log_dir, recursive=False)
        observer.start()
        
        try:
            # Process existing alerts first
            print("Processing existing alerts...")
            watcher.process_new_alerts()
            
            # Keep the main thread running
            while True:
                time.sleep(args.poll_interval)
                # Also poll periodically in case file watching misses something
                watcher.process_new_alerts()
                
        except KeyboardInterrupt:
            print("Stopping connector...")
            observer.stop()
        except Exception as e:
            print(f"Error in main loop: {str(e)}")
            observer.stop()
        finally:    
            observer.join()
    else:
        print(f"Log directory {log_dir} not found, using polling mode")
        poll_mode(watcher, args)

def poll_mode(watcher, args):
    """Use polling mode for the log file"""
    print(f"Using polling mode with {args.poll_interval} second interval")
    try:
        while True:
            watcher.process_new_alerts()
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("Stopping connector...")

if __name__ == "__main__":
    main()