#!/usr/bin/env python3
import requests
import json
import sys
import argparse
import os
from tools.db_connector import DatabaseConnector

# Load environment variables if .env exists
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(env_path):
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split('=', 1)
                os.environ[key] = value

# Test threat data
test_threats = [
    {
        "source_ip": "192.168.10.80",
        "destination_ip": "10.0.0.40",
        "protocol": "TCP",
        "behavior": "malware_c2",
        "timestamp": "03/04-14:10:22.123456",
        "additional_data": {
            "snort_signature_id": "1000008",
            "snort_signature_name": "SNORT ALERT: Malware C2 Traffic",
            "snort_classification": "Potentially Bad Traffic",
            "snort_priority": 1,
            "source_port": 54321,
            "destination_port": 8080
        }
    },
    {
        "source_ip": "192.168.10.90",
        "destination_ip": "10.0.0.45",
        "protocol": "UDP",
        "behavior": "dns_tunneling",
        "timestamp": "03/04-14:15:30.654321",
        "additional_data": {
            "snort_signature_id": "1000009",
            "snort_signature_name": "SNORT ALERT: DNS Tunneling",
            "snort_classification": "Suspicious Activity",
            "snort_priority": 2,
            "source_port": 53245,
            "destination_port": 53
        }
    }
]

def send_threat(threat_data, api_url, db=None):
    """Send a threat to the API"""
    # Store in database if available
    if db:
        try:
            threat_id = db.store_threat(threat_data)
            print(f"Stored threat in database with ID: {threat_id}")
            threat_data['id'] = threat_id
        except Exception as e:
            print(f"ERROR: Failed to store threat in database: {str(e)}")
    
    print(f"Sending threat: {json.dumps(threat_data, indent=2)}")
    try:
        response = requests.post(api_url, json=threat_data)
        
        if response.status_code == 200:
            print(f"SUCCESS: Threat sent - Status: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2)}")
            
            # Update database if available
            if db and 'id' in threat_data:
                try:
                    db.mark_as_submitted(threat_data['id'], True, response.json())
                    print(f"Updated database with submission status")
                except Exception as e:
                    print(f"ERROR: Failed to update threat submission status: {str(e)}")
            
            return True
        else:
            print(f"ERROR: Failed to send threat - Status: {response.status_code}")
            print(f"Response: {response.text}")
            
            # Update database if available
            if db and 'id' in threat_data:
                try:
                    db.mark_as_submitted(threat_data['id'], False, None, f"HTTP {response.status_code}: {response.text}")
                    print(f"Updated database with failed submission status")
                except Exception as e:
                    print(f"ERROR: Failed to update threat submission status: {str(e)}")
            
            return False
    except Exception as e:
        print(f"ERROR: Exception sending threat: {str(e)}")
        
        # Update database if available
        if db and 'id' in threat_data:
            try:
                db.mark_as_submitted(threat_data['id'], False, None, str(e))
                print(f"Updated database with failed submission status")
            except Exception as db_e:
                print(f"ERROR: Failed to update threat submission status: {str(db_e)}")
        
        return False

def show_database_stats(db_path):
    """Show statistics from the database"""
    try:
        db = DatabaseConnector(db_path)
        stats = db.get_stats()
        print("\n📊 CyberCare Threat Database Statistics")
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
        
        # Get recent threats
        recent = db.get_recent_threats(5)
        if recent:
            print("\n   Recent threats:")
            for i, threat in enumerate(recent):
                print(f"     {i+1}. [{threat['behavior']}] {threat['source_ip']} -> {threat['destination_ip']} ({threat['timestamp']})")
                print(f"        Submitted: {'Yes' if threat['submitted'] else 'No'}")
        
        return True
    except Exception as e:
        print(f"Error getting statistics: {str(e)}")
        return False

def list_unsent_threats(db_path):
    """List unsent threats from the database"""
    try:
        db = DatabaseConnector(db_path)
        unsent = db.get_unsent_threats()
        
        if not unsent:
            print("No unsent threats found in database")
            return True
            
        print(f"Found {len(unsent)} unsent threats in database:")
        for i, threat in enumerate(unsent):
            print(f"  {i+1}. [{threat['behavior']}] {threat['source_ip']} -> {threat['destination_ip']} ({threat['timestamp']})")
        
        return True
    except Exception as e:
        print(f"Error listing unsent threats: {str(e)}")
        return False

def retry_unsent_threats(db_path, api_url, limit=10):
    """Retry sending unsent threats from the database"""
    try:
        db = DatabaseConnector(db_path)
        unsent = db.get_unsent_threats(limit)
        
        if not unsent:
            print("No unsent threats found in database")
            return True
            
        print(f"Retrying {len(unsent)} unsent threats:")
        success_count = 0
        
        for i, threat in enumerate(unsent):
            print(f"  Threat #{i+1}: [{threat['behavior']}] {threat['source_ip']} -> {threat['destination_ip']}")
            if send_threat(threat, api_url, db):
                success_count += 1
        
        print(f"Successfully sent {success_count} of {len(unsent)} threats")
        return True
    except Exception as e:
        print(f"Error retrying unsent threats: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="CyberCare Threat Testing Tool")
    
    parser.add_argument("--api-url", dest="api_url",
                      default="http://localhost:8005/api/v1/threats/analyze",
                      help="API URL for threat submission")
    
    parser.add_argument("--db-path", dest="db_path",
                      default=os.environ.get("TEST_DB_PATH", "test_threats.db"),
                      help="Path to database file for persistent storage")
    
    parser.add_argument("--stats", dest="show_stats",
                      action="store_true",
                      help="Show statistics from the database and exit")
    
    parser.add_argument("--list-unsent", dest="list_unsent",
                      action="store_true",
                      help="List unsent threats from the database and exit")
    
    parser.add_argument("--retry-unsent", dest="retry_unsent",
                      action="store_true",
                      help="Retry sending unsent threats from the database")
    
    parser.add_argument("--retry-limit", dest="retry_limit",
                      type=int, default=int(os.environ.get("RETRY_LIMIT", "10")),
                      help="Maximum number of unsent threats to retry")
    
    parser.add_argument("--test", dest="run_test",
                      action="store_true",
                      help="Run the standard threat test")
    
    args = parser.parse_args()
    
    # Initialize database
    db = None
    try:
        db = DatabaseConnector(args.db_path)
        print(f"Using database at {args.db_path}")
    except Exception as e:
        print(f"ERROR: Failed to initialize database: {str(e)}")
        db = None
    
    # Check if showing stats
    if args.show_stats:
        show_database_stats(args.db_path)
        return
    
    # Check if listing unsent threats
    if args.list_unsent:
        list_unsent_threats(args.db_path)
        return
    
    # Check if retrying unsent threats
    if args.retry_unsent:
        retry_unsent_threats(args.db_path, args.api_url, args.retry_limit)
        return
    
    # Default behavior - run the test
    if args.run_test or not (args.show_stats or args.list_unsent or args.retry_unsent):
        print(f"Testing CyberCare Threat API: {args.api_url}")
        
        # Send each test threat
        for i, threat in enumerate(test_threats):
            print(f"\n[Threat #{i+1}]")
            send_threat(threat, args.api_url, db)
            
        # Get recent threats
        print("\n[Retrieving recent threats]")
        try:
            response = requests.get("http://localhost:8005/api/v1/threats/recent")
            if response.status_code == 200:
                threats = response.json()
                print(f"Found {len(threats)} recent threats:")
                for i, threat in enumerate(threats):
                    print(f"Threat #{i+1}: {threat['source_ip']} -> {threat['destination_ip']} ({threat['behavior']}) Severity: {threat['severity']}")
            else:
                print(f"Failed to get recent threats: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error retrieving recent threats: {str(e)}")
        
        # Show database stats if available
        if db:
            show_database_stats(args.db_path)

if __name__ == "__main__":
    main()
