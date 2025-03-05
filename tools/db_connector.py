#!/usr/bin/env python3
"""
CyberCare Database Connector for Snort IDS

This module provides database functionality for persisting and retrieving threat data 
from the Snort IDS connector.
"""

import os
import json
import sqlite3
import logging
import time
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class DatabaseConnector:
    """Handles database interactions for the Snort connector"""
    
    def __init__(self, db_path: str = "threats.db"):
        """
        Initialize the database connector
        
        Args:
            db_path (str): Path to the SQLite database file
        """
        self.db_path = db_path
        self.initialized = False
        self.init_db()
    
    def init_db(self) -> None:
        """Initialize the database schema if it doesn't exist"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Create threats table if it doesn't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                protocol TEXT,
                behavior TEXT,
                timestamp TEXT,
                creation_time TEXT NOT NULL,
                submitted BOOLEAN DEFAULT 0,
                submission_time TEXT,
                api_response TEXT,
                additional_data TEXT
            )
            ''')
            
            # Create attempts table to track submission attempts
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS submission_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id TEXT NOT NULL,
                attempt_time TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                error_message TEXT,
                FOREIGN KEY (threat_id) REFERENCES threats (id)
            )
            ''')
            
            # Create index on source_ip for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON threats (source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_behavior ON threats (behavior)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_submitted ON threats (submitted)')
            
            conn.commit()
            self.initialized = True
            logger.info(f"Database initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise
        finally:
            if 'conn' in locals():
                conn.close()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with retry logic"""
        max_retries = 3
        retry_delay = 1  # seconds
        
        for attempt in range(max_retries):
            try:
                # Ensure directory exists
                os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
                
                # Connect to database with timeout
                conn = sqlite3.connect(self.db_path, timeout=10)
                conn.row_factory = sqlite3.Row  # Return rows as dictionaries
                return conn
            except sqlite3.Error as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Database connection attempt {attempt+1} failed: {str(e)}. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error(f"Failed to connect to database after {max_retries} attempts: {str(e)}")
                    raise
    
    def store_threat(self, threat_data: Dict[str, Any]) -> str:
        """
        Store a threat in the database
        
        Args:
            threat_data: The threat data to store
            
        Returns:
            str: The ID of the stored threat
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Generate a unique ID if not provided
            if 'id' not in threat_data:
                threat_data['id'] = f"threat_{int(time.time())}_{hash(threat_data['source_ip'])}"
            
            # Prepare data for insertion
            threat_id = threat_data['id']
            source_ip = threat_data['source_ip']
            destination_ip = threat_data.get('destination_ip')
            protocol = threat_data.get('protocol')
            behavior = threat_data.get('behavior')
            timestamp = threat_data.get('timestamp')
            creation_time = datetime.now().isoformat()
            
            # Convert additional_data to JSON string
            additional_data = json.dumps(threat_data.get('additional_data', {}))
            
            # Insert the threat
            cursor.execute('''
            INSERT OR REPLACE INTO threats 
            (id, source_ip, destination_ip, protocol, behavior, timestamp, creation_time, additional_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (threat_id, source_ip, destination_ip, protocol, behavior, timestamp, creation_time, additional_data))
            
            conn.commit()
            logger.debug(f"Stored threat {threat_id} from {source_ip} in database")
            return threat_id
        except Exception as e:
            logger.error(f"Error storing threat: {str(e)}")
            if 'conn' in locals():
                conn.rollback()
            raise
        finally:
            if 'conn' in locals():
                conn.close()
    
    def store_batch(self, threat_batch: List[Dict[str, Any]]) -> List[str]:
        """
        Store multiple threats in a single transaction
        
        Args:
            threat_batch: List of threat data dictionaries
            
        Returns:
            List[str]: The IDs of the stored threats
        """
        if not threat_batch:
            return []
            
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            threat_ids = []
            
            # Begin transaction
            conn.execute('BEGIN TRANSACTION')
            
            for threat_data in threat_batch:
                # Generate a unique ID if not provided
                if 'id' not in threat_data:
                    threat_data['id'] = f"threat_{int(time.time())}_{hash(threat_data['source_ip'])}"
                
                # Prepare data for insertion
                threat_id = threat_data['id']
                threat_ids.append(threat_id)
                source_ip = threat_data['source_ip']
                destination_ip = threat_data.get('destination_ip')
                protocol = threat_data.get('protocol')
                behavior = threat_data.get('behavior')
                timestamp = threat_data.get('timestamp')
                creation_time = datetime.now().isoformat()
                
                # Convert additional_data to JSON string
                additional_data = json.dumps(threat_data.get('additional_data', {}))
                
                # Insert the threat
                cursor.execute('''
                INSERT OR REPLACE INTO threats 
                (id, source_ip, destination_ip, protocol, behavior, timestamp, creation_time, additional_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (threat_id, source_ip, destination_ip, protocol, behavior, timestamp, creation_time, additional_data))
            
            conn.commit()
            logger.info(f"Stored batch of {len(threat_ids)} threats in database")
            return threat_ids
        except Exception as e:
            logger.error(f"Error storing threat batch: {str(e)}")
            if 'conn' in locals():
                conn.rollback()
            raise
        finally:
            if 'conn' in locals():
                conn.close()
    
    def mark_as_submitted(self, threat_id: str, success: bool, api_response: Optional[Dict[str, Any]] = None, error_message: Optional[str] = None) -> None:
        """
        Mark a threat as submitted and store the API response
        
        Args:
            threat_id: The ID of the threat
            success: Whether the submission was successful
            api_response: The API response data (if successful)
            error_message: Error message (if failed)
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            submission_time = datetime.now().isoformat()
            
            # Update the threat record
            if success:
                cursor.execute('''
                UPDATE threats 
                SET submitted = 1, submission_time = ?, api_response = ?
                WHERE id = ?
                ''', (submission_time, json.dumps(api_response), threat_id))
            
            # Log the submission attempt
            cursor.execute('''
            INSERT INTO submission_attempts 
            (threat_id, attempt_time, success, error_message)
            VALUES (?, ?, ?, ?)
            ''', (threat_id, submission_time, 1 if success else 0, error_message))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error marking threat {threat_id} as submitted: {str(e)}")
            if 'conn' in locals():
                conn.rollback()
        finally:
            if 'conn' in locals():
                conn.close()
    
    def get_unsent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get threats that have not been successfully submitted
        
        Args:
            limit: Maximum number of threats to retrieve
            
        Returns:
            List of unsent threat dictionaries
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM threats
            WHERE submitted = 0
            ORDER BY creation_time ASC
            LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            threats = []
            
            for row in rows:
                threat = dict(row)
                # Parse additional_data from JSON
                if threat['additional_data']:
                    threat['additional_data'] = json.loads(threat['additional_data'])
                else:
                    threat['additional_data'] = {}
                    
                # Parse API response from JSON if present
                if threat.get('api_response'):
                    threat['api_response'] = json.loads(threat['api_response'])
                
                threats.append(threat)
            
            return threats
        except Exception as e:
            logger.error(f"Error retrieving unsent threats: {str(e)}")
            return []
        finally:
            if 'conn' in locals():
                conn.close()
    
    def get_threat_by_id(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a threat by its ID
        
        Args:
            threat_id: The ID of the threat to retrieve
            
        Returns:
            The threat data or None if not found
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM threats
            WHERE id = ?
            ''', (threat_id,))
            
            row = cursor.fetchone()
            if row:
                threat = dict(row)
                # Parse additional_data from JSON
                if threat['additional_data']:
                    threat['additional_data'] = json.loads(threat['additional_data'])
                else:
                    threat['additional_data'] = {}
                    
                # Parse API response from JSON if present
                if threat.get('api_response'):
                    threat['api_response'] = json.loads(threat['api_response'])
                    
                return threat
            return None
        except Exception as e:
            logger.error(f"Error retrieving threat {threat_id}: {str(e)}")
            return None
        finally:
            if 'conn' in locals():
                conn.close()
    
    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recently detected threats
        
        Args:
            limit: Maximum number of threats to retrieve
            
        Returns:
            List of recent threats
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM threats
            ORDER BY creation_time DESC
            LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            threats = []
            
            for row in rows:
                threat = dict(row)
                # Parse additional_data from JSON
                if threat['additional_data']:
                    threat['additional_data'] = json.loads(threat['additional_data'])
                else:
                    threat['additional_data'] = {}
                    
                # Parse API response from JSON if present
                if threat.get('api_response'):
                    threat['api_response'] = json.loads(threat['api_response'])
                
                threats.append(threat)
            
            return threats
        except Exception as e:
            logger.error(f"Error retrieving recent threats: {str(e)}")
            return []
        finally:
            if 'conn' in locals():
                conn.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics
        
        Returns:
            Dictionary with statistics
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get total count
            cursor.execute('SELECT COUNT(*) FROM threats')
            total_count = cursor.fetchone()[0]
            
            # Get submitted count
            cursor.execute('SELECT COUNT(*) FROM threats WHERE submitted = 1')
            submitted_count = cursor.fetchone()[0]
            
            # Get behavior counts
            cursor.execute('''
            SELECT behavior, COUNT(*) as count 
            FROM threats 
            GROUP BY behavior
            ORDER BY count DESC
            ''')
            behavior_counts = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Get recent submission stats
            cursor.execute('''
            SELECT success, COUNT(*) as count 
            FROM submission_attempts 
            WHERE attempt_time > datetime('now', '-24 hours')
            GROUP BY success
            ''')
            recent_submission_stats = {
                'success': 0,
                'failure': 0
            }
            for row in cursor.fetchall():
                if row[0]:
                    recent_submission_stats['success'] = row[1]
                else:
                    recent_submission_stats['failure'] = row[1]
            
            return {
                'total_threats': total_count,
                'submitted_threats': submitted_count,
                'pending_threats': total_count - submitted_count,
                'behavior_counts': behavior_counts,
                'recent_submission_stats': recent_submission_stats,
                'database_path': self.db_path
            }
        except Exception as e:
            logger.error(f"Error retrieving database stats: {str(e)}")
            return {
                'error': str(e),
                'database_path': self.db_path
            }
        finally:
            if 'conn' in locals():
                conn.close()
    
    def cleanup_old_threats(self, days: int = 30) -> int:
        """
        Remove threats older than the specified number of days
        
        Args:
            days: Number of days to keep threats for
            
        Returns:
            Number of threats removed
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get count of threats to be deleted
            cursor.execute('''
            SELECT COUNT(*) FROM threats
            WHERE creation_time < datetime('now', ?)
            ''', (f'-{days} days',))
            
            count = cursor.fetchone()[0]
            
            # Delete old threats
            cursor.execute('''
            DELETE FROM threats
            WHERE creation_time < datetime('now', ?)
            ''', (f'-{days} days',))
            
            # Delete orphaned submission attempts
            cursor.execute('''
            DELETE FROM submission_attempts
            WHERE threat_id NOT IN (SELECT id FROM threats)
            ''')
            
            conn.commit()
            logger.info(f"Cleaned up {count} threats older than {days} days")
            return count
        except Exception as e:
            logger.error(f"Error cleaning up old threats: {str(e)}")
            if 'conn' in locals():
                conn.rollback()
            return 0
        finally:
            if 'conn' in locals():
                conn.close()
