"""
Azure Anomaly Detector Service integration for SentinelAI.
This module provides a wrapper around Azure Anomaly Detector for detecting unusual network activity.
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta

# Check if Azure Anomaly Detector SDK is available
try:
    from azure.ai.anomalydetector import AnomalyDetectorClient
    from azure.core.credentials import AzureKeyCredential
    from azure.core.exceptions import HttpResponseError
    AZURE_ANOMALY_DETECTOR_AVAILABLE = True
except ImportError:
    AZURE_ANOMALY_DETECTOR_AVAILABLE = False
    logging.warning("Azure Anomaly Detector SDK not installed. Service will be unavailable.")

logger = logging.getLogger(__name__)

class AzureAnomalyDetector:
    """Azure Anomaly Detector service wrapper for SentinelAI network traffic analysis."""
    
    def __init__(self):
        """Initialize the Azure Anomaly Detector service with credentials from environment variables."""
        self.endpoint = os.getenv("AZURE_ANOMALY_DETECTOR_ENDPOINT")
        self.key = os.getenv("AZURE_ANOMALY_DETECTOR_KEY")
        self.available = AZURE_ANOMALY_DETECTOR_AVAILABLE and self.endpoint and self.key
        self.client = None
        
        if self.available:
            try:
                self.client = AnomalyDetectorClient(
                    endpoint=self.endpoint,
                    credential=AzureKeyCredential(self.key)
                )
                logger.info("Azure Anomaly Detector initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Azure Anomaly Detector client: {str(e)}")
                self.available = False
        else:
            logger.warning("Azure Anomaly Detector service is not available.")
    
    def detect_anomalies(self, time_series_data: List[Dict[str, Any]], 
                         sensitivity: int = 95) -> Optional[Dict[str, Any]]:
        """
        Detect anomalies in time series data.
        
        Args:
            time_series_data: List of dictionaries with 'timestamp' and 'value' keys
            sensitivity: Sensitivity value (0-99, higher is more sensitive)
            
        Returns:
            Dictionary with anomaly detection results or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Anomaly Detector service is not available for anomaly detection.")
            return None
        
        try:
            # Format data for Azure Anomaly Detector
            series = []
            for point in time_series_data:
                # Check required fields
                if 'timestamp' not in point or 'value' not in point:
                    logger.error("Invalid time series data point. Missing required fields.")
                    continue
                    
                # Convert timestamp string to datetime if needed
                timestamp = point['timestamp']
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    except ValueError:
                        logger.error(f"Invalid timestamp format: {timestamp}")
                        continue
                
                # Format point for Azure API
                series.append({
                    "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
                    "value": float(point['value'])
                })
            
            if not series:
                logger.error("No valid data points to analyze.")
                return None
            
            # Detect anomalies
            response = self.client.detect_entire_series(
                series=series,
                granularity="minutely",  # Can be parameterized based on the data
                sensitivity=sensitivity
            )
            
            # Format the response
            result = {
                "is_anomaly_detected": any(response.is_anomaly),
                "anomaly_indexes": [i for i, is_anomaly in enumerate(response.is_anomaly) if is_anomaly],
                "expected_values": response.expected_values,
                "upper_margins": response.upper_margins,
                "lower_margins": response.lower_margins,
                "score": max(response.anomaly_score) if response.anomaly_score else 0.0
            }
            
            return result
            
        except HttpResponseError as e:
            logger.error(f"Azure Anomaly Detector API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return None
    
    def detect_last_point(self, time_series_data: List[Dict[str, Any]],
                         sensitivity: int = 95) -> Optional[Dict[str, Any]]:
        """
        Detect if the last data point is an anomaly.
        
        Args:
            time_series_data: List of dictionaries with 'timestamp' and 'value' keys
            sensitivity: Sensitivity value (0-99, higher is more sensitive)
            
        Returns:
            Dictionary with anomaly detection results or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Anomaly Detector service is not available for last point detection.")
            return None
        
        try:
            # Format data for Azure Anomaly Detector
            series = []
            for point in time_series_data:
                # Check required fields
                if 'timestamp' not in point or 'value' not in point:
                    logger.error("Invalid time series data point. Missing required fields.")
                    continue
                    
                # Convert timestamp string to datetime if needed
                timestamp = point['timestamp']
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    except ValueError:
                        logger.error(f"Invalid timestamp format: {timestamp}")
                        continue
                
                # Format point for Azure API
                series.append({
                    "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
                    "value": float(point['value'])
                })
            
            if not series:
                logger.error("No valid data points to analyze.")
                return None
            
            # Detect last point anomaly
            response = self.client.detect_last_point(
                series=series,
                granularity="minutely",  # Can be parameterized based on the data
                sensitivity=sensitivity
            )
            
            # Format the response
            result = {
                "is_anomaly": response.is_anomaly,
                "expected_value": response.expected_value,
                "upper_margin": response.upper_margin,
                "lower_margin": response.lower_margin,
                "score": response.anomaly_score
            }
            
            return result
            
        except HttpResponseError as e:
            logger.error(f"Azure Anomaly Detector API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error detecting last point anomaly: {str(e)}")
            return None
    
    def get_usage_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get usage statistics for the Anomaly Detector service.
        
        Returns:
            Dictionary with usage statistics or None if service is unavailable
        """
        if not self.available:
            return None
        
        try:
            # Return basic information
            # In a production system, you would likely track usage in a database
            return {
                "detections_today": 0,  # placeholder
                "status": "active"
            }
        except Exception as e:
            logger.error(f"Error getting Anomaly Detector usage stats: {str(e)}")
            return None
    
    def check_network_traffic_anomaly(self, 
                                     source_ip: str, 
                                     time_window_minutes: int = 60,
                                     db_connector = None) -> Optional[Dict[str, Any]]:
        """
        Check if there's an anomaly in network traffic from a specific IP address.
        
        Args:
            source_ip: Source IP address to analyze
            time_window_minutes: Time window to analyze (in minutes)
            db_connector: Database connector instance to retrieve historical data
            
        Returns:
            Dictionary with anomaly detection results or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Anomaly Detector service unavailable. Skipping traffic anomaly check.")
            return None
            
        if not db_connector:
            logger.warning("Database connector not provided. Cannot retrieve historical data.")
            return None
            
        try:
            # Get historical traffic data for this IP
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=time_window_minutes)
            
            # This assumes db_connector has a method to get time series data
            # Format should be: [{"timestamp": "2023-01-01T00:00:00Z", "value": count}, ...]
            historical_data = db_connector.get_ip_traffic_time_series(
                source_ip, 
                start_time, 
                end_time
            )
            
            if not historical_data or len(historical_data) < 12:
                logger.warning(f"Insufficient historical data for IP {source_ip}")
                return None
                
            # Detect anomalies
            return self.detect_anomalies(historical_data)
            
        except Exception as e:
            logger.error(f"Error checking network traffic anomaly: {str(e)}")
            return None
    
    def analyze_threat_pattern(self, threat_data: Dict[str, Any], 
                             historical_threats: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Analyze if a threat follows an anomalous pattern compared to historical threats.
        
        Args:
            threat_data: Current threat data
            historical_threats: List of historical threats for comparison
            
        Returns:
            Dictionary with threat pattern analysis or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Anomaly Detector service unavailable. Skipping threat pattern analysis.")
            return None
            
        if not historical_threats:
            logger.warning("No historical threats available for comparison.")
            return {
                "is_anomalous_pattern": False,
                "confidence": 0,
                "reason": "Insufficient historical data for comparison"
            }
            
        try:
            # This is a simplified approach - in a real implementation, you would
            # need to extract relevant features from threats and build time series
            
            # Example: Count threats per hour over time
            threat_counts = {}
            for threat in historical_threats:
                # Extract hour from timestamp
                timestamp = threat.get("timestamp", "")
                if timestamp:
                    hour = timestamp.split("T")[1].split(":")[0]
                    threat_counts[hour] = threat_counts.get(hour, 0) + 1
            
            # Convert to time series
            time_series = [
                {"timestamp": f"2023-01-01T{hour}:00:00Z", "value": count}
                for hour, count in threat_counts.items()
            ]
            
            # If there's enough data, detect anomalies
            if len(time_series) >= 12:
                return self.detect_anomalies(time_series)
            else:
                return {
                    "is_anomalous_pattern": False,
                    "confidence": 0,
                    "reason": "Insufficient historical data points"
                }
                
        except Exception as e:
            logger.error(f"Error analyzing threat pattern: {str(e)}")
            return None
