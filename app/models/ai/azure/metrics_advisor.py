"""
Azure Metrics Advisor service integration for SentinelAI.
This module provides a wrapper around Azure Metrics Advisor for detecting
anomalies in security metrics and telemetry data.
"""
import os
import json
import logging
import datetime
from typing import Dict, Any, Optional, List, Union

# Check if Azure Metrics Advisor SDK is available
try:
    from azure.ai.metricsadvisor import MetricsAdvisorClient, MetricsAdvisorKeyCredential
    from azure.ai.metricsadvisor.models import (
        MetricAnomalyDetectionConfiguration,
        MetricSeriesGroupDetectionCondition,
        SeverityCondition
    )
    from azure.core.exceptions import HttpResponseError
    AZURE_METRICS_ADVISOR_AVAILABLE = True
except ImportError:
    AZURE_METRICS_ADVISOR_AVAILABLE = False
    logging.warning("Azure Metrics Advisor SDK not installed. Service will be unavailable.")

logger = logging.getLogger(__name__)

class AzureMetricsAdvisor:
    """Azure Metrics Advisor service wrapper for SentinelAI security metrics analysis."""
    
    def __init__(self):
        """Initialize the Azure Metrics Advisor service with credentials from environment variables."""
        self.endpoint = os.getenv("AZURE_METRICS_ADVISOR_ENDPOINT")
        self.subscription_key = os.getenv("AZURE_METRICS_ADVISOR_SUBSCRIPTION_KEY")
        self.api_key = os.getenv("AZURE_METRICS_ADVISOR_API_KEY")
        self.data_feed_id = os.getenv("AZURE_METRICS_ADVISOR_DATA_FEED_ID")
        self.available = (AZURE_METRICS_ADVISOR_AVAILABLE and self.endpoint 
                        and self.subscription_key and self.api_key)
        self.client = None
        
        if self.available:
            try:
                self.client = MetricsAdvisorClient(
                    endpoint=self.endpoint,
                    credential=MetricsAdvisorKeyCredential(
                        subscription_key=self.subscription_key,
                        api_key=self.api_key
                    )
                )
                logger.info("Azure Metrics Advisor initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Azure Metrics Advisor client: {str(e)}")
                self.available = False
        else:
            logger.warning("Azure Metrics Advisor service is not available.")
    
    def get_metric_series(self, metric_id: str, start_time: datetime.datetime, 
                        end_time: datetime.datetime) -> Optional[Dict[str, Any]]:
        """
        Get metric series data for a specific metric.
        
        Args:
            metric_id: The ID of the metric to retrieve
            start_time: The start time for the metric data
            end_time: The end time for the metric data
            
        Returns:
            Dictionary with metric series data or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Metrics Advisor service is not available for retrieving metric series.")
            return None
        
        try:
            # Get the metric series data
            series_data = {}
            
            # Get dimension combination for the metric
            dimension_combinations = list(self.client.list_metric_dimension_values(
                metric_id=metric_id,
                dimension_name="*",
            ))
            
            # For each dimension combination, get the metric series
            for dimension in dimension_combinations[:10]:  # Limit to 10 dimensions for simplicity
                series = list(self.client.list_metric_series_data(
                    metric_id=metric_id,
                    start_time=start_time,
                    end_time=end_time,
                    series_keys=[dimension]
                ))
                
                # Add to the series data
                if series:
                    series_key = str(dimension)
                    series_data[series_key] = [
                        {"timestamp": point.timestamp, "value": point.value}
                        for point in series[0].series_values
                    ]
            
            return {
                "metric_id": metric_id,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "series_data": series_data
            }
            
        except HttpResponseError as e:
            logger.error(f"Azure Metrics Advisor API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error getting metric series: {str(e)}")
            return None
    
    def get_anomalies(self, metric_id: str, start_time: datetime.datetime, 
                    end_time: datetime.datetime) -> Optional[Dict[str, Any]]:
        """
        Get anomalies for a specific metric.
        
        Args:
            metric_id: The ID of the metric to check for anomalies
            start_time: The start time for anomaly detection
            end_time: The end time for anomaly detection
            
        Returns:
            Dictionary with anomaly detection results or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Metrics Advisor service is not available for anomaly detection.")
            return None
        
        try:
            # Get the anomaly detection configurations for this metric
            detection_configs = list(self.client.list_detection_configurations(
                metric_id=metric_id
            ))
            
            # If no detection configurations exist, return empty results
            if not detection_configs:
                logger.warning(f"No anomaly detection configurations found for metric ID: {metric_id}")
                return {
                    "metric_id": metric_id,
                    "anomalies_detected": False,
                    "message": "No anomaly detection configurations found for this metric."
                }
            
            # Use the first detection configuration
            detection_config_id = detection_configs[0].id
            
            # Get anomalies using the detection configuration
            anomalies = list(self.client.list_anomalies_for_detection_configuration(
                configuration_id=detection_config_id,
                start_time=start_time,
                end_time=end_time
            ))
            
            # Format the results
            anomaly_results = []
            for anomaly in anomalies:
                anomaly_results.append({
                    "timestamp": anomaly.timestamp.isoformat(),
                    "severity": anomaly.severity,
                    "status": anomaly.status,
                    "dimension_key": str(anomaly.series_key),
                    "value": anomaly.value
                })
            
            return {
                "metric_id": metric_id,
                "anomalies_detected": len(anomaly_results) > 0,
                "anomaly_count": len(anomaly_results),
                "anomalies": anomaly_results
            }
            
        except HttpResponseError as e:
            logger.error(f"Azure Metrics Advisor API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error getting anomalies: {str(e)}")
            return None
    
    def analyze_security_metrics(self, metrics_data: Dict[str, Any], 
                              timeframe: str = "24h") -> Optional[Dict[str, Any]]:
        """
        Analyze security metrics data for anomalies.
        
        Args:
            metrics_data: Dictionary of security metrics data to analyze
            timeframe: Timeframe for analysis (e.g., "24h", "7d")
            
        Returns:
            Dictionary with analysis results or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Metrics Advisor service is not available for security metrics analysis.")
            return None
        
        try:
            # Convert timeframe to datetime objects
            end_time = datetime.datetime.now()
            
            if timeframe == "24h":
                start_time = end_time - datetime.timedelta(hours=24)
            elif timeframe == "7d":
                start_time = end_time - datetime.timedelta(days=7)
            elif timeframe == "30d":
                start_time = end_time - datetime.timedelta(days=30)
            else:
                # Default to 24 hours
                start_time = end_time - datetime.timedelta(hours=24)
            
            # Ensure metrics_data has required format
            if not isinstance(metrics_data, dict) or "metrics" not in metrics_data:
                logger.error("Invalid metrics data format. Expected dictionary with 'metrics' key.")
                return {
                    "error": "Invalid metrics data format",
                    "message": "Expected dictionary with 'metrics' key containing metric IDs."
                }
            
            # Get the metrics to analyze
            metrics = metrics_data.get("metrics", [])
            if not metrics:
                logger.warning("No metrics provided for analysis.")
                return {
                    "anomalies_detected": False,
                    "message": "No metrics provided for analysis."
                }
            
            # Analyze each metric
            results = []
            anomalies_detected = False
            
            for metric in metrics:
                # Get metric ID
                metric_id = metric.get("id")
                if not metric_id:
                    continue
                
                # Get anomalies for this metric
                anomaly_result = self.get_anomalies(
                    metric_id=metric_id,
                    start_time=start_time,
                    end_time=end_time
                )
                
                if anomaly_result and anomaly_result.get("anomalies_detected", False):
                    anomalies_detected = True
                
                # Add to results
                if anomaly_result:
                    results.append(anomaly_result)
            
            # Return the combined results
            return {
                "anomalies_detected": anomalies_detected,
                "timeframe": timeframe,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "analysis_results": results
            }
            
        except Exception as e:
            logger.error(f"Error analyzing security metrics: {str(e)}")
            return None
    
    def get_usage_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get usage statistics for the Metrics Advisor service.
        
        Returns:
            Dictionary with usage statistics or None if service is unavailable
        """
        if not self.available:
            return None
        
        try:
            # Return basic information
            # In a production system, you would likely track usage in a database
            return {
                "analyses_today": 0,  # placeholder
                "status": "active",
                "data_feed_id": self.data_feed_id
            }
        except Exception as e:
            logger.error(f"Error getting Metrics Advisor usage stats: {str(e)}")
            return None
