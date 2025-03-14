"""
Azure AI Services Manager for SentinelAI.
This module provides a unified interface to all Azure AI services for cybersecurity.
"""
import os
import logging
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from .openai_service import AzureOpenAIService
from .content_safety import AzureContentSafety
from .search_service import AzureSearchService
from .metrics_advisor import AzureMetricsAdvisor

logger = logging.getLogger(__name__)

# Settings file path
SETTINGS_PATH = Path(__file__).parent.parent.parent.parent.parent / "settings.json"

class AzureAIServiceManager:
    """Manager class for Azure AI services in SentinelAI."""
    
    def __init__(self):
        """Initialize all Azure AI services."""
        logger.info("Initializing Azure AI Service Manager")
        
        # Load settings
        self.settings = self._load_settings()
        
        # Initialize individual services only if Azure services are enabled
        if self.settings.get("azure_services_enabled", False):
            self._initialize_azure_services()
        else:
            self._initialize_default_services()
            
    def _load_settings(self) -> Dict[str, Any]:
        """Load settings from the settings file."""
        # Get API key from environment variable first
        env_api_key = os.environ.get("OPENAI_API_KEY", "")
        env_api_base = os.environ.get("OPENAI_API_BASE_URL", "https://api.openai.com/v1")
        
        default_settings = {
            "azure_services_enabled": False,
            "use_gpt4o": True,
            "gpt4o_api_key": env_api_key,
            "gpt4o_endpoint": env_api_base,
            "hide_disabled_services": True
        }
        
        try:
            if SETTINGS_PATH.exists():
                with open(SETTINGS_PATH, 'r') as f:
                    settings = json.load(f)
                    # Ensure all default settings exist
                    for key, value in default_settings.items():
                        if key not in settings:
                            settings[key] = value
                    
                    # Always prioritize environment variables for API keys if they exist
                    if env_api_key:
                        settings["gpt4o_api_key"] = env_api_key
                    if env_api_base:
                        settings["gpt4o_endpoint"] = env_api_base
                        
                    return settings
            else:
                # Create default settings file if it doesn't exist
                with open(SETTINGS_PATH, 'w') as f:
                    json.dump(default_settings, f, indent=2)
                return default_settings
        except Exception as e:
            logger.error(f"Error loading settings: {e}")
            return default_settings
    
    def save_settings(self, new_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Save settings to the settings file."""
        try:
            # Load existing settings first to ensure we don't lose any
            if SETTINGS_PATH.exists():
                with open(SETTINGS_PATH, 'r') as f:
                    settings = json.load(f)
            else:
                settings = self._load_settings()
                
            # Update with new settings
            for key, value in new_settings.items():
                settings[key] = value
                
            # Don't overwrite API key from environment variable if it exists
            env_api_key = os.environ.get("OPENAI_API_KEY")
            if env_api_key:
                settings["gpt4o_api_key"] = env_api_key
                
            # Update instance settings
            self.settings = settings
                
            # Write to file
            with open(SETTINGS_PATH, 'w') as f:
                json.dump(settings, f, indent=2)
                
            return settings
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            return self.settings
    
    def _initialize_azure_services(self):
        """Initialize Azure AI services."""
        logger.info("Initializing Azure AI services")
        self.openai_service = AzureOpenAIService()
        self.content_safety = AzureContentSafety()
        self.search_service = AzureSearchService()
        self.metrics_advisor = AzureMetricsAdvisor()
        
        # Check services availability
        self._check_services_availability()
        
    def _initialize_default_services(self):
        """Initialize default services without Azure."""
        logger.info("Initializing default services (Azure services disabled)")
        # Initialize with services unavailable
        self.openai_service = AzureOpenAIService()
        self.openai_service.available = False
        
        self.content_safety = AzureContentSafety()
        self.content_safety.available = False
        
        self.search_service = AzureSearchService()
        self.search_service.available = False
        
        self.metrics_advisor = AzureMetricsAdvisor()
        self.metrics_advisor.available = False
        
        # Check services availability
        self._check_services_availability()
    
    def _check_services_availability(self):
        """Check which Azure AI services are available and log their status."""
        services = {
            "OpenAI Service": self.openai_service.available,
            "Content Safety": self.content_safety.available,
            "Search Service": self.search_service.available,
            "Metrics Advisor": self.metrics_advisor.available
        }
        
        available_services = [name for name, available in services.items() if available]
        unavailable_services = [name for name, available in services.items() if not available]
        
        logger.info(f"Available Azure services: {', '.join(available_services) if available_services else 'None'}")
        if unavailable_services:
            logger.warning(f"Unavailable Azure services: {', '.join(unavailable_services)}")
    
    def get_services_status(self) -> Dict[str, Any]:
        """
        Get the status of all Azure AI services.
        
        Returns:
            Dictionary with status of each service
        """
        return {
            "azure_services_enabled": self.settings.get("azure_services_enabled", False),
            "use_gpt4o": self.settings.get("use_gpt4o", True),
            "gpt4o_api_key": self.settings.get("gpt4o_api_key", ""),
            "gpt4o_endpoint": self.settings.get("gpt4o_endpoint", ""),
            "hide_disabled_services": self.settings.get("hide_disabled_services", True),
            "openai_service": {
                "available": self.openai_service.available,
                "status": "active" if self.openai_service.available else "unavailable"
            },
            "content_safety": {
                "available": self.content_safety.available,
                "status": "active" if self.content_safety.available else "unavailable"
            },
            "search_service": {
                "available": self.search_service.available,
                "status": "active" if self.search_service.available else "unavailable"
            },
            "metrics_advisor": {
                "available": self.metrics_advisor.available,
                "status": "active" if self.metrics_advisor.available else "unavailable"
            }
        }
    
    def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a security threat using multiple Azure AI services.
        
        Args:
            threat_data: Dictionary containing threat information
            
        Returns:
            Dictionary with comprehensive threat analysis
        """
        results = {
            "threat_data": threat_data,
            "analysis_completed": False,
            "services_used": [],
            "analysis": {}
        }
        
        try:
            # 1. Use OpenAI to classify the threat
            if self.openai_service.available:
                threat_classification = self.openai_service.classify_threat(threat_data)
                if threat_classification:
                    results["analysis"]["classification"] = threat_classification
                    results["services_used"].append("openai_service")
            
            # 2. Use Content Safety to check if the threat contains harmful content
            if self.content_safety.available and "payload" in threat_data:
                safety_analysis = self.content_safety.analyze_threat_payload(threat_data)
                if safety_analysis:
                    results["analysis"]["safety"] = safety_analysis
                    results["services_used"].append("content_safety")
            
            # 3. Use Search Service to find similar threats
            if self.search_service.available:
                similar_threats = self.search_service.get_similar_threats(threat_data)
                if similar_threats:
                    results["analysis"]["similar_threats"] = similar_threats
                    results["services_used"].append("search_service")
            
            # 4. Generate recommendations with OpenAI
            if self.openai_service.available:
                # Include previous analysis results for better recommendations
                recommendations = self.openai_service.generate_recommendations(
                    threat_data, 
                    additional_context=results["analysis"]
                )
                if recommendations:
                    results["analysis"]["recommendations"] = recommendations
            
            # Update analysis completion status
            results["analysis_completed"] = True
            
        except Exception as e:
            logger.error(f"Error in threat analysis pipeline: {e}")
            results["error"] = str(e)
        
        return results
    
    def monitor_security_metrics(self, metrics_data: Dict[str, Any], 
                              timeframe: str = "24h") -> Dict[str, Any]:
        """
        Monitor security metrics for anomalies using Azure Metrics Advisor.
        
        Args:
            metrics_data: Dictionary with security metrics data
            timeframe: Timeframe for analysis (e.g., "24h", "7d")
            
        Returns:
            Dictionary with monitoring results
        """
        results = {
            "metrics_monitored": True,
            "timeframe": timeframe,
            "services_used": []
        }
        
        try:
            if self.metrics_advisor.available:
                metrics_analysis = self.metrics_advisor.analyze_security_metrics(
                    metrics_data,
                    timeframe=timeframe
                )
                
                if metrics_analysis:
                    results["analysis"] = metrics_analysis
                    results["services_used"].append("metrics_advisor")
                else:
                    results["metrics_monitored"] = False
                    results["error"] = "Metrics analysis failed"
            else:
                results["metrics_monitored"] = False
                results["error"] = "Metrics Advisor service unavailable"
                
        except Exception as e:
            logger.error(f"Error monitoring security metrics: {e}")
            results["metrics_monitored"] = False
            results["error"] = str(e)
            
        return results
    
    def search_threats(self, query: str) -> Dict[str, Any]:
        """
        Search for threats using Azure AI Search.
        
        Args:
            query: Search query string
            
        Returns:
            Dictionary with search results
        """
        results = {
            "query": query,
            "search_completed": False,
            "services_used": []
        }
        
        try:
            if self.search_service.available:
                search_results = self.search_service.search_threats(query)
                
                if search_results:
                    results["results"] = search_results
                    results["search_completed"] = True
                    results["services_used"].append("search_service")
                else:
                    results["error"] = "No search results found"
            else:
                results["error"] = "Search service unavailable"
                
        except Exception as e:
            logger.error(f"Error searching threats: {e}")
            results["error"] = str(e)
            
        return results
    
    def analyze_content_safety(self, content: str) -> Dict[str, Any]:
        """
        Analyze content for safety concerns using Azure Content Safety.
        
        Args:
            content: Text content to analyze
            
        Returns:
            Dictionary with content safety analysis
        """
        results = {
            "content_length": len(content),
            "analysis_completed": False,
            "services_used": []
        }
        
        try:
            if self.content_safety.available:
                safety_analysis = self.content_safety.analyze_text(content)
                
                if safety_analysis:
                    results["analysis"] = safety_analysis
                    results["analysis_completed"] = True
                    results["services_used"].append("content_safety")
                else:
                    results["error"] = "Content safety analysis failed"
            else:
                results["error"] = "Content Safety service unavailable"
                
        except Exception as e:
            logger.error(f"Error analyzing content safety: {e}")
            results["error"] = str(e)
            
        return results
    
    async def get_system_stats(self) -> Dict[str, Any]:
        """
        Get system statistics from all available Azure AI services.
        
        Returns:
            Dictionary with AI system statistics for dashboard display
        """
        stats = {
            "ai_analyzed": 0,
            "similar_threats": 0,
            "unsafe_content": 0,
            "metrics_alerts": 0,
            "ai_confidence": 0,
            "timestamp": datetime.now().isoformat(),
            "services_available": []
        }
        
        try:
            # Track which services are available
            available_services = []
            
            # Get OpenAI service stats
            if self.openai_service.available:
                openai_stats = self.openai_service.get_usage_stats()
                if openai_stats:
                    stats["ai_analyzed"] = openai_stats.get("processed_threats", 0)
                    stats["ai_confidence"] = openai_stats.get("average_confidence", 0)
                available_services.append("OpenAI")
            
            # Get Content Safety stats
            if self.content_safety.available:
                safety_stats = self.content_safety.get_usage_stats()
                if safety_stats:
                    stats["unsafe_content"] = safety_stats.get("flagged_content", 0)
                available_services.append("Content Safety")
            
            # Get Search Service stats
            if self.search_service.available:
                search_stats = self.search_service.get_usage_stats()
                if search_stats:
                    stats["similar_threats"] = search_stats.get("similar_threats_found", 0)
                available_services.append("Search Service")
            
            # Get Metrics Advisor stats
            if self.metrics_advisor.available:
                metrics_stats = self.metrics_advisor.get_usage_stats()
                if metrics_stats:
                    stats["metrics_alerts"] = metrics_stats.get("active_alerts", 0)
                available_services.append("Metrics Advisor")
            
            stats["services_available"] = available_services
            
        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            stats["error"] = str(e)
        
        return stats
