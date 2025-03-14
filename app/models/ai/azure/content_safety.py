"""
Azure Content Safety Service integration for SentinelAI.
This module provides a wrapper around Azure Content Safety for detecting
malicious URLs, phishing content, and other harmful data.
"""
import os
import json
import logging
import re
from typing import Dict, Any, Optional, List, Tuple

# Check if Azure Content Safety SDK is available
try:
    from azure.ai.contentsafety import ContentSafetyClient
    from azure.core.credentials import AzureKeyCredential
    from azure.core.exceptions import HttpResponseError
    from azure.ai.contentsafety.models import (
        AnalyzeTextOptions, 
        AnalyzeImageOptions,
        TextCategory, 
        ImageCategory
    )
    AZURE_CONTENT_SAFETY_AVAILABLE = True
except ImportError:
    AZURE_CONTENT_SAFETY_AVAILABLE = False
    logging.warning("Azure Content Safety SDK not installed. Service will be unavailable.")

logger = logging.getLogger(__name__)

class AzureContentSafety:
    """Azure Content Safety service wrapper for SentinelAI security content analysis."""
    
    def __init__(self):
        """Initialize the Azure Content Safety service with credentials from environment variables."""
        self.endpoint = os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT")
        self.key = os.getenv("AZURE_CONTENT_SAFETY_KEY")
        self.available = AZURE_CONTENT_SAFETY_AVAILABLE and self.endpoint and self.key
        self.client = None
        
        if self.available:
            try:
                self.client = ContentSafetyClient(
                    endpoint=self.endpoint,
                    credential=AzureKeyCredential(self.key)
                )
                logger.info("Azure Content Safety initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Azure Content Safety client: {str(e)}")
                self.available = False
        else:
            logger.warning("Azure Content Safety service is not available.")
    
    def analyze_text(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Analyze text content for harmful content.
        
        Args:
            text: The text to analyze
            
        Returns:
            Dictionary with analysis results or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Content Safety service is not available for text analysis.")
            return None
        
        try:
            # Truncate text if it's too long (API limit is 1000 characters)
            if len(text) > 1000:
                logger.warning("Text length exceeds 1000 characters, truncating.")
                text = text[:1000]
            
            # Analyze the text
            request = AnalyzeTextOptions(text=text)
            response = self.client.analyze_text(request)
            
            # Extract results
            result = {
                "harmful_content_detected": False,
                "categories": {}
            }
            
            # Check categories
            if response.categories:
                for category in response.categories:
                    category_name = category.category
                    score = category.score
                    
                    # Add to result
                    result["categories"][category_name] = score
                    
                    # Check if any category exceeds threshold (0.8)
                    if score > 0.8:
                        result["harmful_content_detected"] = True
            
            return result
            
        except HttpResponseError as e:
            logger.error(f"Azure Content Safety API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error analyzing text: {str(e)}")
            return None
    
    def analyze_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a URL for potential phishing or malicious content.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary with analysis results or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Content Safety service is not available for URL analysis.")
            return None
        
        try:
            # Extract domain and content from URL
            domain = self._extract_domain(url)
            
            # Analyze the URL as text
            result = self.analyze_text(url)
            
            # Add URL-specific information
            if result:
                result["url"] = url
                result["domain"] = domain
                
                # Check for common phishing indicators in the URL
                phishing_indicators = self._check_phishing_indicators(url)
                if phishing_indicators:
                    result["phishing_indicators"] = phishing_indicators
                    
                    # If phishing indicators found, mark as harmful
                    if phishing_indicators:
                        result["harmful_content_detected"] = True
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            return None
    
    def analyze_threat_payload(self, threat_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze threat payload for harmful content.
        
        Args:
            threat_data: Dictionary with threat data
            
        Returns:
            Dictionary with analysis results or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Content Safety service is not available for threat payload analysis.")
            return None
        
        try:
            result = {
                "harmful_content_detected": False,
                "analysis": []
            }
            
            # Extract potential harmful content from the threat data
            payload = threat_data.get("payload", "")
            urls = self._extract_urls(payload)
            
            # Analyze payload if available
            if payload and isinstance(payload, str):
                payload_analysis = self.analyze_text(payload)
                if payload_analysis:
                    result["analysis"].append({
                        "type": "payload",
                        "content": payload[:100] + "..." if len(payload) > 100 else payload,
                        "result": payload_analysis
                    })
                    
                    if payload_analysis.get("harmful_content_detected", False):
                        result["harmful_content_detected"] = True
            
            # Analyze URLs found in the payload
            for url in urls:
                url_analysis = self.analyze_url(url)
                if url_analysis:
                    result["analysis"].append({
                        "type": "url",
                        "content": url,
                        "result": url_analysis
                    })
                    
                    if url_analysis.get("harmful_content_detected", False):
                        result["harmful_content_detected"] = True
            
            # Add detected URLs to the result
            if urls:
                result["detected_urls"] = urls
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing threat payload: {str(e)}")
            return None
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from a URL."""
        try:
            # Simple regex to extract domain
            match = re.search(r"^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n]+)", url)
            if match:
                return match.group(1)
            return url
        except Exception:
            return url
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        if not text or not isinstance(text, str):
            return []
            
        try:
            # Regex to find URLs in text
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*(?:\?\S*)?'
            return re.findall(url_pattern, text)
        except Exception:
            return []
    
    def _check_phishing_indicators(self, url: str) -> List[str]:
        """Check for common phishing indicators in a URL."""
        indicators = []
        
        # Check for IP address instead of domain
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            indicators.append("IP address used instead of domain name")
        
        # Check for misleading domains
        common_domains = ["google", "microsoft", "apple", "amazon", "paypal", "facebook"]
        for domain in common_domains:
            if domain in url.lower() and domain not in self._extract_domain(url).lower():
                indicators.append(f"Potentially misleading use of {domain} in URL")
        
        # Check for excessive subdomains
        if url.count('.') > 3:
            indicators.append("Excessive number of subdomains")
        
        # Check for URL shorteners
        shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "shorturl"]
        for shortener in shorteners:
            if shortener in url.lower():
                indicators.append(f"URL shortener detected ({shortener})")
        
        return indicators
    
    def get_usage_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get usage statistics for the Content Safety service.
        
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
                "status": "active"
            }
        except Exception as e:
            logger.error(f"Error getting Content Safety usage stats: {str(e)}")
            return None
