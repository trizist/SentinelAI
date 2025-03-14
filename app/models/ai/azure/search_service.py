"""
Azure AI Search Service integration for SentinelAI.
This module provides a wrapper around Azure AI Search for threat intelligence retrieval.
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List, Union

# Check if Azure AI Search SDK is available
try:
    from azure.search.documents import SearchClient
    from azure.search.documents.models import QueryType
    from azure.core.credentials import AzureKeyCredential
    from azure.core.exceptions import HttpResponseError
    AZURE_SEARCH_AVAILABLE = True
except ImportError:
    AZURE_SEARCH_AVAILABLE = False
    logging.warning("Azure AI Search SDK not installed. Service will be unavailable.")

logger = logging.getLogger(__name__)

class AzureSearchService:
    """Azure AI Search service wrapper for SentinelAI threat intelligence."""
    
    def __init__(self):
        """Initialize the Azure AI Search service with credentials from environment variables."""
        self.endpoint = os.getenv("AZURE_SEARCH_ENDPOINT")
        self.key = os.getenv("AZURE_SEARCH_KEY")
        self.index_name = os.getenv("AZURE_SEARCH_INDEX_NAME", "cybersecurity-threats")
        self.available = AZURE_SEARCH_AVAILABLE and self.endpoint and self.key
        self.client = None
        
        if self.available:
            try:
                self.client = SearchClient(
                    endpoint=self.endpoint,
                    index_name=self.index_name,
                    credential=AzureKeyCredential(self.key)
                )
                logger.info("Azure Search Service initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Azure Search client: {str(e)}")
                self.available = False
        else:
            logger.warning("Azure Search Service is not available.")
    
    def search_threats(self, query: str, top: int = 10) -> Optional[List[Dict[str, Any]]]:
        """
        Search for threats using the provided query.
        
        Args:
            query: The search query string
            top: Maximum number of results to return
            
        Returns:
            List of threat dictionaries or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Search Service is not available for threat search.")
            return None
        
        try:
            # Run the search
            results = self.client.search(
                search_text=query,
                query_type=QueryType.SEMANTIC,
                query_language="en-us",
                top=top,
                include_total_count=True
            )
            
            # Extract and format results
            formatted_results = []
            for result in results:
                # Extract data from the search result
                threat_data = {k: v for k, v in result.items() if not k.startswith('@')}
                
                # Add score from search results
                threat_data["search_score"] = result.get("@search.score", 0)
                
                formatted_results.append(threat_data)
            
            return formatted_results
            
        except HttpResponseError as e:
            logger.error(f"Azure Search API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error searching threats: {str(e)}")
            return None
    
    def get_similar_threats(self, threat_data: Dict[str, Any], 
                          top: int = 5) -> Optional[List[Dict[str, Any]]]:
        """
        Find threats similar to the provided threat data.
        
        Args:
            threat_data: The threat data to find similar threats for
            top: Maximum number of results to return
            
        Returns:
            List of similar threat dictionaries or None if service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Search Service is not available for similar threat search.")
            return None
        
        try:
            # Create a search query from the threat data
            query_parts = []
            
            # Add key threat attributes to the query
            if "type" in threat_data:
                query_parts.append(f"type:{threat_data['type']}")
            
            if "behavior" in threat_data:
                query_parts.append(f"behavior:{threat_data['behavior']}")
            
            if "severity" in threat_data:
                query_parts.append(f"severity:{threat_data['severity']}")
            
            if "source_ip" in threat_data:
                query_parts.append(f"source_ip:{threat_data['source_ip']}")
            
            # If we don't have enough query parts, add a generic description
            if len(query_parts) < 2:
                query_parts.append("cybersecurity threat")
            
            # Join the query parts
            query = " ".join(query_parts)
            
            # Run the search
            return self.search_threats(query, top)
            
        except Exception as e:
            logger.error(f"Error finding similar threats: {str(e)}")
            return None
    
    def get_threat_by_id(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a threat by its ID.
        
        Args:
            threat_id: The ID of the threat to retrieve
            
        Returns:
            Threat dictionary or None if not found or service is unavailable
        """
        if not self.available or not self.client:
            logger.warning("Azure Search Service is not available for threat retrieval.")
            return None
        
        try:
            # Retrieve the document by ID
            result = self.client.get_document(key=threat_id)
            
            if result:
                return {k: v for k, v in result.items()}
            
            return None
            
        except HttpResponseError as e:
            logger.error(f"Azure Search API error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving threat by ID: {str(e)}")
            return None
    
    def get_usage_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get usage statistics for the Search service.
        
        Returns:
            Dictionary with usage statistics or None if service is unavailable
        """
        if not self.available:
            return None
        
        try:
            # Return basic information
            # In a production system, you would likely track usage in a database
            return {
                "searches_today": 0,  # placeholder
                "index_name": self.index_name,
                "status": "active"
            }
        except Exception as e:
            logger.error(f"Error getting Search service usage stats: {str(e)}")
            return None
