"""
Azure OpenAI Service integration for SentinelAI.
This module provides a wrapper around Azure OpenAI for threat analysis and intelligence.
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Check if OpenAI SDK is available
try:
    from openai import AsyncOpenAI, OpenAI
    OPENAI_SDK_AVAILABLE = True
except ImportError:
    OPENAI_SDK_AVAILABLE = False
    logger.warning("OpenAI SDK not installed. Azure OpenAI service will be unavailable.")

class AzureOpenAIService:
    """Azure OpenAI service wrapper for SentinelAI threat analysis."""
    
    def __init__(self):
        """Initialize the Azure OpenAI service with credentials from environment variables."""
        self.api_key = os.getenv("AZURE_OPENAI_API_KEY")
        self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        self.api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2023-05-15")
        self.deployment_name = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4")
        
        # Check if service is available (SDK installed and credentials provided)
        self.available = OPENAI_SDK_AVAILABLE and self.api_key and self.endpoint
        
        if self.available:
            try:
                # Initialize the client
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url=f"{self.endpoint}/openai/deployments/{self.deployment_name}",
                    default_headers={"api-key": self.api_key}
                )
                self.async_client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=f"{self.endpoint}/openai/deployments/{self.deployment_name}",
                    default_headers={"api-key": self.api_key}
                )
                logger.info("Azure OpenAI service initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Azure OpenAI client: {str(e)}")
                self.available = False
        else:
            logger.warning("Azure OpenAI service is not available.")
    
    def analyze_security_log(self, log_data: str) -> Optional[str]:
        """
        Analyze security logs to identify potential security threats.
        
        Args:
            log_data: The security log data to analyze
            
        Returns:
            Analysis results or None if the service is unavailable
        """
        if not self.available:
            logger.warning("Azure OpenAI service unavailable. Skipping security log analysis.")
            return None
            
        try:
            prompt = (
                "You are an AI security analyst. Analyze the following security log and identify "
                "potential threats. Categorize each threat by severity (Low, Medium, High, Critical) "
                "and provide a brief explanation.\n\n"
                f"Log data:\n{log_data}\n\n"
                "Analysis:"
            )
            
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": prompt},
                ],
                model=self.deployment_name,
                temperature=0.3,
                max_tokens=500
            )
            
            # Extract the response content
            if response.choices and len(response.choices) > 0:
                return response.choices[0].message.content.strip()
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing security log: {str(e)}")
            return None
    
    def generate_mitigation_steps(self, threat_data: Dict[str, Any]) -> Optional[str]:
        """
        Generate mitigation steps for an identified security threat.
        
        Args:
            threat_data: Dictionary containing threat information
            
        Returns:
            Mitigation recommendations or None if the service is unavailable
        """
        if not self.available:
            logger.warning("Azure OpenAI service unavailable. Skipping mitigation generation.")
            return None
            
        try:
            # Convert threat data to a formatted string for the prompt
            threat_str = json.dumps(threat_data, indent=2)
            
            prompt = (
                "You are a cybersecurity expert. Based on the following threat information, "
                "provide a prioritized list of specific mitigation steps.\n\n"
                f"Threat data:\n{threat_str}\n\n"
                "Recommended mitigation steps:"
            )
            
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": prompt},
                ],
                model=self.deployment_name,
                temperature=0.2,
                max_tokens=400
            )
            
            # Extract the response content
            if response.choices and len(response.choices) > 0:
                return response.choices[0].message.content.strip()
            
            return None
            
        except Exception as e:
            logger.error(f"Error generating mitigation steps: {str(e)}")
            return None
    
    def classify_threat(self, threat_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Classify a security threat using Azure OpenAI.
        
        Args:
            threat_data: Dictionary containing threat information
            
        Returns:
            Dictionary with threat classification or None if service is unavailable
        """
        if not self.available:
            logger.warning("Azure OpenAI service unavailable. Skipping threat classification.")
            return None
            
        try:
            # Convert threat data to a formatted string for the prompt
            threat_str = json.dumps(threat_data, indent=2)
            
            prompt = (
                "You are a cybersecurity threat classifier. Analyze this threat and classify it "
                "by type, severity, and priority. Respond in JSON format.\n\n"
                f"Threat data:\n{threat_str}\n\n"
                "Respond with JSON in this format:\n"
                "{\n"
                "  \"threat_type\": \"[THREAT TYPE]\",\n"
                "  \"severity\": \"[Low/Medium/High/Critical]\",\n"
                "  \"priority\": \"[Low/Medium/High/Critical]\",\n"
                "  \"confidence\": \"[0-100 percentage]\",\n"
                "  \"description\": \"[Brief description]\"\n"
                "}\n\n"
                "JSON response:"
            )
            
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": prompt},
                ],
                model=self.deployment_name,
                temperature=0.1,
                max_tokens=400
            )
            
            # Extract the response content
            if response.choices and len(response.choices) > 0:
                try:
                    content = response.choices[0].message.content
                    return json.loads(content)
                except json.JSONDecodeError as je:
                    logger.error(f"Failed to parse OpenAI response as JSON: {str(je)}")
                    return None
            
            return None
            
        except Exception as e:
            logger.error(f"Error classifying threat: {str(e)}")
            return None
    
    def summarize_threats(self, threats: List[Dict[str, Any]]) -> Optional[str]:
        """
        Provide a summary of multiple threat entries.
        
        Args:
            threats: List of threat dictionaries
            
        Returns:
            Summary text or None if service is unavailable
        """
        if not self.available:
            logger.warning("Azure OpenAI service unavailable. Skipping threat summarization.")
            return None
            
        if not threats:
            return "No threats to summarize."
            
        try:
            # Convert threats to a formatted string
            threats_str = json.dumps(threats, indent=2)
            
            prompt = (
                "You are a cybersecurity analyst. Summarize the following collection of security threats "
                "into a concise executive summary. Highlight patterns, severity distribution, and recommendations.\n\n"
                f"Threats:\n{threats_str}\n\n"
                "Executive Summary:"
            )
            
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": prompt},
                ],
                model=self.deployment_name,
                temperature=0.3,
                max_tokens=600
            )
            
            # Extract the response content
            if response.choices and len(response.choices) > 0:
                return response.choices[0].message.content.strip()
            
            return None
            
        except Exception as e:
            logger.error(f"Error summarizing threats: {str(e)}")
            return None
    
    def classify_threat(self, prompt: str) -> Optional[Dict[str, Any]]:
        """
        Classify a threat using OpenAI.
        
        Args:
            prompt: The threat prompt to classify
            
        Returns:
            Dictionary with classification results or None if service is unavailable
        """
        if not self.available:
            logger.warning("Azure OpenAI service is not available for threat classification.")
            return None
        
        try:
            system_message = """
            You are a cybersecurity threat analyzer. Your task is to classify security threats and 
            provide an assessment of their severity and potential impact. Respond with a JSON 
            object that includes:
            - classification: The type of threat (e.g., malware, phishing, DDoS, etc.)
            - confidence: A confidence score between 0 and 1
            - severity: A severity level (low, medium, high, critical)
            - summary: A brief summary of the threat
            """
            
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                model=self.deployment_name,
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            
            # Extract the response content
            if response.choices and len(response.choices) > 0:
                try:
                    content = response.choices[0].message.content
                    return json.loads(content)
                except json.JSONDecodeError as je:
                    logger.error(f"Failed to parse OpenAI response as JSON: {str(je)}")
                    return None
            
            return None
            
        except Exception as e:
            logger.error(f"Error in Azure OpenAI threat classification: {str(e)}")
            return None
    
    def generate_recommendation(self, prompt: str) -> Optional[str]:
        """
        Generate a security recommendation based on threat information.
        
        Args:
            prompt: The prompt containing threat information
            
        Returns:
            Recommendation string or None if service is unavailable
        """
        if not self.available:
            logger.warning("Azure OpenAI service is not available for recommendation generation.")
            return None
        
        try:
            system_message = """
            You are a cybersecurity advisor. Based on the threat information provided, 
            generate a concise, actionable security recommendation. Focus on practical steps 
            that security teams can take to mitigate the threat. Be specific and prioritize 
            the most important actions first.
            """
            
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt}
                ],
                model=self.deployment_name,
                temperature=0.3,
                max_tokens=200
            )
            
            # Extract the response content
            if response.choices and len(response.choices) > 0:
                return response.choices[0].message.content.strip()
            
            return None
            
        except Exception as e:
            logger.error(f"Error in Azure OpenAI recommendation generation: {str(e)}")
            return None
    
    def get_usage_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get usage statistics for the OpenAI service.
        
        Returns:
            Dictionary with usage statistics or None if service is unavailable
        """
        if not self.available:
            return None
        
        try:
            # For now, return basic information
            # In a production system, you would likely track usage in a database
            return {
                "model": self.deployment_name,
                "requests_today": 0,  # placeholder
                "tokens_used": 0,     # placeholder
                "status": "active"
            }
        except Exception as e:
            logger.error(f"Error getting OpenAI usage stats: {str(e)}")
            return None
