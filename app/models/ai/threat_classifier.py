# Define AI_DEPENDENCIES_AVAILABLE at module level for easier import checking
AI_DEPENDENCIES_AVAILABLE = False

# Try to import AI dependencies with proper error handling
try:
    # Use a simpler approach - don't try to import TensorFlow yet
    import numpy as np
    AI_DEPENDENCIES_AVAILABLE = True
    # Don't attempt to import TensorFlow/PyTorch until needed
except ImportError:
    AI_DEPENDENCIES_AVAILABLE = False
    
from typing import List, Dict, Any, Tuple, Optional
import json
import os
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class ThreatClassifier:
    def __init__(self):
        self.is_ready = False
        self.model = None
        self.tokenizer = None
        
        # Load MITRE ATT&CK techniques mapping regardless of AI availability
        self.techniques_map = self._load_techniques_map()
        
        if not settings.USE_AI_FEATURES:
            logger.warning("AI features are disabled in configuration")
            return
            
        if not AI_DEPENDENCIES_AVAILABLE:
            logger.warning("AI dependencies are not available. ThreatClassifier will run in limited mode.")
            return
        
        # Defer model loading until needed
        logger.info("ThreatClassifier initialized in deferred loading mode")
        
    def _load_model(self):
        """Load AI model on demand"""
        if self.is_ready or not AI_DEPENDENCIES_AVAILABLE:
            return
            
        try:
            # Only import TensorFlow when actually needed
            import tensorflow as tf
            from transformers import DistilBertTokenizer, TFDistilBertForSequenceClassification
            
            self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
            self.model = TFDistilBertForSequenceClassification.from_pretrained(
                'distilbert-base-uncased',
                num_labels=4  # Normal, Low, Medium, High
            )
            self.is_ready = True
            logger.info("ThreatClassifier model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading AI model: {str(e)}")
        
    def _load_techniques_map(self) -> Dict[str, str]:
        """Load MITRE ATT&CK techniques mapping"""
        techniques_file = os.path.join(settings.AI_MODEL_PATH, 'mitre_techniques.json')
        if os.path.exists(techniques_file):
            try:
                with open(techniques_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading MITRE techniques: {str(e)}")
        else:
            logger.warning(f"MITRE techniques file not found at {techniques_file}")
        return {}

    def preprocess_input(self, data: Dict[str, Any]) -> str:
        """Convert input data to text format for classification"""
        # Combine relevant fields into a text description
        fields = [
            f"source_ip: {data.get('source_ip', 'unknown')}",
            f"destination_ip: {data.get('destination_ip', 'unknown')}",
            f"protocol: {data.get('protocol', 'unknown')}",
            f"payload: {data.get('payload', 'none')}",
            f"behavior: {data.get('behavior', 'unknown')}"
        ]
        return " | ".join(fields)

    def predict(self, data: Dict[str, Any]) -> Tuple[str, float, List[str]]:
        """
        Predict threat level and identify potential MITRE ATT&CK techniques
        Returns: (severity, confidence, techniques)
        """
        # Always identify techniques regardless of AI model availability
        techniques = self._identify_techniques(data)
        
        # Try to load model if it's not loaded yet and AI is available
        if AI_DEPENDENCIES_AVAILABLE and not self.is_ready:
            self._load_model()
        
        # Default values if AI is not available
        severity = "UNKNOWN"
        confidence = 0.0
        
        # If AI is not ready, return basic analysis
        if not self.is_ready:
            logger.warning("ThreatClassifier is not ready. Returning basic prediction.")
            # Perform basic heuristic analysis without ML
            severity = self._basic_threat_analysis(data)
            confidence = 0.5  # Medium confidence for heuristic analysis
            return severity, confidence, techniques
            
        try:
            # Preprocess input
            text = self.preprocess_input(data)
            
            # Tokenize
            inputs = self.tokenizer(
                text,
                truncation=True,
                padding=True,
                return_tensors="tf"
            )
            
            # Get prediction
            outputs = self.model(inputs)
            
            import tensorflow as tf
            predictions = tf.nn.softmax(outputs.logits, axis=-1)
            predicted_class = tf.argmax(predictions, axis=-1).numpy()[0]
            confidence = float(predictions.numpy().max())
            
            # Map class to severity
            severity_map = {0: "NORMAL", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}
            severity = severity_map[predicted_class]
            
            logger.info(f"Prediction complete: {severity} with {confidence:.2f} confidence")
            
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}")
            # Fall back to basic analysis if AI prediction fails
            severity = self._basic_threat_analysis(data)
            confidence = 0.4  # Lower confidence for fallback analysis
            
        return severity, confidence, techniques

    def _basic_threat_analysis(self, data: Dict[str, Any]) -> str:
        """Perform basic threat analysis without ML models"""
        # Simple rules-based threat analysis
        payload = str(data.get('payload', '')).lower()
        behavior = str(data.get('behavior', '')).lower()
        
        # High severity indicators
        high_indicators = ['malware', 'ransomware', 'exploit', 'attack', 'vulnerability']
        if any(indicator in payload or indicator in behavior for indicator in high_indicators):
            return "HIGH"
            
        # Medium severity indicators
        medium_indicators = ['scan', 'probe', 'suspicious', 'unusual', 'admin']
        if any(indicator in payload or indicator in behavior for indicator in medium_indicators):
            return "MEDIUM"
            
        # Low severity indicators
        low_indicators = ['warning', 'notice', 'attempt', 'failed']
        if any(indicator in payload or indicator in behavior for indicator in low_indicators):
            return "LOW"
            
        return "NORMAL"

    def _identify_techniques(self, data: Dict[str, Any]) -> List[str]:
        """Identify potential MITRE ATT&CK techniques based on the input data"""
        techniques = []
        
        payload = str(data.get('payload', '')).lower()
        behavior = str(data.get('behavior', '')).lower()
        protocol = str(data.get('protocol', '')).lower()
        
        # Example technique identification logic
        if protocol == 'http' and 'admin' in payload:
            techniques.append('T1190')  # Exploit Public-Facing Application
        
        if 'scan' in behavior or 'scanning' in behavior:
            techniques.append('T1046')  # Network Service Scanning
            
        if 'select' in payload and 'from' in payload:
            techniques.append('T1190')  # SQL Injection
            
        if 'brute' in behavior or 'password' in payload:
            techniques.append('T1110')  # Brute Force
            
        if 'execute' in payload or 'cmd' in payload or 'command' in payload:
            techniques.append('T1059')  # Command and Scripting Interpreter
            
        return techniques
