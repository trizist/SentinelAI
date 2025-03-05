import tensorflow as tf
import numpy as np
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta

class AnomalyDetector:
    def __init__(self):
        self.model = self._build_model()
        self._initialize_baseline()
        
    def _build_model(self) -> tf.keras.Model:
        """Build an autoencoder for anomaly detection"""
        # Input layer
        input_layer = tf.keras.layers.Input(shape=(10,))  # 10 features
        
        # Encoder
        encoded = tf.keras.layers.Dense(8, activation='relu')(input_layer)
        encoded = tf.keras.layers.Dense(4, activation='relu')(encoded)
        
        # Decoder
        decoded = tf.keras.layers.Dense(8, activation='relu')(encoded)
        decoded = tf.keras.layers.Dense(10, activation='sigmoid')(decoded)
        
        # Build autoencoder
        autoencoder = tf.keras.Model(input_layer, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        return autoencoder
    
    def _initialize_baseline(self):
        """Initialize baseline metrics for normal behavior"""
        self.baseline_metrics = {
            'avg_requests_per_minute': 100,
            'avg_payload_size': 1024,
            'common_ports': {80, 443, 22, 53},
            'baseline_hours': set(range(24))
        }
    
    def _extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from input data"""
        features = [
            float(data.get('requests_per_minute', 0)),
            float(data.get('payload_size', 0)),
            float(data.get('port', 0)),
            float(data.get('duration', 0)),
            float(data.get('packet_count', 0)),
            float(data.get('bytes_in', 0)),
            float(data.get('bytes_out', 0)),
            float(data.get('concurrent_connections', 0)),
            float(data.get('error_rate', 0)),
            float(data.get('response_time', 0))
        ]
        return np.array(features).reshape(1, -1)
    
    def detect(self, data: Dict[str, Any]) -> Tuple[bool, float, List[str]]:
        """
        Detect anomalies in the input data
        Returns: (is_anomaly, anomaly_score, reasons)
        """
        features = self._extract_features(data)
        
        # Get reconstruction error
        reconstructed = self.model.predict(features)
        mse = np.mean(np.power(features - reconstructed, 2))
        
        # Check various anomaly indicators
        reasons = []
        
        # Check request rate
        if data.get('requests_per_minute', 0) > self.baseline_metrics['avg_requests_per_minute'] * 2:
            reasons.append("Unusual request rate detected")
            
        # Check payload size
        if data.get('payload_size', 0) > self.baseline_metrics['avg_payload_size'] * 3:
            reasons.append("Unusually large payload detected")
            
        # Check port
        if data.get('port') not in self.baseline_metrics['common_ports']:
            reasons.append("Uncommon port detected")
            
        # Check time of day
        current_hour = datetime.now().hour
        if current_hour not in self.baseline_metrics['baseline_hours']:
            reasons.append("Activity outside normal hours")
        
        # Determine if this is an anomaly
        is_anomaly = mse > 0.1 or len(reasons) > 0
        
        return is_anomaly, float(mse), reasons
    
    def update_baseline(self, data: Dict[str, Any]):
        """Update baseline metrics with new normal behavior"""
        # Update average requests per minute
        self.baseline_metrics['avg_requests_per_minute'] = (
            0.9 * self.baseline_metrics['avg_requests_per_minute'] +
            0.1 * data.get('requests_per_minute', 0)
        )
        
        # Update average payload size
        self.baseline_metrics['avg_payload_size'] = (
            0.9 * self.baseline_metrics['avg_payload_size'] +
            0.1 * data.get('payload_size', 0)
        )
        
        # Update common ports
        if data.get('port'):
            self.baseline_metrics['common_ports'].add(data.get('port'))
