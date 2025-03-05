from typing import Dict, Any, List, Tuple, Optional
import logging
import uuid
import json
import asyncio
import datetime
from app.models.ai.threat_classifier import ThreatClassifier, AI_DEPENDENCIES_AVAILABLE
from app.core.config import settings
import redis.asyncio as redis

logger = logging.getLogger(__name__)

class ThreatDetectionService:
    def __init__(self):
        if not AI_DEPENDENCIES_AVAILABLE:
            logger.warning("AI dependencies not available - ThreatDetectionService operating in limited mode")
        
        self.classifier = ThreatClassifier()
        self.redis = None
        self._job_cache = {}  # Fallback in-memory cache if Redis is unavailable
        
    async def get_redis(self) -> Optional[redis.Redis]:
        """Get Redis connection with lazy initialization"""
        if self.redis is None:
            try:
                self.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
                # Test connection
                await self.redis.ping()
                logger.info("Connected to Redis successfully")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {str(e)}")
                self.redis = None
        return self.redis
        
    async def analyze_threat(self, data: Dict[str, Any]) -> Tuple[str, float, List[str]]:
        """
        Analyze threat data using the AI model
        
        Returns:
            Tuple[str, float, List[str]]: (severity, confidence, techniques)
        """
        logger.info(f"Analyzing threat from {data.get('source_ip', 'unknown')}")
        try:
            # Use the classifier to determine severity, confidence, and MITRE techniques
            severity, confidence, techniques = self.classifier.predict(data)
            
            logger.info(f"Threat analysis result: {severity} with {confidence:.2f} confidence")
            return severity, confidence, techniques
        except Exception as e:
            logger.error(f"Error during threat analysis: {str(e)}")
            # Return a safe default if something goes wrong
            return "UNKNOWN", 0.0, []
            
    def generate_job_id(self) -> str:
        """Generate a unique job ID for batch processing"""
        return str(uuid.uuid4())
    
    async def process_batch_analysis(self, job_id: str, threats: List[Dict[str, Any]], user_id: int) -> None:
        """Process a batch of threat data asynchronously"""
        logger.info(f"Starting batch analysis job {job_id} with {len(threats)} threats")
        
        # Initialize job in cache
        job_data = {
            "status": "PROCESSING",
            "total": len(threats),
            "completed": 0,
            "results": [],
            "user_id": user_id,
            "start_time": datetime.datetime.now().isoformat(),
            "end_time": None
        }
        
        # Store job data in Redis or in-memory cache
        await self._update_job_status(job_id, job_data)
        
        try:
            results = []
            for i, threat in enumerate(threats):
                # Analyze each threat
                severity, confidence, techniques = await self.analyze_threat(threat)
                
                # Add result
                results.append({
                    "source_ip": threat.get("source_ip", "unknown"),
                    "severity": severity,
                    "confidence": confidence,
                    "techniques": techniques,
                    "recommendation": self._generate_recommendation(severity)
                })
                
                # Update progress
                job_data["completed"] = i + 1
                job_data["results"] = results
                await self._update_job_status(job_id, job_data)
                
                # Small delay to prevent overloading
                await asyncio.sleep(0.1)
            
            # Mark job as complete
            job_data["status"] = "COMPLETED"
            job_data["end_time"] = datetime.datetime.now().isoformat()
            await self._update_job_status(job_id, job_data)
            
            logger.info(f"Batch analysis job {job_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error processing batch analysis job {job_id}: {str(e)}")
            job_data["status"] = "FAILED"
            job_data["error"] = str(e)
            job_data["end_time"] = datetime.datetime.now().isoformat()
            await self._update_job_status(job_id, job_data)
    
    async def _update_job_status(self, job_id: str, job_data: Dict[str, Any]) -> None:
        """Update job status in Redis or in-memory cache"""
        # Try to use Redis
        redis_client = await self.get_redis()
        if redis_client:
            try:
                # Store job data with 24 hour expiration
                key = f"threat_job:{job_id}"
                await redis_client.set(key, json.dumps(job_data), ex=86400)
                return
            except Exception as e:
                logger.error(f"Failed to store job status in Redis: {str(e)}")
        
        # Fallback to in-memory cache
        self._job_cache[job_id] = job_data
    
    async def get_job_status(self, job_id: str, user_id: int) -> Optional[Dict[str, Any]]:
        """Get status of a batch analysis job"""
        # Try to get from Redis
        redis_client = await self.get_redis()
        if redis_client:
            try:
                key = f"threat_job:{job_id}"
                data = await redis_client.get(key)
                if data:
                    job_data = json.loads(data)
                    # Check if user has access to this job
                    if job_data.get("user_id") == user_id:
                        return job_data
                    return None
            except Exception as e:
                logger.error(f"Failed to get job status from Redis: {str(e)}")
        
        # Fallback to in-memory cache
        job_data = self._job_cache.get(job_id)
        if job_data and job_data.get("user_id") == user_id:
            return job_data
            
        return None
        
    def _generate_recommendation(self, severity: str) -> str:
        """Generate recommendation based on severity"""
        recommendations = {
            "HIGH": "Immediate action required. Isolate affected systems and investigate.",
            "MEDIUM": "Investigate promptly. Implement additional monitoring and controls.",
            "LOW": "Monitor the situation. No immediate action required.",
            "NORMAL": "No action required. Part of normal operations.",
            "UNKNOWN": "Unable to assess severity. Manual investigation recommended."
        }
        return recommendations.get(severity, "Unable to determine recommended action.")
