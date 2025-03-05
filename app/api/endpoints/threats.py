from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from app.services.threat_detection import ThreatDetectionService
from app.api.deps import get_current_user
from app.db.models import User
import logging
import time
from datetime import datetime, timedelta
import random
import uuid
import asyncio

logger = logging.getLogger(__name__)
router = APIRouter()

class ThreatData(BaseModel):
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    protocol: Optional[str] = Field(None, description="Network protocol")
    payload: Optional[str] = Field(None, description="Data payload")
    behavior: Optional[str] = Field(None, description="Observed behavior")
    timestamp: Optional[str] = Field(None, description="Time of event")
    additional_data: Optional[Dict[str, Any]] = Field(None, description="Any additional data")

class ThreatResponse(BaseModel):
    severity: str = Field(..., description="Threat severity level (NORMAL, LOW, MEDIUM, HIGH)")
    confidence: float = Field(..., description="Confidence score between 0 and 1")
    techniques: List[str] = Field(default=[], description="MITRE ATT&CK techniques identified")
    recommendation: Optional[str] = Field(None, description="Recommended action")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional analysis details")

# Initialize the threat detection service
threat_service = ThreatDetectionService()

# Temporary in-memory storage for threats and jobs
# In production, this would be a database
_recent_threats = []
_job_statuses = {}
_MAX_RECENT_THREATS = 100

@router.post("/analyze")
async def analyze_threat(
    threat_data: ThreatData,
) -> JSONResponse:
    """
    Analyze potential security threat data
    """
    try:
        logger.info(f"Analyzing threat from {threat_data.source_ip}")
        
        # Call the threat detection service
        severity, confidence, techniques = await threat_service.analyze_threat(threat_data.dict())
        
        # Generate recommendation based on severity
        recommendation = generate_recommendation(severity)
        
        # Store the analyzed threat for the recent threats endpoint
        threat_id = str(uuid.uuid4())
        analyzed_threat = {
            **threat_data.dict(),
            "id": threat_id,
            "severity": severity,
            "confidence": confidence,
            "techniques": techniques,
            "recommendation": recommendation,
            "analysis_time": datetime.utcnow().isoformat()
        }
        _recent_threats.append(analyzed_threat)
        
        # Trim the list if needed
        if len(_recent_threats) > _MAX_RECENT_THREATS:
            _recent_threats.pop(0)
        
        # Return the response
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "severity": severity,
                "confidence": confidence,
                "techniques": techniques,
                "recommendation": recommendation,
                "id": threat_id
            }
        )
    except Exception as e:
        logger.error(f"Error analyzing threat: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to analyze threat: {str(e)}"}
        )

@router.post("/batch-analyze")
async def batch_analyze_threats(
    threats: List[ThreatData],
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    """
    Submit multiple threats for background analysis
    """
    try:
        # Generate a job ID
        job_id = str(uuid.uuid4())
        _job_statuses[job_id] = {
            "status": "PENDING",
            "total": len(threats),
            "completed": 0,
            "results": [],
            "start_time": datetime.utcnow().isoformat()
        }
        
        # Schedule the background task
        background_tasks.add_task(
            process_batch, 
            job_id=job_id, 
            threats=threats
        )
        
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "job_id": job_id,
                "message": f"Batch job started with {len(threats)} threats",
                "status_endpoint": f"/api/v1/threats/status/{job_id}"
            }
        )
    except Exception as e:
        logger.error(f"Error starting batch job: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to process batch request: {str(e)}"}
        )

@router.get("/status/{job_id}")
async def check_analysis_status(
    job_id: str,
) -> JSONResponse:
    """
    Check the status of a batch analysis job
    """
    if job_id not in _job_statuses:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": f"Job ID {job_id} not found"}
        )
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=_job_statuses[job_id]
    )

@router.get("/recent")
async def get_recent_threats() -> JSONResponse:
    """
    Get recent threats that have been analyzed
    """
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=_recent_threats
    )

# Background task for processing batches
async def process_batch(job_id: str, threats: List[ThreatData]):
    """Process a batch of threats in the background"""
    if job_id not in _job_statuses:
        logger.error(f"Job ID {job_id} not found in status map")
        return
    
    # Update job status
    _job_statuses[job_id]["status"] = "PROCESSING"
    
    try:
        results = []
        
        for i, threat in enumerate(threats):
            # Process each threat
            try:
                # Call the threat detection service
                severity, confidence, techniques = await threat_service.analyze_threat(threat.dict())
                
                # Generate recommendation
                recommendation = generate_recommendation(severity)
                
                # Add to results
                threat_id = str(uuid.uuid4())
                result = {
                    **threat.dict(),
                    "id": threat_id,
                    "severity": severity,
                    "confidence": confidence,
                    "techniques": techniques,
                    "recommendation": recommendation,
                    "analysis_time": datetime.utcnow().isoformat()
                }
                results.append(result)
                
                # Add to recent threats
                _recent_threats.append(result)
                # Trim the list if needed
                if len(_recent_threats) > _MAX_RECENT_THREATS:
                    _recent_threats.pop(0)
                
                # Update job progress
                _job_statuses[job_id]["completed"] = i + 1
                
                # Simulate some processing time
                await asyncio.sleep(0.1)
            
            except Exception as e:
                logger.error(f"Error processing threat in batch: {str(e)}")
                # Add failed result
                results.append({
                    **threat.dict(),
                    "error": str(e),
                    "severity": "UNKNOWN",
                    "confidence": 0.0,
                    "techniques": [],
                    "recommendation": "Failed to analyze"
                })
        
        # Update job status
        _job_statuses[job_id]["status"] = "COMPLETED"
        _job_statuses[job_id]["results"] = results
        _job_statuses[job_id]["end_time"] = datetime.utcnow().isoformat()
        
    except Exception as e:
        logger.error(f"Error processing batch job {job_id}: {str(e)}")
        _job_statuses[job_id]["status"] = "FAILED"
        _job_statuses[job_id]["error"] = str(e)
        _job_statuses[job_id]["end_time"] = datetime.utcnow().isoformat()

def generate_recommendation(severity: str) -> str:
    """Generate a recommended action based on threat severity"""
    recommendations = {
        "HIGH": "Immediate action required. Isolate affected systems and investigate.",
        "MEDIUM": "Investigate promptly. Implement additional monitoring and controls.",
        "LOW": "Monitor the situation. No immediate action required.",
        "NORMAL": "No action required. Part of normal operations.",
        "UNKNOWN": "Unable to assess severity. Manual investigation recommended."
    }
    return recommendations.get(severity, "Unable to determine recommended action.")
