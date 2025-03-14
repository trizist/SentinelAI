from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import uuid
import logging
import time
import random
import asyncio
from app.models.domain.threat import ThreatData, ThreatResponse
from app.services.threat_detection import ThreatDetectionService
from app.db.models import User
from app.api.deps import get_current_user

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

@router.post("/{threat_id}/resolve")
async def resolve_threat(
    threat_id: str,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """
    Mark a threat as resolved after investigation
    """
    try:
        # Find the threat in our temporary storage
        threat_index = next((i for i, t in enumerate(_recent_threats) if t.get("id") == threat_id), None)
        
        if threat_index is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": f"Threat with ID {threat_id} not found"}
            )
        
        # Update the threat status
        _recent_threats[threat_index]["status"] = "RESOLVED"
        _recent_threats[threat_index]["resolved_by"] = current_user.username
        _recent_threats[threat_index]["resolved_at"] = datetime.utcnow().isoformat()
        
        logger.info(f"Threat {threat_id} resolved by {current_user.username}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Threat {threat_id} marked as resolved",
                "threat": _recent_threats[threat_index]
            }
        )
    except Exception as e:
        logger.error(f"Error resolving threat: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to resolve threat: {str(e)}"}
        )

@router.post("/{threat_id}/block")
async def block_threat(
    threat_id: str,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """
    Block the source IP of a threat
    """
    try:
        # Find the threat in our temporary storage
        threat_index = next((i for i, t in enumerate(_recent_threats) if t.get("id") == threat_id), None)
        
        if threat_index is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": f"Threat with ID {threat_id} not found"}
            )
        
        # Get the source IP
        source_ip = _recent_threats[threat_index].get("source_ip")
        if not source_ip:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Threat doesn't have a source IP to block"}
            )
        
        # Update the threat status
        _recent_threats[threat_index]["status"] = "BLOCKED"
        _recent_threats[threat_index]["blocked_by"] = current_user.username
        _recent_threats[threat_index]["blocked_at"] = datetime.utcnow().isoformat()
        
        # In a real-world scenario, you would integrate with a firewall or IPS here
        # For now, we'll just simulate the blocking
        logger.info(f"Source IP {source_ip} from threat {threat_id} blocked by {current_user.username}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Source IP {source_ip} from threat {threat_id} has been blocked",
                "threat": _recent_threats[threat_index]
            }
        )
    except Exception as e:
        logger.error(f"Error blocking threat: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to block threat: {str(e)}"}
        )

@router.post("/{threat_id}/escalate")
async def escalate_threat(
    threat_id: str,
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """
    Escalate a threat to an incident for further investigation
    """
    try:
        # Find the threat in our temporary storage
        threat_index = next((i for i, t in enumerate(_recent_threats) if t.get("id") == threat_id), None)
        
        if threat_index is None:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": f"Threat with ID {threat_id} not found"}
            )
        
        # Update the threat status
        _recent_threats[threat_index]["status"] = "ESCALATED"
        _recent_threats[threat_index]["escalated_by"] = current_user.username
        _recent_threats[threat_index]["escalated_at"] = datetime.utcnow().isoformat()
        
        # In a real scenario, this would create a new incident record in the database
        # and trigger notifications to the incident response team
        logger.info(f"Threat {threat_id} escalated to incident by {current_user.username}")
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Threat {threat_id} escalated to incident",
                "threat": _recent_threats[threat_index]
            }
        )
    except Exception as e:
        logger.error(f"Error escalating threat: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Failed to escalate threat: {str(e)}"}
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
