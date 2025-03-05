from fastapi import APIRouter, HTTPException
from typing import List
from datetime import datetime
import uuid
from app.models.domain.threat import ThreatAlert

router = APIRouter()

@router.get("/", response_model=List[ThreatAlert])
async def list_incidents():
    """
    List all security incidents
    """
    # TODO: Implement actual incident retrieval from database
    return []

@router.get("/{incident_id}", response_model=ThreatAlert)
async def get_incident(incident_id: str):
    """
    Get details of a specific security incident
    """
    # TODO: Implement actual incident retrieval from database
    raise HTTPException(status_code=404, detail="Incident not found")
