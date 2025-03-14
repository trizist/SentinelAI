from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class ThreatData(BaseModel):
    """
    Model for submitting threat data for analysis
    """
    source_ip: Optional[str] = None
    description: str
    timestamp: Optional[datetime] = None
    indicators: Optional[List[str]] = None
    context: Optional[str] = None
    
class ThreatAlert(BaseModel):
    id: str
    timestamp: datetime
    severity: str
    description: str
    indicators: List[str]
    confidence_score: float
    source_ip: Optional[str]
    target_systems: List[str]
    mitre_techniques: List[str]

class ThreatResponse(BaseModel):
    threat_id: str
    timestamp: datetime
    actions_taken: List[str]
    status: str
    blocked_ips: Optional[List[str]]
    quarantined_systems: Optional[List[str]]
    recommendations: List[str]
