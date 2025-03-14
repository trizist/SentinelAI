from fastapi import APIRouter
from app.api.endpoints import threats, incidents, analysis, auth, ai

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
api_router.include_router(ai.router, prefix="/ai", tags=["ai"])
