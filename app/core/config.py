from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import EmailStr, Field
from typing import Optional, Dict, Any
from pathlib import Path
import os
from dotenv import load_dotenv
import logging

load_dotenv()

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow"
    )

    # Base settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "CyberCare AI-Powered Cyber Responder"
    VERSION: str = "0.1.0"
    SECRET_KEY: str = "secret-key-placeholder"  # Change in production
    DEBUG: bool = True
    
    # Security
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    
    # Model settings
    MODEL_PATH: str = "app/models/ai/trained_models"
    THREAT_DETECTION_THRESHOLD: float = 0.75
    
    # AI settings
    USE_AI_FEATURES: bool = True
    AI_MODEL_PATH: str = "app/models/ai/data"
    
    # Redis settings
    REDIS_URL: str = "redis://redis:6379/0"
    RATE_LIMIT_PER_MINUTE: int = Field(default=100)
    
    # Database settings
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@db:5432/cybercare"
    
    # CORS settings
    CORS_ORIGINS: list = ["*"]
    
    # Email settings
    SMTP_TLS: bool = True
    SMTP_PORT: int = Field(default=587)
    SMTP_HOST: str = Field(default="smtp.gmail.com")
    SMTP_USER: str = Field(default="")
    SMTP_PASSWORD: str = Field(default="")
    EMAILS_FROM_EMAIL: Optional[EmailStr] = None
    EMAILS_FROM_NAME: str = Field(default="CyberCare Security")
    
    # First Superuser
    FIRST_SUPERUSER_EMAIL: EmailStr = Field(default="admin@example.com")
    FIRST_SUPERUSER_PASSWORD: str = Field(default="changeme")
    
    # Logging settings
    LOG_LEVEL: str = Field(default="DEBUG")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE: str = "logs/app.log"

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

settings = Settings()
