from fastapi import HTTPException
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

async def setup_rate_limiter():
    """Initialize the rate limiter with Redis"""
    try:
        redis_instance = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
        await FastAPILimiter.init(redis_instance)
        logger.info("Rate limiter initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize rate limiter: {e}")
        raise

# Rate limit decorators
default_rate_limit = RateLimiter(times=settings.RATE_LIMIT_PER_MINUTE, minutes=1)
auth_rate_limit = RateLimiter(times=20, minutes=1)  # Stricter limit for auth endpoints
analysis_rate_limit = RateLimiter(times=50, minutes=1)  # Higher limit for analysis endpoints
