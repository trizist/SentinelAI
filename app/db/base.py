from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.config import settings
import logging
import asyncio

logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    pool_pre_ping=True,  # Add connection testing
    pool_recycle=300,    # Recycle connections after 5 minutes
    # Removed connect_timeout which is not supported by asyncpg
)

async_session = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Dependency with retry logic for database connection
async def get_session() -> AsyncSession:
    max_retries = 5
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries):
        try:
            async with async_session() as session:
                # Test connection with a simple query
                await session.execute("SELECT 1")
                logger.debug("Database connection established successfully")
                yield session
                return
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Database connection attempt {attempt+1} failed: {str(e)}. Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logger.error(f"Failed to connect to database after {max_retries} attempts: {str(e)}")
                raise
