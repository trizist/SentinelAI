import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import asyncio
from typing import Generator, AsyncGenerator
import os
import sys
import logging

# Configure test logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/test.log", mode='w'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.db.base import Base
from app.core.config import settings
from app.api.deps import get_db

# Use in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=True,  # Enable SQL logging
    echo_pool=True,  # Enable connection pool logging
    future=True
)

async_session = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    yield loop
    loop.close()

@pytest_asyncio.fixture(scope="function")
async def test_db_engine():
    """Create test database engine."""
    logger.info("Creating test database engine")
    
    async with engine.begin() as conn:
        logger.info("Creating database tables")
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    async with engine.begin() as conn:
        logger.info("Dropping database tables")
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()

@pytest_asyncio.fixture
async def test_db(test_db_engine):
    """Create a new database session for a test."""
    logger.info("Creating test database session")
    
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

@pytest_asyncio.fixture
async def client(test_db) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client with the test database."""
    logger.info("Creating test client")
    
    async def override_get_db():
        logger.info("Using test database")
        try:
            yield test_db
        finally:
            logger.info("Finished using test database")
    
    app.dependency_overrides[get_db] = override_get_db
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        logger.info("Test client created")
        yield ac
    
    logger.info("Cleaning up test client")
    app.dependency_overrides.clear()
