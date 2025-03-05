import asyncio
import logging
from app.db.base import Base, engine
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models import User
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def create_first_superuser(session: AsyncSession):
    """Create a superuser if it doesn't exist"""
    try:
        # Create superuser
        superuser = User(
            email="admin@cybercare.com",
            username="admin",
            hashed_password=get_password_hash("admin123"),  # Change this in production
            is_superuser=True,
            full_name="System Administrator"
        )
        session.add(superuser)
        await session.commit()
        logger.info("Superuser created successfully")
    except Exception as e:
        logger.error(f"Error creating superuser: {e}")
        await session.rollback()
        raise

async def init_db():
    """Initialize the database"""
    try:
        # Create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Tables created successfully")

        # Create async session
        async_session = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with async_session() as session:
            await create_first_superuser(session)

    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(init_db())
