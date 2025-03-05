from typing import AsyncGenerator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.db.base import get_session
from app.db.models import User
from sqlalchemy import select
import logging

logger = logging.getLogger(__name__)

# Initialize OAuth2 scheme with token URL
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=True
)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session"""
    try:
        session = await anext(get_session())
        yield session
    finally:
        await session.close()

async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """Get the current authenticated user from token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Import jwt functions here to avoid circular imports
        from jose import jwt, JWTError
        
        # Decode token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        email: Optional[str] = payload.get("sub")
        if email is None:
            logger.warning("Token payload missing 'sub' claim")
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWT error: {str(e)}")
        raise credentials_exception
    except ImportError as e:
        logger.error(f"ImportError in get_current_user: {str(e)}")
        raise credentials_exception
    
    try:
        # Find user in database
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        
        if user is None:
            logger.warning(f"User not found: {email}")
            raise credentials_exception
            
        if not user.is_active:
            logger.warning(f"Inactive user attempted access: {email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user"
            )
            
        return user
    except Exception as e:
        logger.error(f"Database error in get_current_user: {str(e)}")
        raise credentials_exception
