from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, get_db
from app.core.security import create_access_token, verify_password, get_password_hash
from app.db.models import User
from app.models.domain.user import Token, UserCreate, User as UserModel
from sqlalchemy import select
from app.core.config import settings
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/login", response_model=Token)
async def login_access_token(
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """OAuth2 compatible token login, get an access token for future requests"""
    logger.info(f"Login attempt for user: {form_data.username}")
    try:
        # Query for user
        result = await db.execute(
            select(User).where(User.email == form_data.username)
        )
        user = result.scalar_one_or_none()
        
        if not user or not verify_password(form_data.password, user.hashed_password):
            logger.warning(f"Failed login attempt for user: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        elif not user.is_active:
            logger.warning(f"Login attempt for inactive user: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user"
            )
            
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token = create_access_token(
            subject=user.email,
            expires_delta=access_token_expires
        )
        logger.info(f"Successful login for user: {form_data.username}")
        return Token(
            access_token=token,
            token_type="bearer"
        )
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        raise

@router.post("/register", response_model=UserModel, status_code=status.HTTP_201_CREATED)
async def create_user(
    *,
    db: AsyncSession = Depends(get_db),
    user_in: UserCreate,
) -> Any:
    """Create new user"""
    logger.info(f"Creating new user with email: {user_in.email}")
    try:
        # Check if user already exists
        result = await db.execute(
            select(User).where(User.email == user_in.email)
        )
        user = result.scalar_one_or_none()
        if user:
            logger.warning(f"User already exists: {user_in.email}")
            raise HTTPException(
                status_code=400,
                detail="The user with this email already exists in the system",
            )
            
        # Create new user
        now = datetime.utcnow()
        db_user = User(
            email=user_in.email,
            hashed_password=get_password_hash(user_in.password),
            full_name=user_in.full_name,
            is_active=True,
            created_at=now
        )
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        logger.info(f"Successfully created user: {user_in.email}")
        
        # Convert to response model
        return UserModel.model_validate(db_user)
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        raise

@router.get("/me", response_model=UserModel)
async def read_users_me(
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get current user."""
    return UserModel.model_validate(current_user)
