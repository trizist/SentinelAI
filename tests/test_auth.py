import pytest
import pytest_asyncio
from httpx import AsyncClient
from fastapi import status
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

@pytest.mark.asyncio
async def test_create_user(client: AsyncClient):
    """Test user creation endpoint."""
    logger.info("Testing user creation")
    try:
        response = await client.post(
            f"{settings.API_V1_PREFIX}/auth/register",
            json={
                "email": "test@example.com",
                "password": "testpassword123",
                "full_name": "Test User"
            }
        )
        logger.info(f"User creation response status: {response.status_code}")
        logger.info(f"User creation response body: {response.text}")
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["full_name"] == "Test User"
        assert "id" in data
        assert "password" not in data
    except Exception as e:
        logger.error(f"Error in test_create_user: {str(e)}")
        raise

@pytest.mark.asyncio
async def test_login(client: AsyncClient):
    """Test user login endpoint."""
    logger.info("Testing user login")
    try:
        # First create a user
        create_response = await client.post(
            f"{settings.API_V1_PREFIX}/auth/register",
            json={
                "email": "login@example.com",
                "password": "testpassword123",
                "full_name": "Login Test User"
            }
        )
        logger.info(f"User creation for login test response status: {create_response.status_code}")
        logger.info(f"User creation for login test response body: {create_response.text}")
        
        assert create_response.status_code == status.HTTP_201_CREATED
        
        # Then try to login using form data
        response = await client.post(
            f"{settings.API_V1_PREFIX}/auth/login",
            data={
                "username": "login@example.com",
                "password": "testpassword123",
                "grant_type": "password"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        logger.info(f"Login response status: {response.status_code}")
        logger.info(f"Login response body: {response.text}")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    except Exception as e:
        logger.error(f"Error in test_login: {str(e)}")
        raise

@pytest.mark.asyncio
async def test_invalid_login(client: AsyncClient):
    """Test invalid login attempt."""
    logger.info("Testing invalid login")
    try:
        response = await client.post(
            f"{settings.API_V1_PREFIX}/auth/login",
            data={
                "username": "nonexistent@example.com",
                "password": "wrongpassword",
                "grant_type": "password"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        logger.info(f"Invalid login response status: {response.status_code}")
        logger.info(f"Invalid login response body: {response.text}")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    except Exception as e:
        logger.error(f"Error in test_invalid_login: {str(e)}")
        raise
