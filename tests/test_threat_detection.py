import pytest
from httpx import AsyncClient
from fastapi import status
from app.core.security import create_access_token

pytestmark = pytest.mark.asyncio

@pytest.fixture
async def auth_headers():
    access_token = create_access_token({"sub": "test@example.com"})
    return {"Authorization": f"Bearer {access_token}"}

async def test_analyze_threat(client, auth_headers):
    response = await client.post(
        "/api/v1/threats/analyze",
        headers=auth_headers,
        json={
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "source_port": 12345,
            "destination_port": 80,
            "payload": "GET /admin HTTP/1.1"
        }
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "threat_score" in data
    assert "threat_type" in data
    assert isinstance(data["threat_score"], float)
    assert isinstance(data["threat_type"], str)

async def test_get_threat_history(client, auth_headers):
    response = await client.get(
        "/api/v1/threats/history",
        headers=auth_headers
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)

async def test_unauthorized_access(client):
    response = await client.get("/api/v1/threats/history")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

async def test_rate_limit(client, auth_headers):
    # Make multiple requests to trigger rate limit
    for _ in range(60):  # Assuming rate limit is set to 50 per minute
        await client.post(
            "/api/v1/threats/analyze",
            headers=auth_headers,
            json={
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "source_port": 12345,
                "destination_port": 80,
                "payload": "GET /admin HTTP/1.1"
            }
        )
    
    # The next request should be rate limited
    response = await client.post(
        "/api/v1/threats/analyze",
        headers=auth_headers,
        json={
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "source_port": 12345,
            "destination_port": 80,
            "payload": "GET /admin HTTP/1.1"
        }
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
