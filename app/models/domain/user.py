from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    is_active: bool = True

    model_config = ConfigDict(from_attributes=True)

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)

class UserInDB(UserBase):
    id: int
    hashed_password: str
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class User(UserBase):
    id: int
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={
            datetime: lambda dt: dt.isoformat() if dt else None
        }
    )

class Token(BaseModel):
    access_token: str
    token_type: str = Field(default="bearer")

class TokenPayload(BaseModel):
    sub: str = Field(..., description="Subject (user email)")
    exp: Optional[datetime] = Field(None, description="Expiration time")
