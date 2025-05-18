from database import accounts_validators, UserGroupEnum, UserGroupModel
from pydantic import BaseModel, EmailStr, Field


class UserBaseSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int
    password: str = Field(alias="_hashed_password")

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: str
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
