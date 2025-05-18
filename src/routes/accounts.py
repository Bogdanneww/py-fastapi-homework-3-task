from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession


from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    RefreshTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError
from routes.accounts_crud import (
    get_user_by_email,
    create_user,
    user_activation,
    get_activate_token,
    deactivate_and_create_new_password_reset_token,
    get_password_reset_token,
    update_password,
    delete_token_with_exception,
    get_user_by_id
)

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, str(user.email))

    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {db_user.email} already exists.")

    db_user = await create_user(db, user)
    return UserRegistrationResponseSchema.model_validate(db_user)


@router.post("/activate/", status_code=200)
async def activate(activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, activation_data.email)
    token = await get_activate_token(db, activation_data.token)

    if not token or token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    await user_activation(db=db, user=user, token=token)

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=200)
async def password_reset_request(reset_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):

    user = await get_user_by_email(db, reset_data.email)

    if not user or not user.is_active:
        return {"message": "If you are registered, you will receive an email with instructions."}
    else:
        await deactivate_and_create_new_password_reset_token(db=db, user_id=user.id)

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=200)
async def password_reset_complete(reset_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, reset_data.email)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    db_token = await get_password_reset_token(db=db, user_id=user.id)

    if reset_data.token != db_token.token :
        await delete_token_with_exception(db, db_token)

    if db_token.expires_at < datetime.now(timezone.utc):
        await delete_token_with_exception(db, db_token)

    await update_password(db=db, user=user, password=reset_data.password)

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        settings: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = await get_user_by_email(db, login_data.email)

    if user and not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})
    raw_refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})

    refresh_token = RefreshTokenModel.create(
        user_id=user.id,
        token=raw_refresh_token,
        days_valid=settings.LOGIN_TIME_DAYS
    )
    try:
        db.add(refresh_token)
        await db.commit()
        await db.refresh(refresh_token)
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=raw_refresh_token,
        token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def refresh(
        refresh_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
):
    refresh_token = refresh_data.refresh_token
    try:
        jwt_manager.decode_refresh_token(token=refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_token
    )
    result = await db.execute(stmt)
    refresh_token = result.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    token_user_id = refresh_token.user_id
    user = await get_user_by_id(db=db, id=token_user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return TokenRefreshResponseSchema(
        access_token=access_token
    )
