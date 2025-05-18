from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from starlette import status

from database import UserModel, UserGroupEnum, UserGroupModel
from database.models.accounts import ActivationTokenModel, PasswordResetTokenModel
from schemas.accounts import UserRegistrationRequestSchema


async def get_or_create_group(
        db: AsyncSession,
        name: UserGroupEnum = UserGroupEnum.USER
):
    stmt = select(UserGroupModel).where(
        UserGroupModel.name == name
    )
    result = await db.execute(stmt)
    group = result.scalar_one_or_none()

    if not group:
        group = UserGroupModel(name=name)
        db.add(group)
        await db.commit()
        await db.refresh(group)

    return group


async def validate_password(user: UserModel, password: str):
    try:
        user.password = password
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )


async def update_password(db: AsyncSession, user: UserModel, password: str):
    await validate_password(user=user, password=password)

    try:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return user


async def create_user(db: AsyncSession, user_data: UserRegistrationRequestSchema):
    group = await get_or_create_group(db, UserGroupEnum.USER)
    db_user = UserModel(
        email=str(user_data.email),
        group_id=group.id)

    await validate_password(user=db_user, password=user_data.password)

    try:
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        token = ActivationTokenModel(user_id=db_user.id)
        db.add(token)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return db_user


async def delete_token(db: AsyncSession, token: ActivationTokenModel | PasswordResetTokenModel):
    await db.delete(token)
    await db.commit()


async def delete_token_with_exception(db: AsyncSession, token: ActivationTokenModel | PasswordResetTokenModel):
    await delete_token(db, token)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token."
    )


async def user_activation(
        db: AsyncSession,
        token: ActivationTokenModel,
        user: UserModel
):
    user.is_active = True
    db.add(user)
    await db.commit()
    await db.delete(token)
    await db.commit()

    return user


async def get_activate_token(db: AsyncSession, token: str):
    result = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.token == token))
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, id: int):
    result = await db.execute(select(UserModel).where(UserModel.id == id))
    return result.scalar_one_or_none()


async def get_password_reset_token(db: AsyncSession, user_id: int):
    result = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user_id))
    return result.scalar_one_or_none()


async def deactivate_and_create_new_password_reset_token(db: AsyncSession, user_id: int):
    db_token = await get_password_reset_token(db, user_id)
    if db_token:
        await delete_token(db, db_token)

    new_token = PasswordResetTokenModel(user_id=user_id)
    db.add(new_token)
    await db.commit()
    await db.refresh(new_token)
    return new_token
