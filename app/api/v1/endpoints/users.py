"""
Админские эндпоинты управления пользователями.

Все требуют роль ADMIN.
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import DbSessionDep, require_role
from app.models.user import User, UserRole
from app.schemas.auth import UserRead, UserUpdate
from app.schemas.common import Page
from app.services.user import CannotModifySelfError, UserService

router = APIRouter(prefix="/users", tags=["users"])


def get_user_service(session: DbSessionDep) -> UserService:
    return UserService(session)


UserServiceDep = Annotated[UserService, Depends(get_user_service)]

AdminDep = Annotated[User, Depends(require_role(UserRole.ADMIN))]


@router.get(
    "",
    response_model=Page[UserRead],
    summary="Список всех пользователей (только ADMIN)",
)
async def list_users(
    _: AdminDep,
    service: UserServiceDep,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[UserRead]:
    users, total = await service.list_users(limit=limit, offset=offset)
    return Page[UserRead](
        items=[UserRead.model_validate(u) for u in users],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{user_id}",
    response_model=UserRead,
    summary="Получить юзера по ID (только ADMIN)",
)
async def get_user(
    user_id: uuid.UUID,
    _: AdminDep,
    service: UserServiceDep,
) -> UserRead:
    user = await service.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserRead.model_validate(user)


@router.patch(
    "/{user_id}",
    response_model=UserRead,
    summary="Обновить юзера: роль, имя, активность (только ADMIN)",
)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    admin: AdminDep,
    service: UserServiceDep,
) -> UserRead:
    try:
        user = await service.update_user(user_id, payload, actor_id=admin.id)
    except CannotModifySelfError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserRead.model_validate(user)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Деактивировать юзера (только ADMIN)",
)
async def deactivate_user(
    user_id: uuid.UUID,
    admin: AdminDep,
    service: UserServiceDep,
) -> None:
    try:
        deleted = await service.deactivate(user_id, actor_id=admin.id)
    except CannotModifySelfError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")