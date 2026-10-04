"""
Сервис управления пользователями.

Все методы предполагают, что RBAC уже проверил права вызывающего.
Здесь — только бизнес-логика: кого можно менять, кого нет.
"""
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.auth import UserUpdate


class CannotModifySelfError(Exception):
    """
    Админ пытается изменить самого себя.

    Почему запрещаем:
    - Понизить себя с ADMIN — потерять доступ навсегда.
    - Деактивировать себя — залочиться из системы.
    - Менять роль — можно случайно даунгрейднуть и потерять права.

    Правильнее — сделать второго админа, потом менять себя.
    """


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.repo = UserRepository(session)

    async def list_users(self, *, limit: int = 50, offset: int = 0) -> tuple[list[User], int]:
        """Список всех юзеров с пагинацией."""
        users = await self.repo.get_many(limit=limit, offset=offset)
        total = await self.repo.count()
        return users, total

    async def get_user(self, user_id: uuid.UUID) -> User | None:
        return await self.repo.get(user_id)

    async def update_user(
        self,
        target_id: uuid.UUID,
        data: UserUpdate,
        *,
        actor_id: uuid.UUID,
    ) -> User | None:
        """
        Обновляет юзера. `actor_id` — кто делает изменение.

        Проверяем: actor не может менять себя (защита от self-lockout).
        """
        if target_id == actor_id:
            raise CannotModifySelfError("Admins cannot modify their own account via this endpoint")

        target = await self.repo.get(target_id)
        if target is None:
            return None

        update_data = data.model_dump(exclude_unset=True)

        allowed_fields = {"full_name", "role", "is_active"}
        for field, value in update_data.items():
            if field in allowed_fields:
                setattr(target, field, value)

        self.session.add(target)
        await self.session.commit()
        await self.session.refresh(target)
        return target

    async def deactivate(self, target_id: uuid.UUID, *, actor_id: uuid.UUID) -> bool:
        """
        Soft-delete: ставит is_active=False.

        Юзер остаётся в БД для аудита, но не может логиниться
        и его токены перестают проходить get_current_user.
        """
        if target_id == actor_id:
            raise CannotModifySelfError("Admins cannot deactivate their own account")

        target = await self.repo.get(target_id)
        if target is None:
            return False

        target.is_active = False
        self.session.add(target)
        await self.session.commit()
        return True