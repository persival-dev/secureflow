"""
Репозиторий для User.

Расширяет BaseRepository поиском по email (уникальное поле).
"""
from sqlalchemy import select

from app.models.user import User
from app.repositories.base import BaseRepository
from app.schemas.auth import UserCreate


class UserRepository(BaseRepository[User, UserCreate, UserCreate]):
    model = User

    async def get_by_email(self, email: str) -> User | None:
        """
        Найти юзера по email.

        Email приводим к lower для регистронезависимого поиска.
        Индекс ix_users_email — UNIQUE, запрос быстрый.

        SQL параметризован (никаких f-string) — защита от SQL injection
        через поле email.
        """
        stmt = select(User).where(User.email == email.lower())
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create_from_schema(self, data: UserCreate, hashed_password: str) -> User:
        """
        Создаёт юзера.

        Отдельный метод, потому что BaseRepository.create() ожидает
        Pydantic-схему с полем hashed_password, а у нас в UserCreate
        хранится plaintext-пароль, который нельзя писать в БД.

         Хеширование делает СЕРВИС, не репозиторий. Репозиторий
        только сохраняет уже готовый хеш.
        """
        user = User(
            email=data.email.lower(),  # нормализуем — 'Foo@x.com' и 'foo@x.com' это один юзер
            hashed_password=hashed_password,
            full_name=data.full_name,
        )
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user