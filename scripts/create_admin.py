"""
CLI-скрипт для создания первого администратора.

Запуск:
    docker compose exec api python -m scripts.create_admin admin@example.com 'StrongPass123!' 'Админ'

Идемпотентен: если юзер с таким email уже есть — обновит роль до ADMIN
и сообщит об этом. Это удобно при развёртывании.
"""
import asyncio
import sys

from app.core.security import hash_password
from app.db.session import AsyncSessionLocal
from app.models.user import User, UserRole
from app.repositories.user import UserRepository


async def create_or_promote_admin(
    email: str,
    password: str,
    full_name: str | None = None,
) -> None:
    """Создаёт админа или повышает существующего юзера до ADMIN."""
    async with AsyncSessionLocal() as session:
        repo = UserRepository(session)
        existing = await repo.get_by_email(email)

        if existing is not None:
            # Юзер уже есть — повышаем до ADMIN
            existing.role = UserRole.ADMIN
            existing.is_active = True
            session.add(existing)
            await session.commit()
            print(f" User {email} promoted to ADMIN (id={existing.id})")
            return

        # Создаём нового
        user = User(
            email=email.lower(),
            hashed_password=hash_password(password),
            full_name=full_name,
            role=UserRole.ADMIN,
            is_active=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        print(f" Admin created: {email} (id={user.id})")


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.create_admin <email> <password> [full_name]")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]
    full_name = sys.argv[3] if len(sys.argv) > 3 else None

    if len(password) < 8:
        print(" Password must be at least 8 characters")
        sys.exit(1)

    asyncio.run(create_or_promote_admin(email, password, full_name))


if __name__ == "__main__":
    main()