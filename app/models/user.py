"""
Модель User — пользователь системы.

Роли (RBAC):
- admin     — управление юзерами, настройками, полный доступ
- security  — AppSec-инженер: создаёт проекты, запускает сканы, закрывает уязвимости
- developer — чтение + смена статуса уязвимостей по своим проектам
"""
import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class UserRole(str, enum.Enum):
    """
    Роль пользователя.

    Порядок ВАЖЕН: чем выше — тем больше прав. Используется в
    проверках `require_role(UserRole.SECURITY)` — «security и выше».
    """
    DEVELOPER = "developer"
    SECURITY = "security"
    ADMIN = "admin"


class User(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Email — используется как логин",
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="bcrypt-хеш пароля. Plaintext НИКОГДА не хранится.",
    )
    full_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Отображаемое имя",
    )
    role: Mapped[UserRole] = mapped_column(
        SAEnum(
            UserRole,
            name="user_role",
            native_enum=True,
            values_callable=lambda cls: [m.value for m in cls],
        ),
        nullable=False,
        default=UserRole.DEVELOPER,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="False = юзер деактивирован (soft-delete)",
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Время последнего успешного логина",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r} role={self.role.value}>"