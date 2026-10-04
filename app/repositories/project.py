"""
Репозиторий для Project.
"""
from sqlalchemy import select

from app.models.project import Project
from app.repositories.base import BaseRepository
from app.schemas.project import ProjectCreate, ProjectUpdate


class ProjectRepository(BaseRepository[Project, ProjectCreate, ProjectUpdate]):
    model = Project

    async def get_by_slug(self, slug: str) -> Project | None:
        """Поиск проекта по URL-safe slug."""
        stmt = select(Project).where(Project.slug == slug)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_github_repo(self, repo_full_name: str) -> Project | None:
        """
        Поиск проекта по GitHub-репозиторию.

        repo_full_name — формат "org/repo" из webhook payload'а
        (repository.full_name).
        """
        stmt = select(Project).where(Project.github_repo == repo_full_name)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()