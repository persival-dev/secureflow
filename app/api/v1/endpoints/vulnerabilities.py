"""
CRUD-эндпоинты для уязвимостей.
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.models.vulnerability import SeverityLevel, VulnerabilityStatus
from app.schemas.common import Page
from app.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityRead,
    VulnerabilityUpdate,
)
from app.services.vulnerability import VulnerabilityService
from app.api.deps import CurrentUserDep, DbSessionDep, require_role
from app.models.user import User, UserRole
router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
SecurityDep = Annotated[User, Depends(require_role(UserRole.SECURITY, UserRole.ADMIN))]


def get_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> VulnerabilityService:
    """DI-провайдер сервиса. Вынесено в отдельную функцию, чтобы переиспользовать."""
    return VulnerabilityService(session)


ServiceDep = Annotated[VulnerabilityService, Depends(get_service)]


@router.post(
    "",
    response_model=VulnerabilityRead,
    status_code=status.HTTP_201_CREATED,
    summary="Создать уязвимость",
)
async def create_vulnerability(
    payload: VulnerabilityCreate,
    service: ServiceDep,
    _: Annotated[User, Depends(require_role(UserRole.SECURITY, UserRole.ADMIN))],
) -> VulnerabilityRead:
    try:
        vuln = await service.create(payload)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return VulnerabilityRead.model_validate(vuln)


@router.get(
    "",
    response_model=Page[VulnerabilityRead],
    summary="Список уязвимостей с пагинацией и фильтрами",
)
async def list_vulnerabilities(
    service: ServiceDep,
    current_user: CurrentUserDep,
    project_id: uuid.UUID | None = Query(default=None),
    severity: SeverityLevel | None = Query(default=None),
    status_: VulnerabilityStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[VulnerabilityRead]:
    items, total = await service.list(
        project_id=project_id,
        severity=severity,
        status=status_,
        limit=limit,
        offset=offset,
    )
    return Page[VulnerabilityRead](
        items=[VulnerabilityRead.model_validate(i) for i in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{vuln_id}",
    response_model=VulnerabilityRead,
    summary="Получить уязвимость по ID",
)
async def get_vulnerability(
    vuln_id: uuid.UUID,
    service: ServiceDep,
    current_user: CurrentUserDep,
) -> VulnerabilityRead:
    vuln = await service.get(vuln_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return VulnerabilityRead.model_validate(vuln)


@router.patch(
    "/{vuln_id}",
    response_model=VulnerabilityRead,
    summary="Частично обновить уязвимость",
)
async def update_vulnerability(
    vuln_id: uuid.UUID,
    payload: VulnerabilityUpdate,
    service: ServiceDep,
    current_user: CurrentUserDep,
) -> VulnerabilityRead:
    vuln = await service.update(vuln_id, payload)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return VulnerabilityRead.model_validate(vuln)


@router.delete(
    "/{vuln_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Удалить уязвимость",
)
async def delete_vulnerability(
    vuln_id: uuid.UUID,
    service: ServiceDep,
    _: Annotated[User, Depends(require_role(UserRole.SECURITY, UserRole.ADMIN))],
) -> None:
    deleted = await service.delete(vuln_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Vulnerability not found")