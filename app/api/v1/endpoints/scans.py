"""
Эндпоинты для запуска и просмотра сканирований.

POST   /scans       — запустить новый скан (SECURITY+)
GET    /scans       — список с фильтрами (любая роль)
GET    /scans/{id}  — детали скана (любая роль)
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import CurrentUserDep, DbSessionDep, require_role
from app.models.scan import ScanStatus
from app.models.user import User, UserRole
from app.schemas.common import Page
from app.schemas.scan import ScanCreate, ScanRead
from app.services.scan import ProjectNotFoundError, ScanService
from fastapi.responses import HTMLResponse, Response

from app.services.report import ReportService

router = APIRouter(prefix="/scans", tags=["scans"])


def get_scan_service(session: DbSessionDep) -> ScanService:
    return ScanService(session)


ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]


SecurityDep = Annotated[User, Depends(require_role(UserRole.SECURITY, UserRole.ADMIN))]


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Запустить скан (SECURITY+)",
)
async def create_scan(
    payload: ScanCreate,
    service: ScanServiceDep,
    _: SecurityDep,
) -> ScanRead:
    """
    Создаёт Scan и ставит Celery-задачу в очередь.

    Возвращает 202 Accepted, потому что сканирование асинхронное —
    результат появится позже. Опрашивай GET /scans/{id} до
    status in ('success', 'failed', 'cancelled').
    """
    try:
        scan = await service.create_and_dispatch(payload)
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        # Celery недоступен — Scan сохранён как FAILED
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Scanner queue unavailable: {e}",
        ) from e

    return ScanRead.model_validate(scan)


@router.get(
    "",
    response_model=Page[ScanRead],
    summary="Список сканов с фильтрами",
)
async def list_scans(
    service: ScanServiceDep,
    current_user: CurrentUserDep,
    project_id: uuid.UUID | None = Query(default=None),
    scanner: str | None = Query(default=None),
    status_: ScanStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[ScanRead]:
    items, total = await service.list(
        project_id=project_id,
        scanner=scanner,
        status=status_,
        limit=limit,
        offset=offset,
    )
    return Page[ScanRead](
        items=[ScanRead.model_validate(s) for s in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    summary="Детали скана по ID",
)
async def get_scan(
    scan_id: uuid.UUID,
    service: ScanServiceDep,
    current_user: CurrentUserDep,
) -> ScanRead:
    scan = await service.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRead.model_validate(scan)

@router.get(
    "/{scan_id}/report",
    response_class=HTMLResponse,
    summary="HTML-отчёт по скану",
)
async def get_scan_report(
    scan_id: uuid.UUID,
    session: DbSessionDep,
    current_user: CurrentUserDep,
) -> HTMLResponse:
    """
    Возвращает готовый HTML-отчёт по скану.

    Открывается прямо в браузере. Никаких внешних CDN —
    работает офлайн и в корпоративных сетях.

    Content-Type: text/html. Сохрани через Ctrl+S если нужен PDF.
    """
    service = ReportService(session)
    html = await service.render_scan_report(scan_id)
    if html is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return HTMLResponse(content=html)

@router.get(
    "/{scan_id}/report.pdf",
    response_class=Response,
    summary="PDF-отчёт по скану",
)
async def get_scan_report_pdf(
    scan_id: uuid.UUID,
    session: DbSessionDep,
    current_user: CurrentUserDep,
) -> Response:
    service = ReportService(session)
    try:
        pdf_bytes = await service.render_scan_report_pdf(scan_id)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        ) from e

    if pdf_bytes is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan_id}.pdf"',
        },
    )