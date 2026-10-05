"""UI-страницы: login, список сканов, деталка."""

import logging
import uuid

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import DbSessionDep
from app.core.config import settings
from app.core.security import create_access_token, verify_password
from app.models.project import Project
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.repositories.scan import ScanRepository
from app.repositories.user import UserRepository
from app.schemas.scan import ScanCreate
from app.services.scan import ScanService
from app.ui.deps import COOKIE_NAME, CurrentUserDep

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ---------- Login ----------

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None},
    )


@router.post("/login", response_model=None)
async def login_submit(
    request: Request,
    session: DbSessionDep,
    email: str = Form(...),
    password: str = Form(...),
):
    user_repo = UserRepository(session)
    user = await user_repo.get_by_email(email)

    # Одинаковая ошибка для «нет юзера», «неверный пароль» и «inactive» —
    # anti-enumeration: нельзя узнать, существует ли email
    if (
        user is None
        or not user.is_active
        or not verify_password(password, user.hashed_password)
    ):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Неверный email или пароль"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    token = create_access_token(subject=str(user.id))

    response = RedirectResponse(url="/ui/scans", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,          # нельзя прочитать из JS — защита от XSS
        samesite="lax",         # CSRF-защита для навигации
        secure=not settings.DEBUG,  # True в проде (только HTTPS)
        max_age=15 * 60,        # 15 минут — как access-токен
    )
    return response


@router.get("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE_NAME)
    return response


# ---------- Root ----------

@router.get("/", response_class=HTMLResponse)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/ui/scans", status_code=status.HTTP_303_SEE_OTHER)


# ---------- Scans: list ----------

@router.get("/scans", response_class=HTMLResponse)
async def scans_list(
    request: Request,
    session: DbSessionDep,
    user: CurrentUserDep,
) -> HTMLResponse:
    scan_repo = ScanRepository(session)
    scans = await scan_repo.get_many_with_project(limit=50)

    return templates.TemplateResponse(
        request=request,
        name="scans/list.html",
        context={"user": user, "scans": scans},
    )


# ---------- Scans: create (СТАВИМ ВЫШЕ /scans/{scan_id}!) ----------

@router.get("/scans/create", response_class=HTMLResponse)
async def scan_new_page(
    request: Request,
    session: DbSessionDep,
    user: CurrentUserDep,
) -> HTMLResponse:
    """Форма создания нового скана."""
    projects = list(
        (await session.execute(select(Project).order_by(Project.slug)))
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request=request,
        name="scans/new.html",
        context={
            "user": user,
            "projects": projects,
            "scanners": ["bandit", "semgrep"],
            "default_target": "/app/demo/vulnerable_code.py",
            "error": None,
        },
    )


@router.post("/scans/create", response_model=None)
async def scan_new_submit(
    request: Request,
    session: DbSessionDep,
    user: CurrentUserDep,
    project_id: str = Form(...),
    scanner: str = Form(...),
    target: str = Form(...),
):
    """Создаёт скан и редиректит на его деталку."""
    try:
        scan_uuid = uuid.UUID(project_id)
    except ValueError:
        projects = list(
            (await session.execute(select(Project).order_by(Project.slug)))
            .scalars()
            .all()
        )
        return templates.TemplateResponse(
            request=request,
            name="scans/new.html",
            context={
                "user": user,
                "projects": projects,
                "scanners": ["bandit", "semgrep"],
                "default_target": target,
                "error": "Некорректный ID проекта",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    scan_service = ScanService(session)
    try:
        scan = await scan_service.create_and_dispatch(
            ScanCreate(
                project_id=scan_uuid,
                scanner=scanner,  # type: ignore[arg-type]
                target=target,
            )
        )
    except Exception as exc:
        logger.exception("Failed to create scan from UI: %s", exc)
        projects = list(
            (await session.execute(select(Project).order_by(Project.slug)))
            .scalars()
            .all()
        )
        return templates.TemplateResponse(
            request=request,
            name="scans/new.html",
            context={
                "user": user,
                "projects": projects,
                "scanners": ["bandit", "semgrep"],
                "default_target": target,
                "error": f"Не удалось создать скан: {exc}",
            },
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return RedirectResponse(
        url=f"/ui/scans/{scan.id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------- Scans: detail (В САМОМ КОНЦЕ — иначе съест /scans/create!) ----------

@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    request: Request,
    session: DbSessionDep,
    user: CurrentUserDep,
    scan_id: uuid.UUID,
) -> HTMLResponse:
    """Деталка скана: метаданные + список уязвимостей."""
    scan_stmt = (
        select(Scan)
        .options(selectinload(Scan.project))
        .where(Scan.id == scan_id)
    )
    scan = (await session.execute(scan_stmt)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    vuln_stmt = (
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity.desc())
    )
    vulnerabilities = list((await session.execute(vuln_stmt)).scalars().all())

    return templates.TemplateResponse(
        request=request,
        name="scans/detail.html",
        context={
            "user": user,
            "scan": scan,
            "vulnerabilities": vulnerabilities,
        },
    )