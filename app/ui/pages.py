"""UI-страницы: login, список сканов, деталка."""

import uuid

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import DbSessionDep
from app.core.config import settings
from app.core.security import verify_password
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.repositories.scan import ScanRepository
from app.repositories.user import UserRepository
from app.ui.deps import COOKIE_NAME, CurrentUserDep

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

    # Одинаковая ошибка для «нет юзера» и «неверный пароль» — anti-enumeration
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
    # Создаём access-токен тем же кодом, что и в API
    from app.core.security import create_access_token  # локально — избегаем циклов
    token = create_access_token(subject=str(user.id))

    response = RedirectResponse(url="/ui/scans", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,   # нельзя прочитать из JS — защита от XSS
        samesite="lax",  # CSRF-защита для навигации
        secure=not settings.DEBUG,  # True в проде (только HTTPS)
        max_age=15 * 60,  # 15 минут — как access-токен
    )
    return response


@router.get("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE_NAME)
    return response


# ---------- Scans ----------

@router.get("/", response_class=HTMLResponse)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/ui/scans", status_code=status.HTTP_303_SEE_OTHER)


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


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    request: Request,
    session: DbSessionDep,
    user: CurrentUserDep,
    scan_id: uuid.UUID,
) -> HTMLResponse:
    """Деталка скана: метаданные + список уязвимостей."""
    # Скан с подгруженным project (иначе scan.project.slug упадёт в шаблоне)
    scan_stmt = (
        select(Scan)
        .options(selectinload(Scan.project))
        .where(Scan.id == scan_id)
    )
    scan = (await session.execute(scan_stmt)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Уязвимости этого скана, отсортированные по severity (critical → info)
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