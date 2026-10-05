"""Сборный router для UI (server-rendered HTML)."""

from fastapi import APIRouter

from app.ui import pages

ui_router = APIRouter(prefix="/ui", tags=["ui"])

ui_router.include_router(pages.router)