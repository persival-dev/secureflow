"""
Сборный роутер API v1.
"""
from fastapi import APIRouter

from app.api.v1.endpoints import auth, health, scans, users, vulnerabilities

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(scans.router)
api_router.include_router(vulnerabilities.router)