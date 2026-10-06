"""
Seed-скрипт: наполняет БД демо-данными для скриншотов и проверки UI.

Запуск (внутри контейнера api):
    docker compose exec api python -m scripts.seed_demo

Идемпотентен: юзеры и проект проверяются по email/slug.
Скан создаётся всегда — так можно наделать скринов с историей.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.security import hash_password
from app.db.session import AsyncSessionLocal
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User, UserRole
from app.models.vulnerability import SeverityLevel, Vulnerability, VulnerabilityStatus


DEMO_USERS = [
    {
        "email": "admin@example.com",
        "password": "SuperSecret123!",
        "full_name": "Admin",
        "role": UserRole.ADMIN,
    },
    {
        "email": "sec@example.com",
        "password": "Security123!",
        "full_name": "Security Engineer",
        "role": UserRole.SECURITY,
    },
    {
        "email": "dev@example.com",
        "password": "Developer123!",
        "full_name": "Developer",
        "role": UserRole.DEVELOPER,
    },
]

# cwe — int; path/line уходят в scanner_metadata
DEMO_FINDINGS = [
    {
        "title": "Use of hardcoded password",
        "description": "Password is hardcoded in source code. Move to env vars or a secret manager.",
        "severity": SeverityLevel.HIGH,
        "cwe": 259,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 12,
    },
    {
        "title": "Use of weak MD5 hash",
        "description": "MD5 is cryptographically broken. Use SHA-256 or bcrypt for passwords.",
        "severity": SeverityLevel.HIGH,
        "cwe": 327,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 24,
    },
    {
        "title": "SQL injection via string formatting",
        "description": "User input is concatenated into SQL query. Use parameterized queries.",
        "severity": SeverityLevel.CRITICAL,
        "cwe": 89,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 38,
    },
    {
        "title": "Use of insecure pickle deserialization",
        "description": "Pickle can execute arbitrary code. Use JSON or a safe serializer.",
        "severity": SeverityLevel.CRITICAL,
        "cwe": 502,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 51,
    },
    {
        "title": "Subprocess call with shell=True",
        "description": "Shell injection risk. Pass args as a list and keep shell=False.",
        "severity": SeverityLevel.HIGH,
        "cwe": 78,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 63,
    },
    {
        "title": "Weak random number generator",
        "description": "random module is not cryptographically secure. Use secrets module.",
        "severity": SeverityLevel.MEDIUM,
        "cwe": 338,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 77,
    },
    {
        "title": "Assert used for security check",
        "description": "Assertions are stripped in optimized mode (-O). Use explicit if + raise.",
        "severity": SeverityLevel.MEDIUM,
        "cwe": 617,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 89,
    },
    {
        "title": "Debug mode enabled",
        "description": "debug=True in production leaks stack traces and enables RCE.",
        "severity": SeverityLevel.MEDIUM,
        "cwe": 489,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 95,
    },
    {
        "title": "Missing request timeout",
        "description": "HTTP requests without timeout can hang the worker indefinitely.",
        "severity": SeverityLevel.LOW,
        "cwe": 1088,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 104,
    },
    {
        "title": "Information exposure in error message",
        "description": "Raw exception message returned to user may leak internal details.",
        "severity": SeverityLevel.LOW,
        "cwe": 209,
        "file_path": "/app/demo/vulnerable_code.py",
        "line_number": 118,
    },
]


async def _upsert_user(session, spec: dict) -> User:
    existing = (
        await session.execute(select(User).where(User.email == spec["email"]))
    ).scalar_one_or_none()
    if existing:
        print(f"  = User exists: {spec['email']} ({spec['role'].value})")
        return existing

    user = User(
        email=spec["email"],
        hashed_password=hash_password(spec["password"]),
        full_name=spec["full_name"],
        role=spec["role"],
        is_active=True,
    )
    session.add(user)
    await session.flush()
    print(f"  + Created user: {spec['email']} / {spec['password']} ({spec['role'].value})")
    return user


async def _upsert_project(session) -> Project:
    existing = (
        await session.execute(select(Project).where(Project.slug == "backend-api"))
    ).scalar_one_or_none()
    if existing:
        print("  = Project exists: backend-api")
        return existing

    project = Project(
        name="Backend API",
        slug="backend-api",
        description="Demo project — Python backend with intentional vulnerabilities.",
        github_repo="test/repo",
        default_target="/app/demo/vulnerable_code.py",
    )
    session.add(project)
    await session.flush()
    print("  + Created project: backend-api")
    return project


async def _create_demo_scan(session, project: Project) -> Scan:
    now = datetime.now(UTC)
    scan = Scan(
        project_id=project.id,
        scanner="bandit",
        target="/app/demo/vulnerable_code.py",
        status=ScanStatus.SUCCESS,
        findings_count=len(DEMO_FINDINGS),
        started_at=now - timedelta(seconds=5),
        finished_at=now,
        celery_task_id=str(uuid.uuid4()),
    )
    session.add(scan)
    await session.flush()

    for f in DEMO_FINDINGS:
        session.add(
            Vulnerability(
                project_id=project.id,
                scan_id=scan.id,
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                cwe=f["cwe"],
                scanner="bandit",
                status=VulnerabilityStatus.OPEN,
                scanner_metadata={
                    "file_path": f["file_path"],
                    "line_number": f["line_number"],
                },
            )
        )
    print(f"  + Created scan {scan.id} with {len(DEMO_FINDINGS)} vulnerabilities")
    return scan


async def main() -> None:
    print("Seeding SecureFlow demo data...\n")
    async with AsyncSessionLocal() as session:
        for spec in DEMO_USERS:
            await _upsert_user(session, spec)

        project = await _upsert_project(session)
        await _create_demo_scan(session, project)

        await session.commit()

    print("\nDone.")
    print("\nUI: http://127.0.0.1:8000/ui/login")
    print("   admin@example.com / SuperSecret123!")
    print("   sec@example.com   / Security123!")
    print("   dev@example.com   / Developer123!")


if __name__ == "__main__":
    asyncio.run(main())