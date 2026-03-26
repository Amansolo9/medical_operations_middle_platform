from datetime import timedelta

from fastapi import APIRouter, Depends, Header
from sqlalchemy import select
from sqlalchemy.orm import Session

from pure_backend.core.config import get_settings
from pure_backend.core.errors import AppError
from pure_backend.core.security import encrypt_value, hash_password, password_is_valid, random_token, verify_password
from pure_backend.db.models import LoginAttempt, OrgMembership, Organization, PasswordRecoveryToken, Role, SessionToken, User
from pure_backend.db.session import get_db
from pure_backend.deps import (
    ROLE_ADMIN,
    ROLE_GENERAL,
    get_current_user_or_401,
    normalize_org_code,
    now_utc,
    snapshot_entity,
)
from pure_backend.schemas import (
    LoginReq,
    LogoutReq,
    OrganizationCreateReq,
    OrganizationJoinReq,
    PasswordRecoveryRequestReq,
    PasswordRecoveryResetReq,
    UserRegisterReq,
)
from pure_backend.services.audit import log_audit

router = APIRouter()
settings = get_settings()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "medical-ops-middle-platform"}


@router.get("/")
def root() -> dict:
    return {"status": "ok", "service": "medical-ops-middle-platform", "docs": "/docs", "health": "/health"}


@router.post("/auth/register")
def register(payload: UserRegisterReq, db: Session = Depends(get_db)):
    if not password_is_valid(payload.password):
        raise AppError(400, "Password must be at least 8 characters and include letters and numbers")
    if db.scalar(select(User).where(User.username == payload.username)):
        raise AppError(400, "Username already exists")

    org = db.scalar(select(Organization).where(Organization.name == payload.organization_name))
    if not org:
        org_code = payload.organization_code or normalize_org_code(payload.organization_name)
        if db.scalar(select(Organization).where(Organization.code == org_code)):
            org_code = f"{org_code}{random_token()[:4].upper()}"
        org = Organization(name=payload.organization_name, code=org_code, credit_balance=0.0)
        db.add(org)
        db.flush()
        snapshot_entity(db, "Organization", org.id, org.version_id, {"name": org.name, "credit_balance": str(org.credit_balance)})
    else:
        if payload.organization_code != org.code:
            raise AppError(403, "Registration into existing organization requires valid organization code")
        if payload.role != ROLE_GENERAL:
            raise AppError(403, "Privileged roles for existing organizations require controlled onboarding")

    role = db.scalar(select(Role).where(Role.name == payload.role))
    if not role:
        raise AppError(400, "Invalid role")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        encrypted_id_number=encrypt_value(payload.id_number, settings.app_secret),
        encrypted_contact=encrypt_value(payload.contact, settings.app_secret) if payload.contact else "",
    )
    db.add(user)
    db.flush()
    db.add(OrgMembership(user_id=user.id, organization_id=org.id, role_id=role.id))
    log_audit(db, "USER_REGISTER", "User", user.id, f"User {user.username} registered", actor_user_id=user.id, organization_id=org.id)
    db.commit()
    return {"user_id": user.id, "organization_id": org.id}


@router.post("/auth/logout")
def logout(payload: LogoutReq, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    token = db.get(SessionToken, payload.token)
    if not token:
        raise AppError(404, "Session token not found")
    if token.user_id != user.id:
        raise AppError(403, "Cannot logout another user's session")
    db.delete(token)
    db.commit()
    return {"logged_out": True}


@router.post("/auth/password-recovery/request")
def request_password_recovery(payload: PasswordRecoveryRequestReq, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == payload.username))
    if not user:
        raise AppError(404, "User not found")
    token = random_token()
    db.add(PasswordRecoveryToken(username=payload.username, token=token, expires_at=now_utc() + timedelta(minutes=30), used=False))
    log_audit(db, "PASSWORD_RECOVERY_REQUEST", "User", user.id, "Password recovery requested", actor_user_id=user.id)
    db.commit()
    return {"message": "Recovery request accepted", "expires_in_minutes": 30, "recovery_token": token if settings.environment == "test" else None}


@router.post("/auth/password-recovery/reset")
def reset_password(payload: PasswordRecoveryResetReq, db: Session = Depends(get_db)):
    if not password_is_valid(payload.new_password):
        raise AppError(400, "Password must be at least 8 characters and include letters and numbers")
    token_record = db.scalar(
        select(PasswordRecoveryToken).where(
            PasswordRecoveryToken.username == payload.username,
            PasswordRecoveryToken.token == payload.token,
            PasswordRecoveryToken.used.is_(False),
        )
    )
    if not token_record or token_record.expires_at < now_utc():
        raise AppError(400, "Invalid or expired recovery token")
    user = db.scalar(select(User).where(User.username == payload.username))
    if not user:
        raise AppError(404, "User not found")
    user.password_hash = hash_password(payload.new_password)
    token_record.used = True
    log_audit(db, "PASSWORD_RESET", "User", user.id, "Password reset completed", actor_user_id=user.id)
    db.commit()
    return {"password_reset": True}


@router.post("/auth/login")
def login(payload: LoginReq, db: Session = Depends(get_db)):
    now = now_utc()
    failure_window_start = now - timedelta(minutes=10)
    lock_window_start = now - timedelta(minutes=30)

    recent_attempts = db.scalars(
        select(LoginAttempt)
        .where(LoginAttempt.username == payload.username, LoginAttempt.attempted_at >= failure_window_start)
        .order_by(LoginAttempt.attempted_at.desc())
    ).all()
    consecutive_failures = 0
    for attempt in recent_attempts:
        if attempt.success:
            break
        consecutive_failures += 1

    if consecutive_failures >= 5:
        latest_fail = db.scalar(
            select(LoginAttempt)
            .where(LoginAttempt.username == payload.username, LoginAttempt.success.is_(False), LoginAttempt.attempted_at >= lock_window_start)
            .order_by(LoginAttempt.attempted_at.desc())
        )
        if latest_fail and latest_fail.attempted_at >= now - timedelta(minutes=30):
            raise AppError(403, "Account temporarily locked due to risk control")

    user = db.scalar(select(User).where(User.username == payload.username))
    if not user or not verify_password(payload.password, user.password_hash):
        db.add(LoginAttempt(username=payload.username, success=False))
        log_audit(db, "LOGIN_FAILED", "User", payload.username, "Failed login attempt")
        db.commit()
        raise AppError(401, "Invalid username or password")

    db.add(LoginAttempt(username=payload.username, success=True))
    token = random_token()
    db.add(SessionToken(token=token, user_id=user.id, expires_at=now + timedelta(hours=settings.access_token_hours)))
    log_audit(db, "LOGIN_SUCCESS", "User", user.id, "Successful login", actor_user_id=user.id)
    db.commit()
    return {"access_token": token, "token_type": "bearer"}


@router.post("/organizations/create")
def create_organization(payload: OrganizationCreateReq, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    if db.scalar(select(Organization).where(Organization.code == payload.code)):
        raise AppError(409, "Organization code already exists")
    if db.scalar(select(Organization).where(Organization.name == payload.name)):
        raise AppError(409, "Organization name already exists")
    org = Organization(name=payload.name, code=payload.code, credit_balance=0.0)
    db.add(org)
    db.flush()
    admin_role = db.scalar(select(Role).where(Role.name == ROLE_ADMIN))
    db.add(OrgMembership(user_id=user.id, organization_id=org.id, role_id=admin_role.id))
    snapshot_entity(db, "Organization", org.id, org.version_id, {"name": org.name, "credit_balance": str(org.credit_balance)})
    log_audit(db, "ORG_CREATED", "Organization", org.id, f"Organization {org.name} created", actor_user_id=user.id, organization_id=org.id)
    db.commit()
    return {"organization_id": org.id, "code": org.code, "name": org.name}


@router.post("/organizations/join")
def join_organization(payload: OrganizationJoinReq, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    role = db.scalar(select(Role).where(Role.name == payload.role))
    if not role:
        raise AppError(400, "Invalid role")
    if payload.role != ROLE_GENERAL:
        raise AppError(403, "Self-join only allows general role")
    org = db.scalar(select(Organization).where(Organization.code == payload.organization_code))
    if not org:
        raise AppError(404, "Organization not found")
    existing = db.scalar(select(OrgMembership).where(OrgMembership.user_id == user.id, OrgMembership.organization_id == org.id))
    if existing:
        raise AppError(409, "User already joined organization")
    db.add(OrgMembership(user_id=user.id, organization_id=org.id, role_id=role.id))
    log_audit(db, "ORG_JOIN", "Organization", org.id, f"User joined with role {payload.role}", actor_user_id=user.id, organization_id=org.id)
    db.commit()
    return {"organization_id": org.id, "joined": True, "role": payload.role}
