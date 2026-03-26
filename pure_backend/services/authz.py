from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from pure_backend.db.models import OrgMembership, PermissionPolicy, Role, SessionToken, User


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_current_user(db: Session, authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        return None, "Missing bearer token"
    token = authorization.replace("Bearer ", "", 1).strip()
    session_token = db.get(SessionToken, token)
    if not session_token or session_token.expires_at < now_utc():
        return None, "Invalid or expired token"
    user = db.get(User, session_token.user_id)
    if not user:
        return None, "User not found"
    return user, None


def require_membership(db: Session, user_id: str, organization_id: str):
    stmt = select(OrgMembership).where(
        OrgMembership.user_id == user_id,
        OrgMembership.organization_id == organization_id,
    )
    return db.scalar(stmt)


def membership_role(db: Session, membership: OrgMembership):
    return db.get(Role, membership.role_id)


def authorize_action(db: Session, role_name: str, resource: str, action: str) -> bool:
    allowed = db.scalar(
        select(PermissionPolicy).where(
            PermissionPolicy.role_name == role_name,
            PermissionPolicy.resource == resource,
            PermissionPolicy.action == action,
        )
    )
    return bool(allowed)
