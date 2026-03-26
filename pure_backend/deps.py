from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from pure_backend.core.errors import AppError
from pure_backend.db.models import EntitySnapshot, OrgMembership, PermissionPolicy, Role, SessionToken, User
from pure_backend.services.authz import authorize_action as authz_authorize_action
from pure_backend.services.authz import get_current_user as authz_get_current_user
from pure_backend.services.authz import membership_role as authz_membership_role
from pure_backend.services.authz import require_membership as authz_require_membership

ROLE_ADMIN = "administrator"
ROLE_REVIEWER = "reviewer"
ROLE_GENERAL = "general"
ROLE_AUDITOR = "auditor"

ALLOWED_FILE_TYPES = {"text/csv", "application/json"}
MAX_FILE_SIZE = 20 * 1024 * 1024
EXPORT_FIELD_WHITELIST = {"username", "id_number", "contact", "organization_name", "credit_balance"}


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def snapshot_entity(db: Session, entity_name: str, entity_id: str, version_id: int, data: dict) -> None:
    db.add(EntitySnapshot(entity_name=entity_name, entity_id=entity_id, version_id=version_id, data_json=data))


def normalize_org_code(name: str) -> str:
    base = "".join(ch for ch in name.upper() if ch.isalnum())
    if not base:
        base = "ORG"
    return base[:12]


def desensitize(field_name: str, value: str) -> str:
    if not value:
        return ""
    if field_name == "id_number":
        return f"***{value[-4:]}"
    if field_name == "contact":
        return f"***{value[-4:]}"
    return value


def desensitize_by_role(role_name: str, field_name: str, value: str) -> str:
    if role_name in {ROLE_ADMIN, ROLE_AUDITOR, "admin"}:
        return value
    return desensitize(field_name, value)


def get_current_user_or_401(db: Session, authorization: str | None) -> User:
    user, err = authz_get_current_user(db, authorization)
    if err:
        raise AppError(401, err)
    return user


def require_membership_or_403(db: Session, user_id: str, organization_id: str) -> OrgMembership:
    membership = authz_require_membership(db, user_id, organization_id)
    if not membership:
        raise AppError(403, "Forbidden by organization isolation")
    return membership


def membership_role_or_403(db: Session, membership: OrgMembership) -> str:
    role = authz_membership_role(db, membership)
    if not role:
        raise AppError(403, "Role not found")
    return role.name


def authorize_action_or_403(db: Session, role_name: str, resource: str, action: str) -> None:
    if not authz_authorize_action(db, role_name, resource, action):
        raise AppError(403, "Insufficient role")


def require_role_or_403(role_name: str, allowed: set[str]) -> None:
    if role_name not in allowed:
        raise AppError(403, "Insufficient role")


def require_admin_or_approver_or_403(db: Session, membership: OrgMembership) -> None:
    role = db.get(Role, membership.role_id)
    if not role:
        raise AppError(403, "Insufficient role")
    authorize_action_or_403(db, role.name, "WORKFLOW", "DECIDE")


def authorize_action_exists(db: Session, role_name: str, resource: str, action: str) -> bool:
    row = db.scalar(
        select(PermissionPolicy).where(
            PermissionPolicy.role_name == role_name,
            PermissionPolicy.resource == resource,
            PermissionPolicy.action == action,
        )
    )
    return bool(row)
