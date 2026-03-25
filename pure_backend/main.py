import hashlib
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

from fastapi import Depends, FastAPI, File, Header, Query, Request, UploadFile
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pure_backend.core.config import get_settings
from pure_backend.core.errors import AppError
from pure_backend.core.security import decrypt_value, encrypt_value, hash_password, password_is_valid, random_token, verify_password
from pure_backend.db.base import Base
from pure_backend.db.models import (
    BackupArchiveTask,
    CreditLedger,
    DataDictionary,
    DataLineage,
    EntitySnapshot,
    ExportTask,
    AuditLog,
    IdempotencyKey,
    ImportBatch,
    ImportBatchDetail,
    LoginAttempt,
    MetricRecord,
    OrgMembership,
    Organization,
    PasswordRecoveryToken,
    PermissionPolicy,
    Role,
    SchedulerTask,
    SessionToken,
    StoredFile,
    TaskAssignment,
    User,
    WorkflowAllocation,
    WorkflowApproval,
    WorkflowDefinition,
    WorkflowInstance,
)
from pure_backend.db.session import engine, get_db
from pure_backend.services.audit import log_audit
from pure_backend.services.metrics_logic import validate_metric_item
from pure_backend.services.workflow_logic import can_transition

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

settings = get_settings()
ALLOWED_FILE_TYPES = {"text/csv", "application/json"}
MAX_FILE_SIZE = 20 * 1024 * 1024
EXPORT_FIELD_WHITELIST = {"username", "id_number", "contact", "organization_name", "credit_balance"}
ROLE_ADMIN = "administrator"
ROLE_REVIEWER = "reviewer"
ROLE_GENERAL = "general"
ROLE_AUDITOR = "auditor"


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _column_exists(db: Session, table_name: str, column_name: str) -> bool:
    inspector = inspect(db.bind)
    try:
        columns = inspector.get_columns(table_name)
    except Exception:
        return False
    return any(col["name"] == column_name for col in columns)


def _existing_columns(db: Session, table_name: str) -> set[str]:
    inspector = inspect(db.bind)
    try:
        columns = inspector.get_columns(table_name)
    except Exception:
        return set()
    return {col["name"] for col in columns}


def _ensure_schema_compatibility(db: Session) -> None:
    dialect = db.bind.dialect.name
    wf_columns = _existing_columns(db, "workflow_definitions")
    user_columns = _existing_columns(db, "users")
    org_columns = _existing_columns(db, "organizations")
    file_columns = _existing_columns(db, "stored_files")
    audit_columns = _existing_columns(db, "audit_logs")
    metric_columns = _existing_columns(db, "metric_records")
    task_columns = _existing_columns(db, "backup_archive_tasks")

    if not settings.enable_runtime_schema_patch:
        return

    if "branch_rules_json" not in wf_columns:
        if dialect == "postgresql":
            db.execute(text("ALTER TABLE workflow_definitions ADD COLUMN branch_rules_json JSON NOT NULL DEFAULT '{}'::json"))
        else:
            db.execute(text("ALTER TABLE workflow_definitions ADD COLUMN branch_rules_json JSON NOT NULL DEFAULT '{}'"))

    if "encrypted_contact" not in user_columns:
        db.execute(text("ALTER TABLE users ADD COLUMN encrypted_contact TEXT NOT NULL DEFAULT ''"))

    if "code" not in org_columns:
        db.execute(text("ALTER TABLE organizations ADD COLUMN code VARCHAR(64)"))

    if "business_type" not in file_columns:
        db.execute(text("ALTER TABLE stored_files ADD COLUMN business_type VARCHAR(80) NOT NULL DEFAULT 'GENERIC'"))
    if "business_id" not in file_columns:
        db.execute(text("ALTER TABLE stored_files ADD COLUMN business_id VARCHAR(120) NOT NULL DEFAULT 'UNSPECIFIED'"))

    if "previous_hash" not in audit_columns:
        db.execute(text("ALTER TABLE audit_logs ADD COLUMN previous_hash VARCHAR(64) NOT NULL DEFAULT ''"))
    if "current_hash" not in audit_columns:
        db.execute(text("ALTER TABLE audit_logs ADD COLUMN current_hash VARCHAR(64) NOT NULL DEFAULT ''"))

    if "appointment_id" not in metric_columns:
        db.execute(text("ALTER TABLE metric_records ADD COLUMN appointment_id VARCHAR(64) NOT NULL DEFAULT ''"))
    if "patient_id" not in metric_columns:
        db.execute(text("ALTER TABLE metric_records ADD COLUMN patient_id VARCHAR(64) NOT NULL DEFAULT ''"))
    if "doctor_id" not in metric_columns:
        db.execute(text("ALTER TABLE metric_records ADD COLUMN doctor_id VARCHAR(64) NOT NULL DEFAULT ''"))
    if "activity_type" not in metric_columns:
        db.execute(text("ALTER TABLE metric_records ADD COLUMN activity_type VARCHAR(64) NOT NULL DEFAULT ''"))
    if "message_reach" not in metric_columns:
        db.execute(text("ALTER TABLE metric_records ADD COLUMN message_reach FLOAT NOT NULL DEFAULT 0"))

    if "scheduled_for" not in task_columns:
        db.execute(text("ALTER TABLE backup_archive_tasks ADD COLUMN scheduled_for TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"))
    if "retained_until" not in task_columns:
        db.execute(text("ALTER TABLE backup_archive_tasks ADD COLUMN retained_until TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"))

    if dialect == "postgresql":
        db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_idempotency_org_business ON idempotency_keys (organization_id, business_number)"))
        db.execute(
            text(
                """
                CREATE OR REPLACE FUNCTION prevent_audit_log_changes()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_logs is append-only';
                END;
                $$ LANGUAGE plpgsql;
                """
            )
        )
        db.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_update') THEN
                        CREATE TRIGGER trg_prevent_audit_update
                        BEFORE UPDATE ON audit_logs
                        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_delete') THEN
                        CREATE TRIGGER trg_prevent_audit_delete
                        BEFORE DELETE ON audit_logs
                        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();
                    END IF;
                END$$;
                """
            )
        )
    else:
        db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_idempotency_org_business ON idempotency_keys (organization_id, business_number)"))
        db.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_update
                BEFORE UPDATE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit_logs is append-only');
                END;
                """
            )
        )
        db.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_delete
                BEFORE DELETE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit_logs is append-only');
                END;
                """
            )
        )

    if dialect == "postgresql" and ("code" in org_columns or "code" in _existing_columns(db, "organizations")):
        db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_organizations_code ON organizations (code)"))

    db.commit()


def _ensure_audit_append_only(db: Session) -> None:
    dialect = db.bind.dialect.name
    if dialect == "postgresql":
        db.execute(
            text(
                """
                CREATE OR REPLACE FUNCTION prevent_audit_log_changes()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_logs is append-only';
                END;
                $$ LANGUAGE plpgsql;
                """
            )
        )
        db.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_update') THEN
                        CREATE TRIGGER trg_prevent_audit_update
                        BEFORE UPDATE ON audit_logs
                        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_delete') THEN
                        CREATE TRIGGER trg_prevent_audit_delete
                        BEFORE DELETE ON audit_logs
                        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();
                    END IF;
                END$$;
                """
            )
        )
    else:
        db.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_update
                BEFORE UPDATE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit_logs is append-only');
                END;
                """
            )
        )
        db.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_delete
                BEFORE DELETE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit_logs is append-only');
                END;
                """
            )
        )
    db.commit()


def bootstrap() -> None:
    Base.metadata.create_all(bind=engine)
    with Session(engine) as db:
        _ensure_schema_compatibility(db)
        _ensure_audit_append_only(db)
        for role_name in [ROLE_ADMIN, ROLE_REVIEWER, ROLE_GENERAL, ROLE_AUDITOR, "admin", "approver", "export"]:
            existing = db.scalar(select(Role).where(Role.name == role_name))
            if not existing:
                db.add(Role(name=role_name))

        permission_rows = [
            (ROLE_ADMIN, "EXPORT", "READ"),
            (ROLE_ADMIN, "EXPORT", "CREATE"),
            (ROLE_ADMIN, "WORKFLOW", "ASSIGN"),
            (ROLE_ADMIN, "WORKFLOW", "DECIDE"),
            (ROLE_ADMIN, "WORKFLOW", "ROLLBACK"),
            (ROLE_ADMIN, "GOVERNANCE", "MANAGE"),
            (ROLE_REVIEWER, "WORKFLOW", "DECIDE"),
            (ROLE_REVIEWER, "WORKFLOW", "CLAIM"),
            (ROLE_REVIEWER, "WORKFLOW", "ASSIGN"),
            (ROLE_AUDITOR, "EXPORT", "READ"),
            (ROLE_AUDITOR, "EXPORT", "CREATE"),
            (ROLE_AUDITOR, "GOVERNANCE", "MANAGE"),
            (ROLE_GENERAL, "WORKFLOW", "CREATE"),
            ("admin", "EXPORT", "READ"),
            ("admin", "EXPORT", "CREATE"),
            ("admin", "WORKFLOW", "ASSIGN"),
            ("admin", "WORKFLOW", "DECIDE"),
            ("approver", "WORKFLOW", "DECIDE"),
            ("approver", "WORKFLOW", "CLAIM"),
            ("export", "EXPORT", "READ"),
            ("export", "EXPORT", "CREATE"),
        ]
        for role_name, resource, action in permission_rows:
            exists = db.scalar(
                select(PermissionPolicy).where(
                    PermissionPolicy.role_name == role_name,
                    PermissionPolicy.resource == resource,
                    PermissionPolicy.action == action,
                )
            )
            if not exists:
                db.add(PermissionPolicy(role_name=role_name, resource=resource, action=action))
        for wf_code, approvals in [("RESOURCE_APPLICATION", 1), ("CREDIT_CHANGE", 2)]:
            existing = db.scalar(select(WorkflowDefinition).where(WorkflowDefinition.code == wf_code))
            if not existing:
                db.add(
                    WorkflowDefinition(
                        code=wf_code,
                        required_approvals=approvals,
                        sla_hours=48,
                        branch_rules_json={
                            "HIGH_RISK": {"required_approvals": 2},
                            "LOW_RISK": {"required_approvals": 1},
                        },
                    )
                )
        dictionary_rows = [
            ("metrics", "metric_value", "Validated numeric value by metric type bounds"),
            ("metrics", "appointment_id", "Appointment dimension for operation analytics"),
            ("metrics", "patient_id", "Patient dimension for operation analytics"),
            ("metrics", "doctor_id", "Doctor dimension for operation analytics"),
            ("metrics", "activity_type", "Operational activity taxonomy"),
            ("metrics", "message_reach", "Message reach score used in campaign analysis"),
        ]
        for domain, field_name, description in dictionary_rows:
            if not db.scalar(select(DataDictionary).where(DataDictionary.domain == domain, DataDictionary.field_name == field_name)):
                db.add(DataDictionary(domain=domain, field_name=field_name, description=description))
        if not db.scalar(select(DataLineage).where(DataLineage.source_entity == "import_batch", DataLineage.target_entity == "metric_records")):
            db.add(DataLineage(source_entity="import_batch", target_entity="metric_records", transform_rule="quality_checks_then_insert"))
        db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    bootstrap()
    yield


app = FastAPI(title="Medical Operations Middle Platform", lifespan=lifespan)


class UserRegisterReq(BaseModel):
    username: str
    password: str
    id_number: str
    contact: str = ""
    organization_name: str
    organization_code: str | None = None
    role: str = "general"


class LoginReq(BaseModel):
    username: str
    password: str


class PasswordRecoveryRequestReq(BaseModel):
    username: str


class PasswordRecoveryResetReq(BaseModel):
    username: str
    token: str
    new_password: str


class LogoutReq(BaseModel):
    token: str


class WorkflowCreateReq(BaseModel):
    business_number: str
    workflow_code: str
    payload: dict
    idempotency_key: str


class WorkflowDecisionReq(BaseModel):
    decision: str
    comment: str = ""


class MetricIngestReq(BaseModel):
    items: list[dict]


class ExportCreateReq(BaseModel):
    fields: list[str]


class ImportBatchReq(BaseModel):
    items: list[dict]


class SchedulerRunReq(BaseModel):
    should_fail: bool = False


class OrganizationCreateReq(BaseModel):
    name: str
    code: str


class OrganizationJoinReq(BaseModel):
    organization_code: str
    role: str = ROLE_GENERAL


class WorkflowReminderReq(BaseModel):
    before_minutes: int = 120


class AssignTaskReq(BaseModel):
    assign_to_user_id: str
    note: str = ""


class ClaimTaskReq(BaseModel):
    note: str = ""


class WorkflowAllocateReq(BaseModel):
    allocate_to_user_id: str
    department: str = ""
    note: str = ""


def _error_json(code: int, msg: str) -> JSONResponse:
    return JSONResponse(status_code=code, content={"code": code, "msg": msg})


@app.exception_handler(AppError)
def handle_app_error(_, exc: AppError):
    return _error_json(exc.code, exc.msg)


@app.exception_handler(RequestValidationError)
def handle_validation_error(_, exc: RequestValidationError):
    return _error_json(400, str(exc))


@app.exception_handler(Exception)
def handle_unexpected_error(_, __):
    return _error_json(500, "Internal server error")


@app.exception_handler(HTTPException)
def handle_http_exception(_, exc: HTTPException):
    if isinstance(exc.detail, dict) and "code" in exc.detail and "msg" in exc.detail:
        detail = cast(dict[str, Any], exc.detail)
        code = int(detail.get("code", exc.status_code))
        msg = str(detail.get("msg", "Error"))
        return _error_json(code, msg)
    return _error_json(exc.status_code, str(exc.detail))


def _snapshot_entity(db: Session, entity_name: str, entity_id: str, version_id: int, data: dict) -> None:
    db.add(EntitySnapshot(entity_name=entity_name, entity_id=entity_id, version_id=version_id, data_json=data))


def _normalize_org_code(name: str) -> str:
    base = "".join(ch for ch in name.upper() if ch.isalnum())
    if not base:
        base = "ORG"
    return base[:12]


def _desensitize(field_name: str, value: str) -> str:
    if not value:
        return ""
    if field_name == "id_number":
        return f"***{value[-4:]}"
    if field_name == "contact":
        return f"***{value[-4:]}"
    return value


def _desensitize_by_role(role_name: str, field_name: str, value: str) -> str:
    if role_name in {ROLE_ADMIN, ROLE_AUDITOR, "admin"}:
        return value
    return _desensitize(field_name, value)


def _get_current_user(db: Session, authorization: str | None) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise AppError(401, "Missing bearer token")
    token = authorization.replace("Bearer ", "", 1).strip()
    session_token = db.get(SessionToken, token)
    if not session_token or session_token.expires_at < now_utc():
        raise AppError(401, "Invalid or expired token")
    user = db.get(User, session_token.user_id)
    if not user:
        raise AppError(401, "User not found")
    return user


def _require_membership(db: Session, user_id: str, organization_id: str) -> OrgMembership:
    stmt = select(OrgMembership).where(
        OrgMembership.user_id == user_id,
        OrgMembership.organization_id == organization_id,
    )
    membership = db.scalar(stmt)
    if not membership:
        raise AppError(403, "Forbidden by organization isolation")
    return membership


def _require_admin_or_approver(db: Session, membership: OrgMembership) -> None:
    role = db.get(Role, membership.role_id)
    if not role:
        raise AppError(403, "Insufficient role")
    _authorize_action(db, role.name, "WORKFLOW", "DECIDE")


def _membership_role(db: Session, membership: OrgMembership) -> str:
    role = db.get(Role, membership.role_id)
    if not role:
        raise AppError(403, "Role not found")
    return role.name


def _require_role(role_name: str, allowed: set[str]) -> None:
    if role_name not in allowed:
        raise AppError(403, "Insufficient role")


def _authorize_action(db: Session, role_name: str, resource: str, action: str) -> None:
    allowed = db.scalar(
        select(PermissionPolicy).where(
            PermissionPolicy.role_name == role_name,
            PermissionPolicy.resource == resource,
            PermissionPolicy.action == action,
        )
    )
    if not allowed:
        raise AppError(403, "Insufficient role")


@app.middleware("http")
async def https_only_middleware(request: Request, call_next):
    if settings.enforce_https and settings.environment == "production":
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        if request.url.scheme != "https" and forwarded_proto != "https":
            return _error_json(400, "HTTPS is required")
    return await call_next(request)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "medical-ops-middle-platform"}


@app.get("/")
def root() -> dict:
    return {
        "status": "ok",
        "service": "medical-ops-middle-platform",
        "docs": "/docs",
        "health": "/health",
    }


@app.post("/auth/register")
def register(payload: UserRegisterReq, db: Session = Depends(get_db)):
    if not password_is_valid(payload.password):
        raise AppError(400, "Password must be at least 8 characters and include letters and numbers")
    if db.scalar(select(User).where(User.username == payload.username)):
        raise AppError(400, "Username already exists")

    org = db.scalar(select(Organization).where(Organization.name == payload.organization_name))
    if not org:
        org_code = payload.organization_code or _normalize_org_code(payload.organization_name)
        if db.scalar(select(Organization).where(Organization.code == org_code)):
            org_code = f"{org_code}{random_token()[:4].upper()}"
        org = Organization(name=payload.organization_name, code=org_code, credit_balance=0.0)
        db.add(org)
        db.flush()
        _snapshot_entity(db, "Organization", org.id, org.version_id, {"name": org.name, "credit_balance": str(org.credit_balance)})
    else:
        if payload.organization_code != org.code:
            raise AppError(403, "Registration into existing organization requires valid organization code")

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


@app.post("/auth/logout")
def logout(payload: LogoutReq, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = _get_current_user(db, authorization)
    token = db.get(SessionToken, payload.token)
    if not token:
        raise AppError(404, "Session token not found")
    if token.user_id != user.id:
        raise AppError(403, "Cannot logout another user's session")
    db.delete(token)
    db.commit()
    return {"logged_out": True}


@app.post("/auth/password-recovery/request")
def request_password_recovery(payload: PasswordRecoveryRequestReq, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == payload.username))
    if not user:
        raise AppError(404, "User not found")
    token = random_token()
    db.add(
        PasswordRecoveryToken(
            username=payload.username,
            token=token,
            expires_at=now_utc() + timedelta(minutes=30),
            used=False,
        )
    )
    log_audit(db, "PASSWORD_RECOVERY_REQUEST", "User", user.id, "Password recovery requested", actor_user_id=user.id)
    db.commit()
    return {
        "message": "Recovery request accepted",
        "expires_in_minutes": 30,
        "recovery_token": token if settings.environment == "test" else None,
    }


@app.post("/auth/password-recovery/reset")
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


@app.post("/auth/login")
def login(payload: LoginReq, db: Session = Depends(get_db)):
    now = now_utc()
    failure_window_start = now - timedelta(minutes=10)
    lock_window_start = now - timedelta(minutes=30)

    recent_attempts = db.scalars(
        select(LoginAttempt)
        .where(
            LoginAttempt.username == payload.username,
            LoginAttempt.attempted_at >= failure_window_start,
        )
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


@app.post("/organizations/create")
def create_organization(
    payload: OrganizationCreateReq,
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    if db.scalar(select(Organization).where(Organization.code == payload.code)):
        raise AppError(409, "Organization code already exists")
    if db.scalar(select(Organization).where(Organization.name == payload.name)):
        raise AppError(409, "Organization name already exists")
    org = Organization(name=payload.name, code=payload.code, credit_balance=0.0)
    db.add(org)
    db.flush()
    admin_role = db.scalar(select(Role).where(Role.name == ROLE_ADMIN))
    db.add(OrgMembership(user_id=user.id, organization_id=org.id, role_id=admin_role.id))
    _snapshot_entity(db, "Organization", org.id, org.version_id, {"name": org.name, "credit_balance": str(org.credit_balance)})
    log_audit(db, "ORG_CREATED", "Organization", org.id, f"Organization {org.name} created", actor_user_id=user.id, organization_id=org.id)
    db.commit()
    return {"organization_id": org.id, "code": org.code, "name": org.name}


@app.post("/organizations/join")
def join_organization(
    payload: OrganizationJoinReq,
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
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


@app.post("/workflows")
def create_workflow(
    payload: WorkflowCreateReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)

    existing = db.scalar(
        select(IdempotencyKey).where(
            IdempotencyKey.organization_id == x_org_id,
            IdempotencyKey.business_number == payload.business_number,
        )
    )
    if existing and existing.created_at >= now_utc() - timedelta(hours=24):
        return {"idempotent": True, "result": existing.response_json}

    definition = db.scalar(select(WorkflowDefinition).where(WorkflowDefinition.code == payload.workflow_code))
    if not definition:
        raise AppError(400, "Unknown workflow code")

    instance = WorkflowInstance(
        business_number=payload.business_number,
        organization_id=x_org_id,
        definition_id=definition.id,
        status="PENDING",
        payload_json=payload.payload,
        idempotency_key=payload.idempotency_key,
        deadline_at=now_utc() + timedelta(hours=definition.sla_hours),
        created_by=user.id,
    )
    db.add(instance)
    db.flush()
    _snapshot_entity(db, "WorkflowInstance", instance.id, instance.version_id, {"status": instance.status, "payload": instance.payload_json})

    response = {"workflow_instance_id": instance.id, "status": instance.status}
    row = db.scalar(
        select(IdempotencyKey).where(
            IdempotencyKey.organization_id == x_org_id,
            IdempotencyKey.business_number == payload.business_number,
        )
    )
    if row:
        if row.created_at >= now_utc() - timedelta(hours=24):
            db.rollback()
            return {"idempotent": True, "result": row.response_json}
        row.response_json = response
        row.created_at = now_utc()
    else:
        db.add(IdempotencyKey(organization_id=x_org_id, business_number=payload.business_number, response_json=response))
    log_audit(db, "WORKFLOW_CREATED", "WorkflowInstance", instance.id, f"Workflow {payload.workflow_code} created", actor_user_id=user.id, organization_id=x_org_id)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raced = db.scalar(
            select(IdempotencyKey).where(
                IdempotencyKey.organization_id == x_org_id,
                IdempotencyKey.business_number == payload.business_number,
            )
        )
        if raced and raced.created_at >= now_utc() - timedelta(hours=24):
            return {"idempotent": True, "result": raced.response_json}
        raise AppError(409, "Duplicate workflow submission conflict")
    return response


@app.post("/workflows/{instance_id}/decision")
def decision_workflow(
    instance_id: str,
    payload: WorkflowDecisionReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    _require_admin_or_approver(db, membership)

    instance = db.get(WorkflowInstance, instance_id)
    if not instance or instance.organization_id != x_org_id:
        raise AppError(404, "Workflow instance not found")

    if instance.deadline_at < now_utc() and instance.status == "PENDING":
        if can_transition(instance.status, "TIMED_OUT"):
            instance.status = "TIMED_OUT"
            instance.version_id += 1
            _snapshot_entity(db, "WorkflowInstance", instance.id, instance.version_id, {"status": instance.status})
            log_audit(db, "WORKFLOW_TIMEOUT", "WorkflowInstance", instance.id, "Workflow timed out", actor_user_id=user.id, organization_id=x_org_id)
            db.commit()
        raise AppError(400, "Workflow already timed out")

    if payload.decision not in {"APPROVE", "REJECT"}:
        raise AppError(400, "Decision must be APPROVE or REJECT")
    if instance.status != "PENDING":
        raise AppError(400, "Workflow is already finalized")

    db.add(WorkflowApproval(instance_id=instance.id, approver_id=user.id, decision=payload.decision, comment=payload.comment))
    db.flush()

    if payload.decision == "REJECT":
        if can_transition(instance.status, "REJECTED"):
            instance.status = "REJECTED"
            instance.version_id += 1
            _snapshot_entity(db, "WorkflowInstance", instance.id, instance.version_id, {"status": instance.status})
            log_audit(db, "WORKFLOW_REJECTED", "WorkflowInstance", instance.id, "Workflow rejected", actor_user_id=user.id, organization_id=x_org_id)
            db.commit()
            return {"status": instance.status}

    definition = db.get(WorkflowDefinition, instance.definition_id)
    risk_level = str(instance.payload_json.get("risk_level", "")).upper() or "LOW_RISK"
    required_approvals = definition.required_approvals
    if definition.branch_rules_json and risk_level in definition.branch_rules_json:
        branch_rule = definition.branch_rules_json[risk_level]
        branch_approvals = int(branch_rule.get("required_approvals", required_approvals))
        if branch_approvals > 0:
            required_approvals = branch_approvals

    approvals = db.scalar(
        select(func.count(WorkflowApproval.id)).where(
            WorkflowApproval.instance_id == instance.id,
            WorkflowApproval.decision == "APPROVE",
        )
    )
    if approvals >= required_approvals:
        if can_transition(instance.status, "APPROVED"):
            instance.status = "APPROVED"
            instance.version_id += 1
            _snapshot_entity(db, "WorkflowInstance", instance.id, instance.version_id, {"status": instance.status})

            if definition.code == "CREDIT_CHANGE":
                amount = Decimal(str(instance.payload_json.get("amount", 0)))
                reason = instance.payload_json.get("reason", "Credit change")
                org = db.get(Organization, instance.organization_id)
                before = Decimal(str(org.credit_balance))
                after = before + amount
                org.credit_balance = after
                org.version_id += 1
                _snapshot_entity(db, "Organization", org.id, org.version_id, {"credit_balance": str(after), "name": org.name})
                db.add(
                    CreditLedger(
                        organization_id=org.id,
                        workflow_instance_id=instance.id,
                        amount=amount,
                        balance_before=before,
                        balance_after=after,
                        reason=reason,
                    )
                )
                log_audit(
                    db,
                    "CREDIT_LEDGER_APPLIED",
                    "Organization",
                    org.id,
                    f"Credit balance changed by {amount}",
                    actor_user_id=user.id,
                    organization_id=org.id,
                )

            log_audit(db, "WORKFLOW_APPROVED", "WorkflowInstance", instance.id, "Workflow approved", actor_user_id=user.id, organization_id=x_org_id)
            db.commit()
            return {"status": instance.status}

    log_audit(
        db,
        "WORKFLOW_PARTIAL_APPROVAL",
        "WorkflowInstance",
        instance.id,
        f"Approval progress {approvals}/{required_approvals} (risk={risk_level})",
        actor_user_id=user.id,
        organization_id=x_org_id,
    )
    db.commit()
    return {"status": instance.status}


@app.post("/metrics/ingest")
def ingest_metrics(
    payload: MetricIngestReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    seen_in_request: set[str] = set()
    inserted = 0

    for item in payload.items:
        err = validate_metric_item(item)
        if err:
            raise AppError(400, err)
        if item["source_key"] in seen_in_request:
            raise AppError(400, "Duplicate source_key in request")
        seen_in_request.add(item["source_key"])

        exists = db.scalar(select(MetricRecord).where(MetricRecord.source_key == item["source_key"]))
        if exists:
            raise AppError(400, "Duplicate source_key in database")

        db.add(
            MetricRecord(
                organization_id=x_org_id,
                metric_type=item["metric_type"],
                metric_value=item["metric_value"],
                source_key=item["source_key"],
                appointment_id=item.get("appointment_id", ""),
                patient_id=item.get("patient_id", ""),
                doctor_id=item.get("doctor_id", ""),
                activity_type=item.get("activity_type", ""),
                message_reach=float(item.get("message_reach", 0) or 0),
                recorded_at=datetime.fromisoformat(item["recorded_at"]),
            )
        )
        inserted += 1

    log_audit(db, "METRICS_INGEST", "MetricRecord", x_org_id, f"Inserted {inserted} metrics", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"inserted": inserted}


@app.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    x_org_id: str = Header(..., alias="X-Org-ID"),
    x_business_type: str = Header(..., alias="X-Business-Type"),
    x_business_id: str = Header(..., alias="X-Business-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)

    if file.content_type not in ALLOWED_FILE_TYPES:
        raise AppError(400, "Unsupported file type")

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise AppError(400, "File exceeds 20MB limit")

    sha256_hash = hashlib.sha256(content).hexdigest()
    existing = db.scalar(
        select(StoredFile).where(
            StoredFile.sha256_hash == sha256_hash,
            StoredFile.organization_id == x_org_id,
            StoredFile.business_type == x_business_type,
            StoredFile.business_id == x_business_id,
        )
    )
    if existing:
        return {"deduplicated": True, "file_id": existing.id, "sha256": sha256_hash}

    storage_dir = Path("pure_backend/storage")
    storage_dir.mkdir(parents=True, exist_ok=True)
    path = storage_dir / f"{sha256_hash}_{file.filename}"
    path.write_bytes(content)

    record = StoredFile(
        organization_id=x_org_id,
        filename=file.filename,
        content_type=file.content_type,
        file_size=len(content),
        sha256_hash=sha256_hash,
        storage_path=str(path),
        uploaded_by=user.id,
        business_type=x_business_type,
        business_id=x_business_id,
    )
    db.add(record)
    log_audit(db, "FILE_UPLOADED", "StoredFile", sha256_hash, f"Uploaded {file.filename}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"deduplicated": False, "file_id": record.id, "sha256": sha256_hash}


@app.get("/organizations/{org_id}/credit-ledger")
def get_credit_ledger(
    org_id: str,
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, org_id)
    rows = db.scalars(select(CreditLedger).where(CreditLedger.organization_id == org_id).order_by(CreditLedger.id.desc())).all()
    return [
        {
            "id": r.id,
            "amount": float(r.amount),
            "balance_before": float(r.balance_before),
            "balance_after": float(r.balance_after),
            "reason": r.reason,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@app.get("/export/domain")
def export_domain(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    if role not in {ROLE_AUDITOR, ROLE_ADMIN, "export", "admin"}:
        raise AppError(403, "General user cannot access export domain")

    org = db.get(Organization, x_org_id)
    metrics_count = db.scalar(select(func.count(MetricRecord.id)).where(MetricRecord.organization_id == x_org_id))
    workflows_count = db.scalar(select(func.count(WorkflowInstance.id)).where(WorkflowInstance.organization_id == x_org_id))
    return {
        "organization": {"id": org.id, "name": org.name, "credit_balance": float(org.credit_balance)},
        "counts": {"metrics": metrics_count, "workflows": workflows_count},
    }


@app.post("/export/tasks")
def create_export_task(
    payload: ExportCreateReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _authorize_action(db, role, "EXPORT", "CREATE")

    if not payload.fields:
        raise AppError(400, "At least one export field is required")
    for field in payload.fields:
        if field not in EXPORT_FIELD_WHITELIST:
            raise AppError(400, f"Field not allowed for export: {field}")

    org = db.get(Organization, x_org_id)
    memberships = db.scalars(select(OrgMembership).where(OrgMembership.organization_id == x_org_id)).all()
    rows: list[dict[str, Any]] = []
    for m in memberships:
        member_user = db.get(User, m.user_id)
        if not member_user:
            continue
        row: dict[str, Any] = {}
        for field in payload.fields:
            if field == "username":
                row[field] = member_user.username
            elif field == "id_number":
                row[field] = _desensitize_by_role(role, "id_number", decrypt_value(member_user.encrypted_id_number, settings.app_secret))
            elif field == "contact":
                contact = decrypt_value(member_user.encrypted_contact, settings.app_secret) if member_user.encrypted_contact else ""
                row[field] = _desensitize_by_role(role, "contact", contact)
            elif field == "organization_name":
                row[field] = org.name
            elif field == "credit_balance":
                row[field] = float(org.credit_balance)
        rows.append(row)

    task = ExportTask(
        organization_id=x_org_id,
        requested_by=user.id,
        fields_json=payload.fields,
        status="DONE",
        result_json={"rows": rows, "row_count": len(rows)},
    )
    db.add(task)
    db.flush()
    log_audit(db, "EXPORT_TASK_CREATED", "ExportTask", task.id, f"Export fields: {payload.fields}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"task_id": task.id, "status": task.status, "row_count": len(rows)}


@app.get("/export/tasks/{task_id}")
def get_export_task(
    task_id: str,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _authorize_action(db, role, "EXPORT", "READ")
    task = db.get(ExportTask, task_id)
    if not task or task.organization_id != x_org_id:
        raise AppError(404, "Export task not found")
    return {
        "task_id": task.id,
        "organization_id": task.organization_id,
        "requested_by": task.requested_by,
        "fields": task.fields_json,
        "status": task.status,
        "result": task.result_json,
    }


@app.post("/workflows/{instance_id}/reminder")
def create_workflow_reminder(
    instance_id: str,
    payload: WorkflowReminderReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    _require_admin_or_approver(db, membership)
    wf = db.get(WorkflowInstance, instance_id)
    if not wf or wf.organization_id != x_org_id:
        raise AppError(404, "Workflow instance not found")
    if wf.status != "PENDING":
        raise AppError(400, "Workflow is not pending")
    if wf.deadline_at < now_utc():
        raise AppError(400, "Workflow already timed out")
    remind_at = wf.deadline_at - timedelta(minutes=payload.before_minutes)
    log_audit(
        db,
        "WORKFLOW_REMINDER_CREATED",
        "WorkflowInstance",
        wf.id,
        f"Reminder scheduled at {remind_at.isoformat()}",
        actor_user_id=user.id,
        organization_id=x_org_id,
    )
    db.commit()
    return {"workflow_instance_id": wf.id, "remind_at": remind_at.isoformat()}


@app.get("/files/{file_id}")
def get_file_metadata(
    file_id: int,
    business_type: str = Query(...),
    business_id: str = Query(...),
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    file_row = db.get(StoredFile, file_id)
    if (
        not file_row
        or file_row.organization_id != x_org_id
        or file_row.business_type != business_type
        or file_row.business_id != business_id
    ):
        raise AppError(404, "File not found")
    return {
        "id": file_row.id,
        "filename": file_row.filename,
        "content_type": file_row.content_type,
        "file_size": file_row.file_size,
        "sha256": file_row.sha256_hash,
        "business_type": file_row.business_type,
        "business_id": file_row.business_id,
    }


@app.post("/metrics/import-batch")
def import_metrics_batch(
    payload: ImportBatchReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    batch = ImportBatch(organization_id=x_org_id, created_by=user.id)
    db.add(batch)
    db.flush()
    success = 0
    failed = 0
    for item in payload.items:
        err = validate_metric_item(item)
        if err:
            db.add(ImportBatchDetail(batch_id=batch.id, item_json=item, status="FAILED", error_message=err))
            failed += 1
            continue
        exists = db.scalar(select(MetricRecord).where(MetricRecord.source_key == item["source_key"]))
        if exists:
            db.add(ImportBatchDetail(batch_id=batch.id, item_json=item, status="FAILED", error_message="Duplicate source_key in database"))
            failed += 1
            continue
        db.add(
            MetricRecord(
                organization_id=x_org_id,
                metric_type=item["metric_type"],
                metric_value=item["metric_value"],
                source_key=item["source_key"],
                appointment_id=item.get("appointment_id", ""),
                patient_id=item.get("patient_id", ""),
                doctor_id=item.get("doctor_id", ""),
                activity_type=item.get("activity_type", ""),
                message_reach=float(item.get("message_reach", 0) or 0),
                recorded_at=datetime.fromisoformat(item["recorded_at"]),
            )
        )
        db.add(ImportBatchDetail(batch_id=batch.id, item_json=item, status="SUCCESS", error_message=""))
        success += 1
    log_audit(db, "IMPORT_BATCH", "ImportBatch", batch.id, f"success={success}, failed={failed}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"batch_id": batch.id, "success": success, "failed": failed}


@app.get("/operations/dashboard")
def operations_dashboard(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    metrics = db.scalars(select(MetricRecord).where(MetricRecord.organization_id == x_org_id)).all()
    workflows_count = db.scalar(select(func.count(WorkflowInstance.id)).where(WorkflowInstance.organization_id == x_org_id))
    summary = {
        "attendance_total": sum(m.metric_value for m in metrics if m.metric_type == "attendance"),
        "expenses_total": sum(m.metric_value for m in metrics if m.metric_type == "expenses"),
        "work_order_sla_avg": (
            (
                sum(m.metric_value for m in metrics if m.metric_type == "work_order_sla")
                / max(1, sum(1 for m in metrics if m.metric_type == "work_order_sla"))
            )
            if metrics
            else 0
        ),
        "sla_avg": (
            (sum(m.metric_value for m in metrics if m.metric_type == "sla") / max(1, sum(1 for m in metrics if m.metric_type == "sla")))
            if metrics
            else 0
        ),
    }
    return {"organization_id": x_org_id, "workflows": workflows_count, "summary": summary}


@app.get("/operations/search")
def operations_search(
    metric_type: str = Query(...),
    appointment_id: str | None = Query(None),
    patient_id: str | None = Query(None),
    doctor_id: str | None = Query(None),
    activity_type: str | None = Query(None),
    min_message_reach: float | None = Query(None),
    max_message_reach: float | None = Query(None),
    start_time: str | None = Query(None),
    end_time: str | None = Query(None),
    min_value: float | None = Query(None),
    max_value: float | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    stmt = select(MetricRecord).where(MetricRecord.organization_id == x_org_id, MetricRecord.metric_type == metric_type)
    if appointment_id:
        stmt = stmt.where(MetricRecord.appointment_id == appointment_id)
    if patient_id:
        stmt = stmt.where(MetricRecord.patient_id == patient_id)
    if doctor_id:
        stmt = stmt.where(MetricRecord.doctor_id == doctor_id)
    if activity_type:
        stmt = stmt.where(MetricRecord.activity_type == activity_type)
    if min_message_reach is not None:
        stmt = stmt.where(MetricRecord.message_reach >= min_message_reach)
    if max_message_reach is not None:
        stmt = stmt.where(MetricRecord.message_reach <= max_message_reach)
    if start_time:
        stmt = stmt.where(MetricRecord.recorded_at >= datetime.fromisoformat(start_time))
    if end_time:
        stmt = stmt.where(MetricRecord.recorded_at <= datetime.fromisoformat(end_time))
    if min_value is not None:
        stmt = stmt.where(MetricRecord.metric_value >= min_value)
    if max_value is not None:
        stmt = stmt.where(MetricRecord.metric_value <= max_value)

    all_rows = db.scalars(stmt.order_by(MetricRecord.recorded_at.desc())).all()
    total = len(all_rows)
    start_idx = (page - 1) * page_size
    items = all_rows[start_idx : start_idx + page_size]
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": item.id,
                "metric_type": item.metric_type,
                "metric_value": item.metric_value,
                "source_key": item.source_key,
                "appointment_id": item.appointment_id,
                "patient_id": item.patient_id,
                "doctor_id": item.doctor_id,
                "activity_type": item.activity_type,
                "message_reach": item.message_reach,
                "recorded_at": item.recorded_at.isoformat(),
            }
            for item in items
        ],
    }


@app.get("/operations/report")
def operations_report(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    rows = db.scalars(select(MetricRecord).where(MetricRecord.organization_id == x_org_id)).all()
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        curr = grouped.setdefault(row.metric_type, {"count": 0, "sum": 0.0, "message_reach_sum": 0.0})
        curr["count"] += 1
        curr["sum"] += row.metric_value
        curr["message_reach_sum"] += row.message_reach
    for metric_type, agg in grouped.items():
        agg["avg"] = agg["sum"] / max(1, agg["count"])
        agg["message_reach_avg"] = agg["message_reach_sum"] / max(1, agg["count"])
        agg["metric_type"] = metric_type
    return {"organization_id": x_org_id, "report": list(grouped.values())}


@app.get("/operations/anomalies/attendance")
def attendance_anomalies(
    threshold_hours: float = Query(12, gt=0),
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    rows = db.scalars(
        select(MetricRecord).where(
            MetricRecord.organization_id == x_org_id,
            MetricRecord.metric_type == "attendance",
            MetricRecord.metric_value > threshold_hours,
        )
    ).all()
    return {
        "threshold_hours": threshold_hours,
        "count": len(rows),
        "items": [
            {
                "id": row.id,
                "metric_value": row.metric_value,
                "source_key": row.source_key,
                "patient_id": row.patient_id,
                "doctor_id": row.doctor_id,
                "recorded_at": row.recorded_at.isoformat(),
            }
            for row in rows
        ],
    }


@app.get("/operations/work-orders/sla")
def work_order_sla_report(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    rows = db.scalars(
        select(MetricRecord).where(
            MetricRecord.organization_id == x_org_id,
            MetricRecord.metric_type == "work_order_sla",
        )
    ).all()
    avg = sum(r.metric_value for r in rows) / max(1, len(rows))
    return {
        "count": len(rows),
        "avg_sla": avg,
        "items": [
            {
                "id": row.id,
                "metric_value": row.metric_value,
                "source_key": row.source_key,
                "appointment_id": row.appointment_id,
                "recorded_at": row.recorded_at.isoformat(),
            }
            for row in rows
        ],
    }


@app.post("/governance/backup")
def create_backup_task(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _require_role(role, {ROLE_ADMIN, ROLE_AUDITOR})
    task = BackupArchiveTask(
        task_type="BACKUP",
        status="DONE",
        detail=f"daily full backup for org {x_org_id}",
        scheduled_for=now_utc(),
        retained_until=now_utc() + timedelta(days=30),
    )
    db.add(task)
    log_audit(db, "BACKUP_TASK", "BackupArchiveTask", str(task.id), "Backup task created", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"task_type": task.task_type, "status": task.status}


@app.post("/governance/archive")
def create_archive_task(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _require_role(role, {ROLE_ADMIN, ROLE_AUDITOR})
    task = BackupArchiveTask(
        task_type="ARCHIVE",
        status="DONE",
        detail=f"archive for org {x_org_id} with 30-day retention",
        scheduled_for=now_utc(),
        retained_until=now_utc() + timedelta(days=30),
    )
    db.add(task)
    log_audit(db, "ARCHIVE_TASK", "BackupArchiveTask", str(task.id), "Archive task created", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"task_type": task.task_type, "status": task.status}


@app.post("/governance/scheduler/{task_name}/run")
def run_scheduler_task(
    task_name: str,
    payload: SchedulerRunReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _require_role(role, {ROLE_ADMIN, ROLE_AUDITOR})
    task = db.scalar(select(SchedulerTask).where(SchedulerTask.name == task_name))
    if not task:
        task = SchedulerTask(name=task_name, max_retries=3, retry_count=0, status="PENDING", last_error="", updated_at=now_utc())
        db.add(task)
        db.flush()

    if task.retry_count >= task.max_retries and task.status == "FAILED" and payload.should_fail:
        raise AppError(409, "Scheduler task exceeded max retries")

    if payload.should_fail:
        task.retry_count += 1
        task.status = "FAILED"
        task.last_error = "Simulated failure"
    else:
        task.status = "SUCCESS"
        task.last_error = ""
    task.updated_at = now_utc()
    log_audit(db, "SCHEDULER_RUN", "SchedulerTask", task.id, f"status={task.status}, retries={task.retry_count}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"task_name": task.name, "status": task.status, "retry_count": task.retry_count, "max_retries": task.max_retries}


@app.post("/workflows/{instance_id}/assign")
def assign_workflow_task(
    instance_id: str,
    payload: AssignTaskReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _authorize_action(db, role, "WORKFLOW", "ASSIGN")

    wf = db.get(WorkflowInstance, instance_id)
    if not wf or wf.organization_id != x_org_id:
        raise AppError(404, "Workflow instance not found")
    assignee_membership = db.scalar(
        select(OrgMembership).where(
            OrgMembership.user_id == payload.assign_to_user_id,
            OrgMembership.organization_id == x_org_id,
        )
    )
    if not assignee_membership:
        raise AppError(404, "Assignee not found in organization")

    assignment = TaskAssignment(
        organization_id=x_org_id,
        workflow_instance_id=instance_id,
        assigned_to_user_id=payload.assign_to_user_id,
        assigned_by_user_id=user.id,
        status="PENDING",
        note=payload.note,
    )
    db.add(assignment)
    db.flush()
    log_audit(db, "TASK_ASSIGNED", "TaskAssignment", assignment.id, f"Assigned workflow task to user {payload.assign_to_user_id}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"assignment_id": assignment.id, "status": assignment.status}


@app.post("/tasks/{assignment_id}/claim")
def claim_task(
    assignment_id: str,
    payload: ClaimTaskReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _authorize_action(db, role, "WORKFLOW", "CLAIM")

    assignment = db.get(TaskAssignment, assignment_id)
    if not assignment or assignment.organization_id != x_org_id:
        raise AppError(404, "Assignment not found")
    if assignment.assigned_to_user_id != user.id:
        raise AppError(403, "Cannot claim task assigned to another user")
    if assignment.status != "PENDING":
        raise AppError(400, "Assignment is not pending")
    assignment.status = "CLAIMED"
    assignment.note = payload.note or assignment.note
    log_audit(db, "TASK_CLAIMED", "TaskAssignment", assignment.id, "Task claimed by assignee", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"assignment_id": assignment.id, "status": assignment.status}


@app.post("/workflows/{instance_id}/allocate")
def allocate_workflow(
    instance_id: str,
    payload: WorkflowAllocateReq,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _authorize_action(db, role, "WORKFLOW", "ASSIGN")

    wf = db.get(WorkflowInstance, instance_id)
    if not wf or wf.organization_id != x_org_id:
        raise AppError(404, "Workflow instance not found")
    if wf.status != "APPROVED":
        raise AppError(400, "Workflow must be approved before allocation")

    assignee_membership = db.scalar(
        select(OrgMembership).where(
            OrgMembership.user_id == payload.allocate_to_user_id,
            OrgMembership.organization_id == x_org_id,
        )
    )
    if not assignee_membership:
        raise AppError(404, "Allocation target not found in organization")

    existing = db.scalar(select(WorkflowAllocation).where(WorkflowAllocation.workflow_instance_id == instance_id))
    if existing:
        existing.allocated_to_user_id = payload.allocate_to_user_id
        existing.department = payload.department
        existing.note = payload.note
        allocation_id = existing.id
    else:
        allocation = WorkflowAllocation(
            organization_id=x_org_id,
            workflow_instance_id=instance_id,
            allocated_by_user_id=user.id,
            allocated_to_user_id=payload.allocate_to_user_id,
            department=payload.department,
            note=payload.note,
        )
        db.add(allocation)
        db.flush()
        allocation_id = allocation.id

    log_audit(
        db,
        "WORKFLOW_ALLOCATED",
        "WorkflowAllocation",
        allocation_id,
        f"Workflow allocated to user {payload.allocate_to_user_id}",
        actor_user_id=user.id,
        organization_id=x_org_id,
    )
    db.commit()
    return {"allocation_id": allocation_id, "workflow_instance_id": instance_id, "allocated_to_user_id": payload.allocate_to_user_id}


@app.get("/governance/lineage")
def get_data_lineage(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    rows = db.scalars(select(DataLineage).order_by(DataLineage.id.asc())).all()
    return [
        {
            "source_entity": row.source_entity,
            "target_entity": row.target_entity,
            "transform_rule": row.transform_rule,
        }
        for row in rows
    ]


@app.get("/governance/dictionary")
def get_data_dictionary(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    _require_membership(db, user.id, x_org_id)
    rows = db.scalars(select(DataDictionary).order_by(DataDictionary.id.asc())).all()
    return [{"domain": row.domain, "field_name": row.field_name, "description": row.description} for row in rows]


@app.post("/governance/retention/run")
def run_retention_enforcement(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _require_role(role, {ROLE_ADMIN, ROLE_AUDITOR})
    now = now_utc()
    expired = db.scalars(select(BackupArchiveTask).where(BackupArchiveTask.retained_until < now)).all()
    cleaned = 0
    for task in expired:
        task.status = "DONE"
        task.detail = f"retention-enforced cleanup at {now.isoformat()}"
        cleaned += 1
    log_audit(db, "RETENTION_ENFORCED", "BackupArchiveTask", x_org_id, f"cleaned={cleaned}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"cleaned": cleaned}


@app.get("/governance/audit/integrity")
def audit_integrity_check(
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    role = _membership_role(db, membership)
    _require_role(role, {ROLE_ADMIN, ROLE_AUDITOR, "admin"})

    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all()
    broken_at: int | None = None
    for idx in range(1, len(rows)):
        if rows[idx].previous_hash != rows[idx - 1].current_hash:
            broken_at = rows[idx].id
            break
    return {
        "integrity_ok": broken_at is None,
        "total_records": len(rows),
        "broken_at_id": broken_at,
    }


@app.post("/versioning/rollback/{entity_name}/{entity_id}/{version_id}")
def rollback_entity(
    entity_name: str,
    entity_id: str,
    version_id: int,
    x_org_id: str = Header(..., alias="X-Org-ID"),
    authorization: str | None = Header(None),
    db: Session = Depends(get_db),
):
    user = _get_current_user(db, authorization)
    membership = _require_membership(db, user.id, x_org_id)
    _require_admin_or_approver(db, membership)

    snap = db.scalar(
        select(EntitySnapshot).where(
            EntitySnapshot.entity_name == entity_name,
            EntitySnapshot.entity_id == entity_id,
            EntitySnapshot.version_id == version_id,
        )
    )
    if not snap:
        raise AppError(404, "Snapshot version not found")

    if entity_name == "Organization":
        org = db.get(Organization, entity_id)
        if not org or org.id != x_org_id:
            raise AppError(404, "Organization not found")
        org.credit_balance = Decimal(str(snap.data_json["credit_balance"]))
        org.version_id += 1
    elif entity_name == "WorkflowInstance":
        wf = db.get(WorkflowInstance, entity_id)
        if not wf or wf.organization_id != x_org_id:
            raise AppError(404, "Workflow not found")
        wf.status = snap.data_json["status"]
        wf.version_id += 1
    else:
        raise AppError(400, "Unsupported entity for rollback")

    log_audit(db, "ROLLBACK", entity_name, entity_id, f"Rollback to version {version_id}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"rolled_back": True, "entity_name": entity_name, "entity_id": entity_id, "target_version": version_id}
