import logging
import re
import uuid
from contextlib import asynccontextmanager
from typing import Any, cast

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from pure_backend.core.config import get_settings
from pure_backend.core.errors import AppError
from pure_backend.db.base import Base
from pure_backend.db.models import DataDictionary, DataLineage, PermissionPolicy, Role, WorkflowDefinition
from pure_backend.db.session import engine
from pure_backend.handlers.auth_org import router as auth_org_router
from pure_backend.handlers.files_export import router as files_export_router
from pure_backend.handlers.governance import router as governance_router
from pure_backend.handlers.metrics_ops import router as metrics_ops_router
from pure_backend.handlers.workflows import router as workflows_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
access_logger = logging.getLogger("access")
error_logger = logging.getLogger("error")
settings = get_settings()


def _error_json(code: int, msg: str) -> JSONResponse:
    return JSONResponse(status_code=code, content={"code": code, "msg": msg})


def _sanitize_exception_message(message: str) -> str:
    if not message:
        return ""
    redacted = re.sub(r"(?i)(password|token|secret|authorization|api[_-]?key)\s*[:=]\s*[^,\s;]+", r"\1=<redacted>", message)
    redacted = re.sub(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*", "Bearer <redacted>", redacted)
    return redacted


def _existing_columns(db: Session, table_name: str) -> set[str]:
    inspector = inspect(db.bind)
    try:
        columns = inspector.get_columns(table_name)
    except Exception:
        return set()
    return {col["name"] for col in columns}


def _ensure_schema_compatibility(db: Session) -> None:
    if not settings.enable_runtime_schema_patch:
        return
    dialect = db.bind.dialect.name
    wf_columns = _existing_columns(db, "workflow_definitions")
    user_columns = _existing_columns(db, "users")
    org_columns = _existing_columns(db, "organizations")
    file_columns = _existing_columns(db, "stored_files")
    audit_columns = _existing_columns(db, "audit_logs")
    metric_columns = _existing_columns(db, "metric_records")
    task_columns = _existing_columns(db, "backup_archive_tasks")

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
    if "organization_id" not in task_columns:
        db.execute(text("ALTER TABLE backup_archive_tasks ADD COLUMN organization_id VARCHAR(36) NOT NULL DEFAULT ''"))
    if dialect == "postgresql" and ("code" in org_columns or "code" in _existing_columns(db, "organizations")):
        db.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_organizations_code ON organizations (code)"))
    db.commit()


def _ensure_audit_append_only(db: Session) -> None:
    dialect = db.bind.dialect.name
    if dialect == "postgresql":
        db.execute(text("""CREATE OR REPLACE FUNCTION prevent_audit_log_changes() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; $$ LANGUAGE plpgsql;"""))
        db.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_update') THEN
                        CREATE TRIGGER trg_prevent_audit_update BEFORE UPDATE ON audit_logs FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_delete') THEN
                        CREATE TRIGGER trg_prevent_audit_delete BEFORE DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_changes();
                    END IF;
                END$$;
                """
            )
        )
    else:
        db.execute(text("""CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_update BEFORE UPDATE ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;"""))
        db.execute(text("""CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_delete BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;"""))
    db.commit()


def bootstrap() -> None:
    Base.metadata.create_all(bind=engine)
    with Session(engine) as db:
        _ensure_schema_compatibility(db)
        _ensure_audit_append_only(db)

        for role_name in ["administrator", "reviewer", "general", "auditor", "admin", "approver", "export"]:
            existing = db.scalar(select(Role).where(Role.name == role_name))
            if not existing:
                db.add(Role(name=role_name))

        permission_rows = [
            ("administrator", "EXPORT", "READ"),
            ("administrator", "EXPORT", "CREATE"),
            ("administrator", "WORKFLOW", "ASSIGN"),
            ("administrator", "WORKFLOW", "DECIDE"),
            ("administrator", "WORKFLOW", "ROLLBACK"),
            ("administrator", "WORKFLOW", "CREATE"),
            ("administrator", "GOVERNANCE", "MANAGE"),
            ("reviewer", "WORKFLOW", "DECIDE"),
            ("reviewer", "WORKFLOW", "CLAIM"),
            ("reviewer", "WORKFLOW", "ASSIGN"),
            ("auditor", "EXPORT", "READ"),
            ("auditor", "EXPORT", "CREATE"),
            ("auditor", "GOVERNANCE", "MANAGE"),
            ("general", "WORKFLOW", "CREATE"),
            ("admin", "EXPORT", "READ"),
            ("admin", "EXPORT", "CREATE"),
            ("admin", "WORKFLOW", "ASSIGN"),
            ("admin", "WORKFLOW", "DECIDE"),
            ("admin", "WORKFLOW", "CREATE"),
            ("approver", "WORKFLOW", "DECIDE"),
            ("approver", "WORKFLOW", "CLAIM"),
            ("export", "EXPORT", "READ"),
            ("export", "EXPORT", "CREATE"),
        ]
        for role_name, resource, action in permission_rows:
            exists = db.scalar(select(PermissionPolicy).where(PermissionPolicy.role_name == role_name, PermissionPolicy.resource == resource, PermissionPolicy.action == action))
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
                        branch_rules_json={"HIGH_RISK": {"required_approvals": 2}, "LOW_RISK": {"required_approvals": 1}},
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


@app.exception_handler(AppError)
def handle_app_error(_, exc: AppError):
    return _error_json(exc.code, exc.msg)


@app.exception_handler(RequestValidationError)
def handle_validation_error(_, exc: RequestValidationError):
    return _error_json(400, str(exc))


@app.exception_handler(Exception)
def handle_unexpected_error(request: Request, exc: Exception):
    request_id = request.headers.get("X-Request-ID", "")
    error_logger.error(
        "event=unhandled_exception request_id=%s method=%s path=%s exception_type=%s message=%s",
        request_id,
        request.method,
        request.url.path,
        type(exc).__name__,
        _sanitize_exception_message(str(exc)),
    )
    return _error_json(500, "Internal server error")


@app.exception_handler(HTTPException)
def handle_http_exception(_, exc: HTTPException):
    if isinstance(exc.detail, dict) and "code" in exc.detail and "msg" in exc.detail:
        detail = cast(dict[str, Any], exc.detail)
        code = int(detail.get("code", exc.status_code))
        msg = str(detail.get("msg", "Error"))
        return _error_json(code, msg)
    return _error_json(exc.status_code, str(exc.detail))


@app.middleware("http")
async def https_only_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    if settings.environment != "test" and settings.enforce_https:
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        if request.url.scheme != "https" and forwarded_proto != "https":
            return _error_json(400, "HTTPS is required")
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    access_logger.info("request_id=%s method=%s path=%s status=%s", request_id, request.method, request.url.path, response.status_code)
    return response


app.include_router(auth_org_router)
app.include_router(workflows_router)
app.include_router(metrics_ops_router)
app.include_router(files_export_router)
app.include_router(governance_router)
