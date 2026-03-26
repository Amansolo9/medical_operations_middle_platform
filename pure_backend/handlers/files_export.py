import hashlib
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Header, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pure_backend.core.config import get_settings
from pure_backend.core.errors import AppError
from pure_backend.core.security import decrypt_value
from pure_backend.db.models import ExportTask, MetricRecord, OrgMembership, Organization, StoredFile, User, WorkflowInstance
from pure_backend.db.session import get_db
from pure_backend.deps import (
    ALLOWED_FILE_TYPES,
    EXPORT_FIELD_WHITELIST,
    MAX_FILE_SIZE,
    authorize_action_or_403,
    desensitize_by_role,
    get_current_user_or_401,
    membership_role_or_403,
    require_membership_or_403,
)
from pure_backend.schemas import ExportCreateReq
from pure_backend.services.audit import log_audit

router = APIRouter()
settings = get_settings()


@router.post("/files/upload")
async def upload_file(file: UploadFile = File(...), x_org_id: str = Header(..., alias="X-Org-ID"), x_business_type: str = Header(..., alias="X-Business-Type"), x_business_id: str = Header(..., alias="X-Business-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
    if file.content_type not in ALLOWED_FILE_TYPES:
        raise AppError(400, "Unsupported file type")
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise AppError(400, "File exceeds 20MB limit")
    sha256_hash = hashlib.sha256(content).hexdigest()
    existing = db.scalar(select(StoredFile).where(StoredFile.sha256_hash == sha256_hash, StoredFile.organization_id == x_org_id, StoredFile.business_type == x_business_type, StoredFile.business_id == x_business_id))
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


@router.get("/files/{file_id}")
def get_file_metadata(file_id: int, business_type: str = Query(...), business_id: str = Query(...), x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
    file_row = db.get(StoredFile, file_id)
    if not file_row or file_row.organization_id != x_org_id or file_row.business_type != business_type or file_row.business_id != business_id:
        raise AppError(404, "File not found")
    return {"id": file_row.id, "filename": file_row.filename, "content_type": file_row.content_type, "file_size": file_row.file_size, "sha256": file_row.sha256_hash, "business_type": file_row.business_type, "business_id": file_row.business_id}


@router.get("/export/domain")
def export_domain(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    if role not in {"auditor", "administrator", "export", "admin"}:
        raise AppError(403, "General user cannot access export domain")
    org = db.get(Organization, x_org_id)
    metrics_count = db.scalar(select(func.count(MetricRecord.id)).where(MetricRecord.organization_id == x_org_id))
    workflows_count = db.scalar(select(func.count(WorkflowInstance.id)).where(WorkflowInstance.organization_id == x_org_id))
    return {"organization": {"id": org.id, "name": org.name, "credit_balance": float(org.credit_balance)}, "counts": {"metrics": metrics_count, "workflows": workflows_count}}


@router.post("/export/tasks")
def create_export_task(payload: ExportCreateReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    authorize_action_or_403(db, role, "EXPORT", "CREATE")

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
                row[field] = desensitize_by_role(role, "id_number", decrypt_value(member_user.encrypted_id_number, settings.app_secret))
            elif field == "contact":
                contact = decrypt_value(member_user.encrypted_contact, settings.app_secret) if member_user.encrypted_contact else ""
                row[field] = desensitize_by_role(role, "contact", contact)
            elif field == "organization_name":
                row[field] = org.name
            elif field == "credit_balance":
                row[field] = float(org.credit_balance)
        rows.append(row)

    task = ExportTask(organization_id=x_org_id, requested_by=user.id, fields_json=payload.fields, status="DONE", result_json={"rows": rows, "row_count": len(rows)})
    db.add(task)
    db.flush()
    log_audit(db, "EXPORT_TASK_CREATED", "ExportTask", task.id, f"Export fields: {payload.fields}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"task_id": task.id, "status": task.status, "row_count": len(rows)}


@router.get("/export/tasks/{task_id}")
def get_export_task(task_id: str, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    authorize_action_or_403(db, role, "EXPORT", "READ")
    task = db.get(ExportTask, task_id)
    if not task or task.organization_id != x_org_id:
        raise AppError(404, "Export task not found")
    return {"task_id": task.id, "organization_id": task.organization_id, "requested_by": task.requested_by, "fields": task.fields_json, "status": task.status, "result": task.result_json}
