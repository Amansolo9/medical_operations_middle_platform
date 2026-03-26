import hashlib
from datetime import timedelta

from fastapi import APIRouter, Depends, Header
from sqlalchemy import select
from sqlalchemy.orm import Session

from pure_backend.core.errors import AppError
from pure_backend.db.models import AuditLog, BackupArchiveTask, DataDictionary, DataLineage, SchedulerTask
from pure_backend.db.session import get_db
from pure_backend.deps import (
    ROLE_ADMIN,
    ROLE_AUDITOR,
    get_current_user_or_401,
    membership_role_or_403,
    now_utc,
    require_membership_or_403,
    require_role_or_403,
)
from pure_backend.schemas import SchedulerRunReq
from pure_backend.services.audit import log_audit
from pure_backend.services.governance import create_archive_artifact, create_backup_artifact, task_detail_payload, verify_task_artifact

router = APIRouter()

BACKUP_SCHEDULE_FREQUENCY = "daily"
BACKUP_SCHEDULE_TIME_UTC = "00:00"
BACKUP_RETENTION_DAYS = 30
SCHEDULER_RETRY_CEILING = 3


def _backup_retention_deadline(scheduled_for):
    return scheduled_for + timedelta(days=BACKUP_RETENTION_DAYS)


def _governance_policy_payload() -> dict:
    return {
        "backup": {
            "frequency": BACKUP_SCHEDULE_FREQUENCY,
            "time_utc": BACKUP_SCHEDULE_TIME_UTC,
            "retention_days": BACKUP_RETENTION_DAYS,
            "execution_mode": "manual_endpoint",
        },
        "scheduler": {
            "retry_compensation": True,
            "max_retries": SCHEDULER_RETRY_CEILING,
            "execution_mode": "manual_run",
        },
    }


@router.post("/governance/backup")
def create_backup_task(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    require_role_or_403(role, {ROLE_ADMIN, ROLE_AUDITOR})
    artifact_path, checksum = create_backup_artifact(db, x_org_id)
    scheduled_for = now_utc()
    task = BackupArchiveTask(
        organization_id=x_org_id,
        task_type="BACKUP",
        status="DONE",
        detail=task_detail_payload(artifact_path, checksum),
        scheduled_for=scheduled_for,
        retained_until=_backup_retention_deadline(scheduled_for),
    )
    db.add(task)
    log_audit(db, "BACKUP_TASK", "BackupArchiveTask", str(task.id), "Backup task created", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"task_type": task.task_type, "status": task.status}


@router.post("/governance/archive")
def create_archive_task(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    require_role_or_403(role, {ROLE_ADMIN, ROLE_AUDITOR})
    artifact_path, checksum = create_archive_artifact(db, x_org_id)
    scheduled_for = now_utc()
    task = BackupArchiveTask(
        organization_id=x_org_id,
        task_type="ARCHIVE",
        status="DONE",
        detail=task_detail_payload(artifact_path, checksum),
        scheduled_for=scheduled_for,
        retained_until=_backup_retention_deadline(scheduled_for),
    )
    db.add(task)
    log_audit(db, "ARCHIVE_TASK", "BackupArchiveTask", str(task.id), "Archive task created", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"task_type": task.task_type, "status": task.status}


@router.get("/governance/policy")
def get_governance_policy(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
    return _governance_policy_payload()


@router.post("/governance/scheduler/{task_name}/run")
def run_scheduler_task(task_name: str, payload: SchedulerRunReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    require_role_or_403(role, {ROLE_ADMIN, ROLE_AUDITOR})
    task = db.scalar(select(SchedulerTask).where(SchedulerTask.name == task_name))
    if not task:
        task = SchedulerTask(name=task_name, max_retries=SCHEDULER_RETRY_CEILING, retry_count=0, status="PENDING", last_error="", updated_at=now_utc())
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


@router.get("/governance/lineage")
def get_data_lineage(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
    rows = db.scalars(select(DataLineage).order_by(DataLineage.id.asc())).all()
    return [{"source_entity": row.source_entity, "target_entity": row.target_entity, "transform_rule": row.transform_rule} for row in rows]


@router.get("/governance/dictionary")
def get_data_dictionary(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
    rows = db.scalars(select(DataDictionary).order_by(DataDictionary.id.asc())).all()
    return [{"domain": row.domain, "field_name": row.field_name, "description": row.description} for row in rows]


@router.post("/governance/retention/run")
def run_retention_enforcement(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    require_role_or_403(role, {ROLE_ADMIN, ROLE_AUDITOR})
    now = now_utc()
    expired = db.scalars(select(BackupArchiveTask).where(BackupArchiveTask.organization_id == x_org_id, BackupArchiveTask.retained_until < now)).all()
    cleaned = 0
    for task in expired:
        task.status = "DONE"
        task.detail = f"retention-enforced cleanup at {now.isoformat()}"
        cleaned += 1
    log_audit(db, "RETENTION_ENFORCED", "BackupArchiveTask", x_org_id, f"cleaned={cleaned}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"cleaned": cleaned}


@router.get("/governance/audit/integrity")
def audit_integrity_check(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    require_role_or_403(role, {ROLE_ADMIN, ROLE_AUDITOR, "admin"})
    rows = db.scalars(select(AuditLog).where(AuditLog.organization_id == x_org_id).order_by(AuditLog.id.asc())).all()
    broken_at: int | None = None
    for row in rows:
        payload = f"{row.previous_hash}|{row.event_type}|{row.entity_name}|{row.entity_id}|{row.message}|{row.actor_user_id or ''}|{row.organization_id or ''}"
        recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if recomputed != row.current_hash:
            broken_at = row.id
            break
    return {"integrity_ok": broken_at is None, "total_records": len(rows), "broken_at_id": broken_at}


@router.get("/governance/backup/{task_id}/verify")
def verify_backup_or_archive_artifact(task_id: int, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    require_role_or_403(role, {ROLE_ADMIN, ROLE_AUDITOR, "admin"})
    task = db.get(BackupArchiveTask, task_id)
    if not task or task.organization_id != x_org_id:
        raise AppError(404, "Backup/archive task not found")
    ok = verify_task_artifact(task)
    return {"task_id": task_id, "verified": ok}
