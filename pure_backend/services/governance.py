import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from pure_backend.db.models import BackupArchiveTask, MetricRecord, WorkflowInstance


def _write_snapshot_file(path: Path, payload: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_backup_artifact(db: Session, organization_id: str) -> tuple[str, str]:
    workflow_count = db.query(WorkflowInstance).filter(WorkflowInstance.organization_id == organization_id).count()
    metric_count = db.query(MetricRecord).filter(MetricRecord.organization_id == organization_id).count()
    payload = f"organization_id={organization_id}\nworkflow_count={workflow_count}\nmetric_count={metric_count}\n"
    file_path = Path("pure_backend/storage/backups") / f"backup_{organization_id}.txt"
    checksum = _write_snapshot_file(file_path, payload)
    return str(file_path), checksum


def create_archive_artifact(db: Session, organization_id: str) -> tuple[str, str]:
    workflow_count = db.query(WorkflowInstance).filter(WorkflowInstance.organization_id == organization_id).count()
    payload = f"organization_id={organization_id}\nworkflow_count={workflow_count}\narchive=true\n"
    file_path = Path("pure_backend/storage/archives") / f"archive_{organization_id}.txt"
    checksum = _write_snapshot_file(file_path, payload)
    return str(file_path), checksum


def verify_artifact(path_str: str, checksum: str) -> bool:
    path = Path(path_str)
    if not path.exists():
        return False
    current = hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    return current == checksum


def task_detail_payload(path_str: str, checksum: str) -> str:
    return f"artifact_path={path_str};checksum={checksum}"


def parse_task_detail(detail: str) -> tuple[str, str]:
    parts = {}
    for part in detail.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            parts[k] = v
    return parts.get("artifact_path", ""), parts.get("checksum", "")


def verify_task_artifact(task: BackupArchiveTask) -> bool:
    path, checksum = parse_task_detail(task.detail)
    if not path or not checksum:
        return False
    return verify_artifact(path, checksum)
