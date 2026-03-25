import logging
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from pure_backend.db.models import AuditLog

logger = logging.getLogger("audit")


def log_audit(
    db: Session,
    event_type: str,
    entity_name: str,
    entity_id: str,
    message: str,
    actor_user_id: str | None = None,
    organization_id: str | None = None,
) -> None:
    entity_id_value = entity_id or ""
    logger.info("%s | %s | %s | %s", event_type, entity_name, entity_id, message)
    session_last_hash = db.info.get("last_audit_hash", "")
    if session_last_hash:
        previous_hash = session_last_hash
    else:
        previous = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
        previous_hash = previous.current_hash if previous else ""
    payload = f"{previous_hash}|{event_type}|{entity_name}|{entity_id_value}|{message}|{actor_user_id or ''}|{organization_id or ''}"
    current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    db.add(
        AuditLog(
            event_type=event_type,
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            entity_name=entity_name,
            entity_id=entity_id_value,
            message=message,
            previous_hash=previous_hash,
            current_hash=current_hash,
        )
    )
    db.info["last_audit_hash"] = current_hash
