from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pure_backend.core.errors import AppError
from pure_backend.db.models import ImportBatch, ImportBatchDetail, MetricRecord, WorkflowInstance
from pure_backend.db.session import get_db
from pure_backend.deps import get_current_user_or_401, require_membership_or_403
from pure_backend.schemas import ImportBatchReq, MetricIngestReq
from pure_backend.services.audit import log_audit
from pure_backend.services.metrics_logic import validate_metric_item

router = APIRouter()


@router.post("/metrics/ingest")
def ingest_metrics(payload: MetricIngestReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
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


@router.post("/metrics/import-batch")
def import_metrics_batch(payload: ImportBatchReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
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
        db.add(MetricRecord(organization_id=x_org_id, metric_type=item["metric_type"], metric_value=item["metric_value"], source_key=item["source_key"], appointment_id=item.get("appointment_id", ""), patient_id=item.get("patient_id", ""), doctor_id=item.get("doctor_id", ""), activity_type=item.get("activity_type", ""), message_reach=float(item.get("message_reach", 0) or 0), recorded_at=datetime.fromisoformat(item["recorded_at"])))
        db.add(ImportBatchDetail(batch_id=batch.id, item_json=item, status="SUCCESS", error_message=""))
        success += 1
    log_audit(db, "IMPORT_BATCH", "ImportBatch", batch.id, f"success={success}, failed={failed}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"batch_id": batch.id, "success": success, "failed": failed}


@router.get("/operations/dashboard")
def operations_dashboard(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
    metrics = db.scalars(select(MetricRecord).where(MetricRecord.organization_id == x_org_id)).all()
    workflows_count = db.scalar(select(func.count(WorkflowInstance.id)).where(WorkflowInstance.organization_id == x_org_id))
    summary = {
        "attendance_total": sum(m.metric_value for m in metrics if m.metric_type == "attendance"),
        "expenses_total": sum(m.metric_value for m in metrics if m.metric_type == "expenses"),
        "work_order_sla_avg": (sum(m.metric_value for m in metrics if m.metric_type == "work_order_sla") / max(1, sum(1 for m in metrics if m.metric_type == "work_order_sla"))) if metrics else 0,
        "sla_avg": (sum(m.metric_value for m in metrics if m.metric_type == "sla") / max(1, sum(1 for m in metrics if m.metric_type == "sla"))) if metrics else 0,
    }
    return {"organization_id": x_org_id, "workflows": workflows_count, "summary": summary}


@router.get("/operations/search")
def operations_search(metric_type: str = Query(...), appointment_id: str | None = Query(None), patient_id: str | None = Query(None), doctor_id: str | None = Query(None), activity_type: str | None = Query(None), min_message_reach: float | None = Query(None), max_message_reach: float | None = Query(None), start_time: str | None = Query(None), end_time: str | None = Query(None), min_value: float | None = Query(None), max_value: float | None = Query(None), page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=200), x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
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


@router.get("/operations/report")
def operations_report(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
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


@router.get("/operations/anomalies/attendance")
def attendance_anomalies(threshold_hours: float = Query(12, gt=0), x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
    rows = db.scalars(select(MetricRecord).where(MetricRecord.organization_id == x_org_id, MetricRecord.metric_type == "attendance", MetricRecord.metric_value > threshold_hours)).all()
    return {"threshold_hours": threshold_hours, "count": len(rows), "items": [{"id": row.id, "metric_value": row.metric_value, "source_key": row.source_key, "patient_id": row.patient_id, "doctor_id": row.doctor_id, "recorded_at": row.recorded_at.isoformat()} for row in rows]}


@router.get("/operations/work-orders/sla")
def work_order_sla_report(x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, x_org_id)
    rows = db.scalars(select(MetricRecord).where(MetricRecord.organization_id == x_org_id, MetricRecord.metric_type == "work_order_sla")).all()
    avg = sum(r.metric_value for r in rows) / max(1, len(rows))
    return {"count": len(rows), "avg_sla": avg, "items": [{"id": row.id, "metric_value": row.metric_value, "source_key": row.source_key, "appointment_id": row.appointment_id, "recorded_at": row.recorded_at.isoformat()} for row in rows]}
