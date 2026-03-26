from datetime import timedelta
from decimal import Decimal

from fastapi import APIRouter, Depends, Header
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pure_backend.core.errors import AppError
from pure_backend.db.models import (
    CreditLedger,
    IdempotencyKey,
    OrgMembership,
    Organization,
    WorkflowAllocation,
    WorkflowApproval,
    WorkflowDefinition,
    WorkflowInstance,
)
from pure_backend.db.session import get_db
from pure_backend.deps import (
    get_current_user_or_401,
    membership_role_or_403,
    now_utc,
    require_admin_or_approver_or_403,
    require_membership_or_403,
    snapshot_entity,
    authorize_action_or_403,
)
from pure_backend.schemas import AssignTaskReq, ClaimTaskReq, WorkflowAllocateReq, WorkflowCreateReq, WorkflowDecisionReq, WorkflowReminderReq
from pure_backend.services.audit import log_audit
from pure_backend.services.workflow_logic import can_transition
from pure_backend.db.models import TaskAssignment, EntitySnapshot

router = APIRouter()


@router.post("/workflows")
def create_workflow(payload: WorkflowCreateReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    authorize_action_or_403(db, role, "WORKFLOW", "CREATE")

    existing = db.scalar(select(IdempotencyKey).where(IdempotencyKey.organization_id == x_org_id, IdempotencyKey.business_number == payload.business_number))
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
    snapshot_entity(db, "WorkflowInstance", instance.id, instance.version_id, {"status": instance.status, "payload": instance.payload_json})

    response = {"workflow_instance_id": instance.id, "status": instance.status}
    row = db.scalar(select(IdempotencyKey).where(IdempotencyKey.organization_id == x_org_id, IdempotencyKey.business_number == payload.business_number))
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
        raced = db.scalar(select(IdempotencyKey).where(IdempotencyKey.organization_id == x_org_id, IdempotencyKey.business_number == payload.business_number))
        if raced and raced.created_at >= now_utc() - timedelta(hours=24):
            return {"idempotent": True, "result": raced.response_json}
        raise AppError(409, "Duplicate workflow submission conflict")
    return response


@router.post("/workflows/{instance_id}/decision")
def decision_workflow(instance_id: str, payload: WorkflowDecisionReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    require_admin_or_approver_or_403(db, membership)

    instance = db.get(WorkflowInstance, instance_id)
    if not instance or instance.organization_id != x_org_id:
        raise AppError(404, "Workflow instance not found")

    if instance.deadline_at < now_utc() and instance.status == "PENDING":
        if can_transition(instance.status, "TIMED_OUT"):
            instance.status = "TIMED_OUT"
            instance.version_id += 1
            snapshot_entity(db, "WorkflowInstance", instance.id, instance.version_id, {"status": instance.status})
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
            snapshot_entity(db, "WorkflowInstance", instance.id, instance.version_id, {"status": instance.status})
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

    approvals = db.scalar(select(func.count(WorkflowApproval.id)).where(WorkflowApproval.instance_id == instance.id, WorkflowApproval.decision == "APPROVE"))
    if approvals >= required_approvals:
        if can_transition(instance.status, "APPROVED"):
            instance.status = "APPROVED"
            instance.version_id += 1
            snapshot_entity(db, "WorkflowInstance", instance.id, instance.version_id, {"status": instance.status})

            if definition.code == "CREDIT_CHANGE":
                amount = Decimal(str(instance.payload_json.get("amount", 0)))
                reason = instance.payload_json.get("reason", "Credit change")
                org = db.get(Organization, instance.organization_id)
                before = Decimal(str(org.credit_balance))
                after = before + amount
                org.credit_balance = after
                org.version_id += 1
                snapshot_entity(db, "Organization", org.id, org.version_id, {"credit_balance": str(after), "name": org.name})
                db.add(CreditLedger(organization_id=org.id, workflow_instance_id=instance.id, amount=amount, balance_before=before, balance_after=after, reason=reason))
                log_audit(db, "CREDIT_LEDGER_APPLIED", "Organization", org.id, f"Credit balance changed by {amount}", actor_user_id=user.id, organization_id=org.id)

            log_audit(db, "WORKFLOW_APPROVED", "WorkflowInstance", instance.id, "Workflow approved", actor_user_id=user.id, organization_id=x_org_id)
            db.commit()
            return {"status": instance.status}

    log_audit(db, "WORKFLOW_PARTIAL_APPROVAL", "WorkflowInstance", instance.id, f"Approval progress {approvals}/{required_approvals} (risk={risk_level})", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"status": instance.status}


@router.post("/workflows/{instance_id}/reminder")
def create_workflow_reminder(instance_id: str, payload: WorkflowReminderReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    require_admin_or_approver_or_403(db, membership)
    wf = db.get(WorkflowInstance, instance_id)
    if not wf or wf.organization_id != x_org_id:
        raise AppError(404, "Workflow instance not found")
    if wf.status != "PENDING":
        raise AppError(400, "Workflow is not pending")
    if wf.deadline_at < now_utc():
        raise AppError(400, "Workflow already timed out")
    remind_at = wf.deadline_at - timedelta(minutes=payload.before_minutes)
    log_audit(db, "WORKFLOW_REMINDER_CREATED", "WorkflowInstance", wf.id, f"Reminder scheduled at {remind_at.isoformat()}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"workflow_instance_id": wf.id, "remind_at": remind_at.isoformat()}


@router.get("/organizations/{org_id}/credit-ledger")
def get_credit_ledger(org_id: str, authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    require_membership_or_403(db, user.id, org_id)
    rows = db.scalars(select(CreditLedger).where(CreditLedger.organization_id == org_id).order_by(CreditLedger.id.desc())).all()
    return [{"id": r.id, "amount": float(r.amount), "balance_before": float(r.balance_before), "balance_after": float(r.balance_after), "reason": r.reason, "created_at": r.created_at.isoformat()} for r in rows]


@router.post("/workflows/{instance_id}/assign")
def assign_workflow_task(instance_id: str, payload: AssignTaskReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    authorize_action_or_403(db, role, "WORKFLOW", "ASSIGN")

    wf = db.get(WorkflowInstance, instance_id)
    if not wf or wf.organization_id != x_org_id:
        raise AppError(404, "Workflow instance not found")
    assignee_membership = db.scalar(select(OrgMembership).where(OrgMembership.user_id == payload.assign_to_user_id, OrgMembership.organization_id == x_org_id))
    if not assignee_membership:
        raise AppError(404, "Assignee not found in organization")

    assignment = TaskAssignment(organization_id=x_org_id, workflow_instance_id=instance_id, assigned_to_user_id=payload.assign_to_user_id, assigned_by_user_id=user.id, status="PENDING", note=payload.note)
    db.add(assignment)
    db.flush()
    log_audit(db, "TASK_ASSIGNED", "TaskAssignment", assignment.id, f"Assigned workflow task to user {payload.assign_to_user_id}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"assignment_id": assignment.id, "status": assignment.status}


@router.post("/tasks/{assignment_id}/claim")
def claim_task(assignment_id: str, payload: ClaimTaskReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    authorize_action_or_403(db, role, "WORKFLOW", "CLAIM")

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


@router.post("/workflows/{instance_id}/allocate")
def allocate_workflow(instance_id: str, payload: WorkflowAllocateReq, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    role = membership_role_or_403(db, membership)
    authorize_action_or_403(db, role, "WORKFLOW", "ASSIGN")

    wf = db.get(WorkflowInstance, instance_id)
    if not wf or wf.organization_id != x_org_id:
        raise AppError(404, "Workflow instance not found")
    if wf.status != "APPROVED":
        raise AppError(400, "Workflow must be approved before allocation")

    assignee_membership = db.scalar(select(OrgMembership).where(OrgMembership.user_id == payload.allocate_to_user_id, OrgMembership.organization_id == x_org_id))
    if not assignee_membership:
        raise AppError(404, "Allocation target not found in organization")

    existing = db.scalar(select(WorkflowAllocation).where(WorkflowAllocation.workflow_instance_id == instance_id))
    if existing:
        existing.allocated_to_user_id = payload.allocate_to_user_id
        existing.department = payload.department
        existing.note = payload.note
        allocation_id = existing.id
    else:
        allocation = WorkflowAllocation(organization_id=x_org_id, workflow_instance_id=instance_id, allocated_by_user_id=user.id, allocated_to_user_id=payload.allocate_to_user_id, department=payload.department, note=payload.note)
        db.add(allocation)
        db.flush()
        allocation_id = allocation.id
    log_audit(db, "WORKFLOW_ALLOCATED", "WorkflowAllocation", allocation_id, f"Workflow allocated to user {payload.allocate_to_user_id}", actor_user_id=user.id, organization_id=x_org_id)
    db.commit()
    return {"allocation_id": allocation_id, "workflow_instance_id": instance_id, "allocated_to_user_id": payload.allocate_to_user_id}


@router.post("/versioning/rollback/{entity_name}/{entity_id}/{version_id}")
def rollback_entity(entity_name: str, entity_id: str, version_id: int, x_org_id: str = Header(..., alias="X-Org-ID"), authorization: str | None = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_or_401(db, authorization)
    membership = require_membership_or_403(db, user.id, x_org_id)
    require_admin_or_approver_or_403(db, membership)

    snap = db.scalar(select(EntitySnapshot).where(EntitySnapshot.entity_name == entity_name, EntitySnapshot.entity_id == entity_id, EntitySnapshot.version_id == version_id))
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
