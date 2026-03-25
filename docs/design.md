# Architecture and Workflow Design

## Overview

This platform implements a FastAPI-based middle layer for medical operations and process governance, with PostgreSQL persistence and SQLAlchemy ORM.

## Domain-Driven Modules

1. **Identity & Multi-Tenancy**
   - `User`, `Organization`, `Role`, `OrgMembership`, `SessionToken`, `LoginAttempt`
   - Organization isolation is enforced with `X-Org-ID` and membership checks.
   - Includes organization create/join APIs.
   - Includes logout and password recovery/reset flows.
   - Password policy: alphanumeric and at least 8 characters.
   - Login risk control: 5 failed attempts in 10 minutes triggers lockout behavior.
   - Sensitive ID numbers are encrypted with AES-GCM using `APP_SECRET`.

2. **Process & Workflow**
   - `WorkflowDefinition`, `WorkflowInstance`, `WorkflowApproval`, `IdempotencyKey`
   - Supports `RESOURCE_APPLICATION` and `CREDIT_CHANGE` workflows.
   - Parallel signing via `required_approvals` threshold.
   - Branching-ready config through `branch_rules_json`.
   - Reminder metadata endpoint for SLA pre-deadline notifications.
   - SLA timeout default is 48 hours.
   - Credit change approval updates `Organization.credit_balance` and writes `CreditLedger` in a single DB transaction.

3. **Operations & Governance**
   - `MetricRecord` with sink endpoint and quality checks (missing/duplicate/out-of-bounds).
   - Includes derived attendance anomaly view (`attendance > 12h`) and work-order SLA metric type (`work_order_sla`).
   - Temporal versioning through `EntitySnapshot` and rollback API.
   - Batch import writeback (`ImportBatch`, `ImportBatchDetail`).
   - Export governance with whitelist fields + desensitization + `ExportTask` trace records.
   - Data lineage/dictionary endpoints and governance tasks for backup/archive.
   - Scheduler retry policy enforced at maximum 3 retries.
   - File upload controls: max 20MB, content-type whitelist, SHA-256 dedup.
   - `AuditLog` captures immutable event trail.

## Snapshot Strategy

Core entities store `version_id` and are snapshotted in `EntitySnapshot`. Rollback reads a target snapshot and restores supported entities.

## Startup & Infrastructure

- `docker compose up --build` starts PostgreSQL and FastAPI.
- `scripts/wait_for_db.py` blocks app startup until DB is reachable.

## Migration Notes

- Current project uses SQLAlchemy `create_all` for schema bootstrap.
- Production migration recommendation: add Alembic migrations that explicitly create:
  - status check constraints (`ck_workflow_instance_status`, `ck_export_task_status`, `ck_backup_archive_status`, `ck_scheduler_task_status`)
  - performance indexes (`ix_login_attempts_attempted_at`, `ix_workflow_instances_deadline_at`, `ix_workflow_instances_created_at`, `ix_metric_records_recorded_at`, `ix_metric_records_created_at`, `ix_audit_logs_created_at`)
- Apply migrations before app rollout to ensure DB-level validation and query performance consistency.

## Security & Compliance

- Sensitive user fields are encrypted by AES-GCM with `APP_SECRET`.
- HTTPS policy middleware enforces secure transport in production (`ENFORCE_HTTPS=true`).
- Local demo can run HTTP by overriding env (`ENFORCE_HTTPS=false`) before startup.
- Audit logs use a chained hash (`previous_hash` -> `current_hash`) for tamper-evident history.
- Additional hardening recommendation: restrict DB account to append-only writes for `audit_logs` using database roles/triggers.
