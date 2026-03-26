# API Specification

Base URL: `http://localhost:8000`

Transport security:

- When `ENVIRONMENT != test`, requests must use HTTPS transport, or include trusted proxy header `X-Forwarded-Proto: https`.
- Plain HTTP in non-test environments is rejected with `400` and error contract payload.

## Health

- `GET /health`

## Authentication

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/logout`
- `POST /auth/password-recovery/request`
- `POST /auth/password-recovery/reset`

Password policy: at least 8 chars, must include letters and numbers.

Registration policy:

- Existing organization registration requires valid `organization_code` and only allows `role=general`.
- Privileged roles for existing organizations are blocked (`403`) and require controlled onboarding.
- New organization bootstrap registration remains supported.

## Organization

- `POST /organizations/create`
  - Auth required
  - Creates organization and auto-adds creator as administrator
- `POST /organizations/join`
  - Auth required
  - Join by organization code

## Workflows

- `POST /workflows`
  - Headers: `Authorization`, `X-Org-ID`
  - Idempotent by `(organization_id, business_number)` in 24h window
- `POST /workflows/{instance_id}/decision`
  - Headers: `Authorization`, `X-Org-ID`
  - Supports `APPROVE`/`REJECT`
  - Applies parallel-approval threshold
- `POST /workflows/{instance_id}/reminder`
  - Reviewer/Administrator only
  - Schedules SLA reminder metadata and audits action

## Credit Ledger

- `GET /organizations/{org_id}/credit-ledger`

## Metrics

- `POST /metrics/ingest`
  - Headers: `Authorization`, `X-Org-ID`
  - Validates missing/duplicate/out-of-bounds
- `POST /metrics/import-batch`
  - Quality writeback per item (`SUCCESS` / `FAILED`) with reason

## File Upload

- `POST /files/upload`
  - Headers: `Authorization`, `X-Org-ID`
  - Multipart file
  - Max 20MB
  - Allowed formats: `text/csv`, `application/json`

## Operations

- `GET /operations/dashboard`
- `GET /operations/search`
  - Query: `metric_type`, `appointment_id`, `patient_id`, `doctor_id`, `activity_type`, `min_message_reach`, `max_message_reach`, `start_time`, `end_time`, `min_value`, `max_value`, `page`, `page_size`
- `GET /operations/report`
- `GET /operations/anomalies/attendance`
  - Flags attendance records above threshold (default 12h)
- `GET /operations/work-orders/sla`
  - Aggregated work-order SLA metrics (`metric_type=work_order_sla`)

## Export & Governance

- `GET /export/domain`
  - Auditor/Administrator role access
- `POST /export/tasks`
  - Field whitelist enforced
  - Sensitive fields desensitized
- `GET /export/tasks/{task_id}`
  - Trace export details and result snapshot
- `POST /governance/backup`
- `POST /governance/archive`
- `POST /governance/retention/run`
- `GET /governance/policy`
  - Returns governance metadata: daily backup schedule (`00:00` UTC), retention days (`30`), and scheduler retry ceiling (`3`).
  - Clarifies policy metadata vs manual execution endpoints.
- `GET /governance/backup/{task_id}/verify`
  - Verifies generated backup/archive artifact checksum
- `POST /governance/scheduler/{task_name}/run`
  - Retry ceiling: 3 attempts (returns 409 after exceeded)
- `GET /governance/audit/integrity`
  - Verifies audit hash-chain continuity
- `GET /governance/lineage`
- `GET /governance/dictionary`

## Versioning Rollback

- `POST /versioning/rollback/{entity_name}/{entity_id}/{version_id}`
  - Headers: `Authorization`, `X-Org-ID`
  - Supported entities: `Organization`, `WorkflowInstance`

## Workflow Task Assignment

- `POST /workflows/{instance_id}/assign`
  - Headers: `Authorization`, `X-Org-ID`
  - Assigns workflow task to a specific org member
- `POST /tasks/{assignment_id}/claim`
  - Headers: `Authorization`, `X-Org-ID`
  - Assignee claims assigned task
- `POST /workflows/{instance_id}/allocate`
  - Headers: `Authorization`, `X-Org-ID`
  - Allocation stage after workflow approval

## Error Contract

All API errors return:

```json
{"code": 400, "msg": "Detailed error message"}
```

Standard status usage: `400`, `401`, `403`, `404`, `409`.
