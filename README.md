# Medical Operations Middle Platform

## One-command startup

```bash
docker compose up --build
```

After startup:

- API DOCS: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

Note: Default `docker-compose.yml` is production-oriented (`ENFORCE_HTTPS=true`).
For local HTTP demo, use the override file below.

Local demo command example:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up --build
```

## Required repository structure

```text
/
├── pure_backend/
├── unit_tests/
├── API_tests/
├── run_tests.sh
├── docker-compose.yml
├── Dockerfile
├── README.md
└── docs/
    ├── design.md
    └── api-spec.md
```

## Key implementation points

- Real PostgreSQL persistence with SQLAlchemy.
- Multi-tenant isolation by organization membership (`X-Org-ID`).
- AES encryption for sensitive ID numbers using `APP_SECRET`.
- Login risk control lockout policy.
- Auth lifecycle includes login, logout, and password recovery/reset.
- Organization lifecycle includes explicit create/join APIs.
- Parallel workflow approvals with SLA timeout.
- Workflow reminder endpoint for SLA governance.
- Credit change workflows write `CreditLedger` and update org balance transactionally.
- Metrics sink with missing/duplicate/out-of-bounds validation.
- Operations dashboard/search/report endpoints with pagination and filters.
- Export governance with whitelist + desensitization + traceable export tasks.
- Governance backup/archive/scheduler retry (max 3), lineage and data dictionary endpoints.
- Transport policy is safe-by-default: non-test environments require HTTPS or trusted `X-Forwarded-Proto=https`.
- Existing-organization self-registration is restricted to `general`; privileged roles require controlled onboarding.
- Snapshot versioning and rollback for core entities.
- File upload validation and SHA-256 deduplication.
- Unified error contract: `{"code": <int>, "msg": "<detail>"}`.

## Security behavior

- HTTPS enforcement: when `ENVIRONMENT != test`, plain HTTP is rejected with `400` unless `X-Forwarded-Proto: https` is present.
- Test runs (`ENVIRONMENT=test`) keep local `TestClient` HTTP flow working for API tests.
- Unhandled exceptions are logged in structured form (`event=unhandled_exception`, request metadata, exception type) and responses stay sanitized as `{"code": 500, "msg": "Internal server error"}`.

## Registration behavior

- New organization bootstrap keeps role selection behavior (for example first user can be `administrator`).
- Existing organization self-registration requires a valid organization code and only permits `general` role.
- Privileged roles (`administrator`, `reviewer`, `auditor`, etc.) must use a controlled onboarding path.

## Governance scheduling behavior

- Backup scheduling policy is modeled as daily at `00:00` UTC with 30-day retention metadata.
- In this codebase, backup/archive/retention execution remains manual via endpoints (`/governance/backup`, `/governance/archive`, `/governance/retention/run`).
- Scheduler retry compensation is capped at 3 retries and enforced by `/governance/scheduler/{task_name}/run`.

## Run tests

```bash
sh run_tests.sh
```
