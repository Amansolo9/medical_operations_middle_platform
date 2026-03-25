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
- Snapshot versioning and rollback for core entities.
- File upload validation and SHA-256 deduplication.
- Unified error contract: `{"code": <int>, "msg": "<detail>"}`.

## Run tests

```bash
sh run_tests.sh
```
