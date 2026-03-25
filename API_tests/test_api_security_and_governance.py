import os
from io import BytesIO

os.environ["DATABASE_URL"] = "sqlite:///./api_test.db"
os.environ["ENVIRONMENT"] = "test"
os.environ["ENFORCE_HTTPS"] = "false"
if os.path.exists("api_test.db"):
    os.remove("api_test.db")

from fastapi.testclient import TestClient
import pytest

from pure_backend.main import app


@pytest.fixture(scope="session", autouse=True)
def fresh_database():
    if os.path.exists("api_test.db"):
        os.remove("api_test.db")
    yield
    if os.path.exists("api_test.db"):
        try:
            os.remove("api_test.db")
        except OSError:
            pass


def register_user(client: TestClient, username: str, org: str, role: str = "general", code: str | None = None):
    payload = {
        "username": username,
        "password": "abc12345",
        "id_number": f"ID-{username}",
        "contact": f"0900{username[-2:]}",
        "organization_name": org,
        "role": role,
    }
    if code:
        payload["organization_code"] = code
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 200
    return response.json()


def login_user(client: TestClient, username: str, password: str = "abc12345") -> str:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def auth_headers(token: str, org_id: str) -> dict:
    return {"Authorization": f"Bearer {token}", "X-Org-ID": org_id}


def test_auth_logout_and_recovery_flow():
    with TestClient(app) as client:
        user = register_user(client, "recover_user", "OrgRecover", "general", code="ORGREC")
        token = login_user(client, "recover_user")

        logout = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"}, json={"token": token})
        assert logout.status_code == 200

        protected = client.post(
            "/workflows",
            headers=auth_headers(token, user["organization_id"]),
            json={
                "business_number": "REC-1",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {},
                "idempotency_key": "ikey-rec-1",
            },
        )
        assert protected.status_code == 401

        req = client.post("/auth/password-recovery/request", json={"username": "recover_user"})
        assert req.status_code == 200
        recovery_token = req.json()["recovery_token"]

        reset = client.post(
            "/auth/password-recovery/reset",
            json={"username": "recover_user", "token": recovery_token, "new_password": "newpass123"},
        )
        assert reset.status_code == 200

        relogin = client.post("/auth/login", json={"username": "recover_user", "password": "newpass123"})
        assert relogin.status_code == 200


def test_password_recovery_token_hidden_outside_test_env():
    from pure_backend import main as main_module

    previous = main_module.settings.environment
    try:
        main_module.settings.environment = "production"
        with TestClient(app) as client:
            register_user(client, "recover_hidden", "OrgRecoverHidden", "general", code="ORGRECH")
            req = client.post("/auth/password-recovery/request", json={"username": "recover_hidden"})
            assert req.status_code == 200
            assert req.json()["recovery_token"] is None
    finally:
        main_module.settings.environment = previous


def test_org_join_blocks_role_escalation():
    with TestClient(app) as client:
        register_user(client, "owner_join", "OrgJoin", "administrator", code="ORGJOIN")
        register_user(client, "candidate_join", "OrgJoin2", "general", code="ORGJOIN2")
        token = login_user(client, "candidate_join")

        denied = client.post(
            "/organizations/join",
            headers={"Authorization": f"Bearer {token}"},
            json={"organization_code": "ORGJOIN", "role": "administrator"},
        )
        assert denied.status_code == 403

        ok = client.post(
            "/organizations/join",
            headers={"Authorization": f"Bearer {token}"},
            json={"organization_code": "ORGJOIN", "role": "general"},
        )
        assert ok.status_code == 200


def test_register_blocks_privileged_role_into_existing_org_without_code():
    with TestClient(app) as client:
        register_user(client, "seed_admin", "VictimOrg", "administrator", code="VIC001")

        bad = client.post(
            "/auth/register",
            json={
                "username": "attacker",
                "password": "abc12345",
                "id_number": "ID-attacker",
                "contact": "09001234",
                "organization_name": "VictimOrg",
                "role": "administrator",
            },
        )
        assert bad.status_code == 403

        ok_general = client.post(
            "/auth/register",
            json={
                "username": "allowed_general",
                "password": "abc12345",
                "id_number": "ID-general",
                "contact": "09004321",
                "organization_name": "VictimOrg",
                "role": "general",
            },
        )
        assert ok_general.status_code == 403


def test_register_into_existing_org_with_valid_code_allows_general():
    with TestClient(app) as client:
        register_user(client, "seed_admin3", "VictimOrg3", "administrator", code="VIC003")
        ok_general = client.post(
            "/auth/register",
            json={
                "username": "existing_general_with_code",
                "password": "abc12345",
                "id_number": "ID-g3",
                "contact": "09009991",
                "organization_name": "VictimOrg3",
                "organization_code": "VIC003",
                "role": "general",
            },
        )
        assert ok_general.status_code == 200


def test_register_privileged_role_requires_matching_org_code():
    with TestClient(app) as client:
        register_user(client, "seed_admin2", "VictimOrg2", "administrator", code="VIC002")

        wrong_code = client.post(
            "/auth/register",
            json={
                "username": "attacker_wrong_code",
                "password": "abc12345",
                "id_number": "ID-wrong",
                "contact": "09000001",
                "organization_name": "VictimOrg2",
                "organization_code": "BAD999",
                "role": "administrator",
            },
        )
        assert wrong_code.status_code == 403

        correct_code = client.post(
            "/auth/register",
            json={
                "username": "attacker_with_code",
                "password": "abc12345",
                "id_number": "ID-right",
                "contact": "09000002",
                "organization_name": "VictimOrg2",
                "organization_code": "VIC002",
                "role": "administrator",
            },
        )
        assert correct_code.status_code == 200


def test_logout_cannot_delete_another_user_token():
    with TestClient(app) as client:
        user1 = register_user(client, "logout_u1", "OrgLogout", "general", code="ORGLOG")
        user2 = register_user(client, "logout_u2", "OrgLogout", "general", code="ORGLOG")
        token1 = login_user(client, "logout_u1")
        token2 = login_user(client, "logout_u2")

        attempt = client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token1}"},
            json={"token": token2},
        )
        assert attempt.status_code == 403

        still_valid = client.post(
            "/workflows",
            headers=auth_headers(token2, user2["organization_id"]),
            json={
                "business_number": "LG-1",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {},
                "idempotency_key": "lg-1",
            },
        )
        assert still_valid.status_code == 200


def test_login_lockout_after_failures():
    with TestClient(app) as client:
        register_user(client, "lock_user", "OrgLock", "general", code="ORGLOCK")
        for _ in range(5):
            bad = client.post("/auth/login", json={"username": "lock_user", "password": "wrong1234"})
            assert bad.status_code == 401
        blocked = client.post("/auth/login", json={"username": "lock_user", "password": "wrong1234"})
        assert blocked.status_code == 403


def test_lockout_requires_consecutive_failures():
    with TestClient(app) as client:
        register_user(client, "lock_seq_user", "OrgLockSeq", "general", code="ORGLSEQ")

        for _ in range(4):
            bad = client.post("/auth/login", json={"username": "lock_seq_user", "password": "wrong1234"})
            assert bad.status_code == 401

        good = client.post("/auth/login", json={"username": "lock_seq_user", "password": "abc12345"})
        assert good.status_code == 200

        bad_after_success = client.post("/auth/login", json={"username": "lock_seq_user", "password": "wrong1234"})
        assert bad_after_success.status_code == 401

        still_not_locked = client.post("/auth/login", json={"username": "lock_seq_user", "password": "abc12345"})
        assert still_not_locked.status_code == 200


def test_idempotency_and_credit_workflow_transaction():
    with TestClient(app) as client:
        admin = register_user(client, "admin1", "OrgCredit", "administrator", code="ORGCREDIT")
        reviewer1 = register_user(client, "reviewer1", "OrgCredit", "reviewer", code="ORGCREDIT")
        reviewer2 = register_user(client, "reviewer2", "OrgCredit", "reviewer", code="ORGCREDIT")
        admin_token = login_user(client, "admin1")
        r1_token = login_user(client, "reviewer1")
        r2_token = login_user(client, "reviewer2")

        create1 = client.post(
            "/workflows",
            headers=auth_headers(admin_token, admin["organization_id"]),
            json={
                "business_number": "CREDIT-BIZ-1",
                "workflow_code": "CREDIT_CHANGE",
                "payload": {"amount": 100, "reason": "Top up", "risk_level": "HIGH_RISK"},
                "idempotency_key": "idemp-1",
            },
        )
        assert create1.status_code == 200
        instance_id = create1.json()["workflow_instance_id"]

        create2 = client.post(
            "/workflows",
            headers=auth_headers(admin_token, admin["organization_id"]),
            json={
                "business_number": "CREDIT-BIZ-1",
                "workflow_code": "CREDIT_CHANGE",
                "payload": {"amount": 100, "reason": "Top up", "risk_level": "HIGH_RISK"},
                "idempotency_key": "idemp-2",
            },
        )
        assert create2.status_code == 200
        assert create2.json()["idempotent"] is True

        approve1 = client.post(
            f"/workflows/{instance_id}/decision",
            headers=auth_headers(r1_token, admin["organization_id"]),
            json={"decision": "APPROVE", "comment": "ok"},
        )
        assert approve1.status_code == 200
        assert approve1.json()["status"] == "PENDING"

        approve2 = client.post(
            f"/workflows/{instance_id}/decision",
            headers=auth_headers(r2_token, admin["organization_id"]),
            json={"decision": "APPROVE", "comment": "ok"},
        )
        assert approve2.status_code == 200
        assert approve2.json()["status"] == "APPROVED"

        ledger = client.get(
            f"/organizations/{admin['organization_id']}/credit-ledger",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert ledger.status_code == 200
        assert len(ledger.json()) >= 1
        assert ledger.json()[0]["amount"] == 100.0


def test_cross_tenant_isolation_on_workflow_decision_and_file_read():
    with TestClient(app) as client:
        org_a = register_user(client, "usera", "OrgA", "administrator", code="ORGA")
        org_b = register_user(client, "userb", "OrgB", "reviewer", code="ORGB")
        token_a = login_user(client, "usera")
        token_b = login_user(client, "userb")

        wf = client.post(
            "/workflows",
            headers=auth_headers(token_a, org_a["organization_id"]),
            json={
                "business_number": "ISO-1",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {"resource": "x"},
                "idempotency_key": "iso-idemp-1",
            },
        )
        assert wf.status_code == 200
        instance_id = wf.json()["workflow_instance_id"]

        cross = client.post(
            f"/workflows/{instance_id}/decision",
            headers=auth_headers(token_b, org_b["organization_id"]),
            json={"decision": "APPROVE", "comment": "x"},
        )
        assert cross.status_code == 404

        upload = client.post(
            "/files/upload",
            headers={**auth_headers(token_a, org_a["organization_id"]), "X-Business-Type": "WORKFLOW", "X-Business-ID": "BIZ-A-1"},
            files={"file": ("data.csv", BytesIO(b"a,b\n1,2\n"), "text/csv")},
        )
        assert upload.status_code == 200
        file_id = upload.json()["file_id"]

        forbidden_file = client.get(
            f"/files/{file_id}",
            headers=auth_headers(token_b, org_b["organization_id"]),
            params={"business_type": "WORKFLOW", "business_id": "BIZ-A-1"},
        )
        assert forbidden_file.status_code == 404


def test_attachment_business_ownership_enforced_within_same_org():
    with TestClient(app) as client:
        user = register_user(client, "attach_user", "OrgAttach", "administrator", code="ORGAT")
        token = login_user(client, "attach_user")

        uploaded = client.post(
            "/files/upload",
            headers={**auth_headers(token, user["organization_id"]), "X-Business-Type": "WORKFLOW", "X-Business-ID": "WF-100"},
            files={"file": ("meta.json", BytesIO(b"{}"), "application/json")},
        )
        assert uploaded.status_code == 200
        file_id = uploaded.json()["file_id"]

        denied = client.get(
            f"/files/{file_id}",
            headers=auth_headers(token, user["organization_id"]),
            params={"business_type": "WORKFLOW", "business_id": "WF-200"},
        )
        assert denied.status_code == 404

        ok = client.get(
            f"/files/{file_id}",
            headers=auth_headers(token, user["organization_id"]),
            params={"business_type": "WORKFLOW", "business_id": "WF-100"},
        )
        assert ok.status_code == 200


def test_export_task_trace_and_desensitization():
    with TestClient(app) as client:
        admin = register_user(client, "admin_export", "OrgExport", "administrator", code="ORGEXP")
        auditor = register_user(client, "auditor_export", "OrgExport", "auditor", code="ORGEXP")
        general = register_user(client, "general_export", "OrgExport", "general", code="ORGEXP")
        auditor_token = login_user(client, "auditor_export")
        general_token = login_user(client, "general_export")

        denied = client.post(
            "/export/tasks",
            headers=auth_headers(general_token, admin["organization_id"]),
            json={"fields": ["username", "id_number"]},
        )
        assert denied.status_code == 403

        created = client.post(
            "/export/tasks",
            headers=auth_headers(auditor_token, admin["organization_id"]),
            json={"fields": ["username", "id_number", "contact", "organization_name"]},
        )
        assert created.status_code == 200
        task_id = created.json()["task_id"]

        detail = client.get(
            f"/export/tasks/{task_id}",
            headers=auth_headers(auditor_token, admin["organization_id"]),
        )
        assert detail.status_code == 200
        rows = detail.json()["result"]["rows"]
        assert len(rows) >= 1
        assert rows[0]["id_number"].startswith("ID-")

        reviewer = register_user(client, "review_export", "OrgExport", "reviewer", code="ORGEXP")
        reviewer_token = login_user(client, "review_export")
        created_review = client.post(
            "/export/tasks",
            headers=auth_headers(reviewer_token, admin["organization_id"]),
            json={"fields": ["username", "id_number", "contact", "organization_name"]},
        )
        assert created_review.status_code == 403


def test_export_whitelist_rejection():
    with TestClient(app) as client:
        admin = register_user(client, "admin_export_wl", "OrgExportWL", "administrator", code="ORGEXWL")
        token = login_user(client, "admin_export_wl")
        response = client.post(
            "/export/tasks",
            headers=auth_headers(token, admin["organization_id"]),
            json={"fields": ["username", "unapproved_field"]},
        )
        assert response.status_code == 400


def test_permission_policy_for_export_is_enforced():
    with TestClient(app) as client:
        admin = register_user(client, "perm_admin", "OrgPerm", "administrator", code="ORGPERM")
        reviewer = register_user(client, "perm_reviewer", "OrgPerm", "reviewer", code="ORGPERM")
        token = login_user(client, "perm_reviewer")
        response = client.post(
            "/export/tasks",
            headers=auth_headers(token, admin["organization_id"]),
            json={"fields": ["username", "id_number"]},
        )
        assert response.status_code == 403


def test_metrics_batch_and_operations_search_report():
    with TestClient(app) as client:
        user = register_user(client, "ops_user", "OrgOps", "administrator", code="ORGOPS")
        token = login_user(client, "ops_user")
        headers = auth_headers(token, user["organization_id"])

        imported = client.post(
            "/metrics/import-batch",
            headers=headers,
            json={
                "items": [
                    {
                        "metric_type": "attendance",
                        "metric_value": 8,
                        "source_key": "ops1",
                        "recorded_at": "2026-03-24T10:00:00",
                        "appointment_id": "AP-1",
                        "patient_id": "PT-1",
                        "doctor_id": "DR-1",
                        "activity_type": "follow_up",
                        "message_reach": 75,
                    },
                    {
                        "metric_type": "sla",
                        "metric_value": 90,
                        "source_key": "ops2",
                        "recorded_at": "2026-03-24T11:00:00",
                        "appointment_id": "AP-2",
                        "patient_id": "PT-2",
                        "doctor_id": "DR-2",
                        "activity_type": "consult",
                        "message_reach": 60,
                    },
                ]
            },
        )
        assert imported.status_code == 200
        assert imported.json()["success"] == 2

        dashboard = client.get("/operations/dashboard", headers=headers)
        assert dashboard.status_code == 200
        assert dashboard.json()["summary"]["attendance_total"] >= 8

        search = client.get(
            "/operations/search",
            headers=headers,
            params={
                "metric_type": "attendance",
                "appointment_id": "AP-1",
                "patient_id": "PT-1",
                "doctor_id": "DR-1",
                "activity_type": "follow_up",
                "min_message_reach": 70,
                "page": 1,
                "page_size": 10,
            },
        )
        assert search.status_code == 200
        assert search.json()["total"] >= 1
        assert search.json()["items"][0]["appointment_id"] == "AP-1"

        bad_reach = client.post(
            "/metrics/ingest",
            headers=headers,
            json={
                "items": [
                    {
                        "metric_type": "attendance",
                        "metric_value": 8,
                        "source_key": "ops_bad_reach",
                        "recorded_at": "2026-03-24T10:00:00",
                        "message_reach": 120,
                    }
                ]
            },
        )
        assert bad_reach.status_code == 400

        report = client.get("/operations/report", headers=headers)
        assert report.status_code == 200
        assert len(report.json()["report"]) >= 1

        work_sla = client.post(
            "/metrics/ingest",
            headers=headers,
            json={
                "items": [
                    {
                        "metric_type": "work_order_sla",
                        "metric_value": 88,
                        "source_key": "ops_work_sla_1",
                        "recorded_at": "2026-03-24T12:00:00",
                        "appointment_id": "WO-1",
                    }
                ]
            },
        )
        assert work_sla.status_code == 200

        anomalies = client.get(
            "/operations/anomalies/attendance",
            headers=headers,
            params={"threshold_hours": 7},
        )
        assert anomalies.status_code == 200
        assert anomalies.json()["count"] >= 1

        sla_report = client.get("/operations/work-orders/sla", headers=headers)
        assert sla_report.status_code == 200
        assert sla_report.json()["count"] >= 1


def test_file_dedup_isolation_by_org_or_business_scope():
    with TestClient(app) as client:
        org_a = register_user(client, "dedup_a", "OrgDedupA", "administrator", code="ORGDA")
        org_b = register_user(client, "dedup_b", "OrgDedupB", "administrator", code="ORGDB")
        token_a = login_user(client, "dedup_a")
        token_b = login_user(client, "dedup_b")
        content = b"same-file-content"

        a_upload = client.post(
            "/files/upload",
            headers={**auth_headers(token_a, org_a["organization_id"]), "X-Business-Type": "WORKFLOW", "X-Business-ID": "WF-A"},
            files={"file": ("x.csv", BytesIO(content), "text/csv")},
        )
        assert a_upload.status_code == 200

        b_upload = client.post(
            "/files/upload",
            headers={**auth_headers(token_b, org_b["organization_id"]), "X-Business-Type": "WORKFLOW", "X-Business-ID": "WF-B"},
            files={"file": ("x.csv", BytesIO(content), "text/csv")},
        )
        assert b_upload.status_code == 200
        assert b_upload.json()["deduplicated"] is False
        assert b_upload.json()["file_id"] != a_upload.json()["file_id"]

        same_scope_dedup = client.post(
            "/files/upload",
            headers={**auth_headers(token_a, org_a["organization_id"]), "X-Business-Type": "WORKFLOW", "X-Business-ID": "WF-A"},
            files={"file": ("x.csv", BytesIO(content), "text/csv")},
        )
        assert same_scope_dedup.status_code == 200
        assert same_scope_dedup.json()["deduplicated"] is True


def test_workflow_branching_high_vs_low_risk_thresholds():
    with TestClient(app) as client:
        admin = register_user(client, "branch_admin", "OrgBranch", "administrator", code="ORGBR")
        rev1 = register_user(client, "branch_r1", "OrgBranch", "reviewer", code="ORGBR")
        rev2 = register_user(client, "branch_r2", "OrgBranch", "reviewer", code="ORGBR")
        admin_token = login_user(client, "branch_admin")
        rev1_token = login_user(client, "branch_r1")
        rev2_token = login_user(client, "branch_r2")
        headers_admin = auth_headers(admin_token, admin["organization_id"])

        low = client.post(
            "/workflows",
            headers=headers_admin,
            json={
                "business_number": "BR-LOW-1",
                "workflow_code": "CREDIT_CHANGE",
                "payload": {"amount": 10, "risk_level": "LOW_RISK"},
                "idempotency_key": "br-low-1",
            },
        )
        low_id = low.json()["workflow_instance_id"]
        low_approve = client.post(
            f"/workflows/{low_id}/decision",
            headers=auth_headers(rev1_token, admin["organization_id"]),
            json={"decision": "APPROVE", "comment": "ok"},
        )
        assert low_approve.status_code == 200
        assert low_approve.json()["status"] == "APPROVED"

        high = client.post(
            "/workflows",
            headers=headers_admin,
            json={
                "business_number": "BR-HIGH-1",
                "workflow_code": "CREDIT_CHANGE",
                "payload": {"amount": 10, "risk_level": "HIGH_RISK"},
                "idempotency_key": "br-high-1",
            },
        )
        high_id = high.json()["workflow_instance_id"]
        high_approve_1 = client.post(
            f"/workflows/{high_id}/decision",
            headers=auth_headers(rev1_token, admin["organization_id"]),
            json={"decision": "APPROVE", "comment": "ok"},
        )
        assert high_approve_1.status_code == 200
        assert high_approve_1.json()["status"] == "PENDING"
        high_approve_2 = client.post(
            f"/workflows/{high_id}/decision",
            headers=auth_headers(rev2_token, admin["organization_id"]),
            json={"decision": "APPROVE", "comment": "ok"},
        )
        assert high_approve_2.status_code == 200
        assert high_approve_2.json()["status"] == "APPROVED"


def test_rollback_success_forbidden_not_found():
    with TestClient(app) as client:
        admin = register_user(client, "rb_admin", "OrgRB", "administrator", code="ORGRB")
        general = register_user(client, "rb_gen", "OrgRB", "general", code="ORGRB")
        outsider = register_user(client, "rb_out", "OrgRB2", "administrator", code="ORGRB2")
        admin_token = login_user(client, "rb_admin")
        general_token = login_user(client, "rb_gen")
        outsider_token = login_user(client, "rb_out")

        wf = client.post(
            "/workflows",
            headers=auth_headers(admin_token, admin["organization_id"]),
            json={"business_number": "RB-1", "workflow_code": "RESOURCE_APPLICATION", "payload": {}, "idempotency_key": "rb-1"},
        )
        wf_id = wf.json()["workflow_instance_id"]

        ok = client.post(
            f"/versioning/rollback/WorkflowInstance/{wf_id}/1",
            headers=auth_headers(admin_token, admin["organization_id"]),
        )
        assert ok.status_code == 200

        forbidden = client.post(
            f"/versioning/rollback/WorkflowInstance/{wf_id}/1",
            headers=auth_headers(general_token, admin["organization_id"]),
        )
        assert forbidden.status_code == 403

        not_found = client.post(
            f"/versioning/rollback/WorkflowInstance/{wf_id}/9999",
            headers=auth_headers(admin_token, admin["organization_id"]),
        )
        assert not_found.status_code == 404

        cross_tenant = client.post(
            f"/versioning/rollback/WorkflowInstance/{wf_id}/1",
            headers=auth_headers(outsider_token, outsider["organization_id"]),
        )
        assert cross_tenant.status_code == 404


def test_governance_lineage_dictionary_auth():
    with TestClient(app) as client:
        admin = register_user(client, "gov_admin", "OrgGov", "administrator", code="ORGGOV")
        token = login_user(client, "gov_admin")

        no_auth_lineage = client.get("/governance/lineage", headers={"X-Org-ID": admin["organization_id"]})
        assert no_auth_lineage.status_code == 401

        ok_lineage = client.get("/governance/lineage", headers=auth_headers(token, admin["organization_id"]))
        assert ok_lineage.status_code == 200
        assert isinstance(ok_lineage.json(), list)

        ok_dict = client.get("/governance/dictionary", headers=auth_headers(token, admin["organization_id"]))
        assert ok_dict.status_code == 200
        assert isinstance(ok_dict.json(), list)


def test_https_enforcement_when_enabled():
    previous_env = os.environ.get("ENVIRONMENT")
    previous_enforce = os.environ.get("ENFORCE_HTTPS")
    os.environ["ENVIRONMENT"] = "production"
    os.environ["ENFORCE_HTTPS"] = "true"
    from pure_backend import main as main_module
    prev_setting_env = main_module.settings.environment
    prev_setting_enforce = main_module.settings.enforce_https
    try:
        main_module.settings.environment = "production"
        main_module.settings.enforce_https = True

        with TestClient(app) as client:
            blocked = client.get("/health")
            assert blocked.status_code == 400

            allowed = client.get("/health", headers={"X-Forwarded-Proto": "https"})
            assert allowed.status_code == 200
    finally:
        main_module.settings.environment = prev_setting_env
        main_module.settings.enforce_https = prev_setting_enforce
        if previous_env is None:
            os.environ.pop("ENVIRONMENT", None)
        else:
            os.environ["ENVIRONMENT"] = previous_env
        if previous_enforce is None:
            os.environ.pop("ENFORCE_HTTPS", None)
        else:
            os.environ["ENFORCE_HTTPS"] = previous_enforce


def test_idempotency_key_outside_24h_window_creates_new_instance():
    with TestClient(app) as client:
        admin = register_user(client, "idemp_admin", "OrgIdemp", "administrator", code="ORGIDP")
        token = login_user(client, "idemp_admin")
        headers = auth_headers(token, admin["organization_id"])

        first = client.post(
            "/workflows",
            headers=headers,
            json={
                "business_number": "IDEMP-24H",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {},
                "idempotency_key": "idemp-old",
            },
        )
        assert first.status_code == 200

        from pure_backend.db.models import IdempotencyKey
        from pure_backend.db.session import SessionLocal
        from pure_backend.main import now_utc, timedelta

        db = SessionLocal()
        try:
            rec = db.query(IdempotencyKey).filter(IdempotencyKey.organization_id == admin["organization_id"], IdempotencyKey.business_number == "IDEMP-24H").first()
            rec.created_at = now_utc() - timedelta(hours=25)
            db.commit()
        finally:
            db.close()

        second = client.post(
            "/workflows",
            headers=headers,
            json={
                "business_number": "IDEMP-24H",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {},
                "idempotency_key": "idemp-new",
            },
        )
        assert second.status_code == 200
        assert second.json().get("idempotent") is None


def test_token_expiry_blocks_access():
    with TestClient(app) as client:
        user = register_user(client, "exp_user", "OrgExp", "administrator", code="ORGEXPY")
        token = login_user(client, "exp_user")

        from pure_backend.db.models import SessionToken
        from pure_backend.db.session import SessionLocal
        from pure_backend.main import now_utc, timedelta

        db = SessionLocal()
        try:
            row = db.get(SessionToken, token)
            row.expires_at = now_utc() - timedelta(minutes=1)
            db.commit()
        finally:
            db.close()

        denied = client.post(
            "/workflows",
            headers=auth_headers(token, user["organization_id"]),
            json={
                "business_number": "EXP-1",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {},
                "idempotency_key": "exp-1",
            },
        )
        assert denied.status_code == 401


def test_scheduler_retry_and_max_retry_limit():
    with TestClient(app) as client:
        admin = register_user(client, "sched_admin", "OrgSched", "administrator", code="ORGSCH")
        token = login_user(client, "sched_admin")
        headers = auth_headers(token, admin["organization_id"])

        for _ in range(3):
            failed = client.post("/governance/scheduler/nightly-sync/run", headers=headers, json={"should_fail": True})
            assert failed.status_code == 200
            assert failed.json()["status"] == "FAILED"

        blocked = client.post("/governance/scheduler/nightly-sync/run", headers=headers, json={"should_fail": True})
        assert blocked.status_code == 409


def test_backup_archive_and_retention_policy_enforcement():
    with TestClient(app) as client:
        admin = register_user(client, "ret_admin", "OrgRet", "administrator", code="ORGRET")
        token = login_user(client, "ret_admin")
        headers = auth_headers(token, admin["organization_id"])

        backup = client.post("/governance/backup", headers=headers)
        assert backup.status_code == 200

        archive = client.post("/governance/archive", headers=headers)
        assert archive.status_code == 200

        from pure_backend.db.models import BackupArchiveTask
        from pure_backend.db.session import SessionLocal
        from pure_backend.main import now_utc, timedelta

        db = SessionLocal()
        try:
            archived = db.query(BackupArchiveTask).filter(BackupArchiveTask.task_type == "ARCHIVE").first()
            archived.retained_until = now_utc() - timedelta(days=1)
            db.commit()
        finally:
            db.close()

        retention = client.post("/governance/retention/run", headers=headers)
        assert retention.status_code == 200
        assert retention.json()["cleaned"] >= 1

        non_admin = register_user(client, "ret_gen", "OrgRet", "general", code="ORGRET")
        non_admin_token = login_user(client, "ret_gen")
        denied_backup = client.post("/governance/backup", headers=auth_headers(non_admin_token, admin["organization_id"]))
        assert denied_backup.status_code == 403

        recover = client.post("/governance/scheduler/nightly-sync/run", headers=headers, json={"should_fail": False})
        assert recover.status_code == 200
        assert recover.json()["status"] == "SUCCESS"


def test_workflow_task_assignment_and_claim_lifecycle():
    with TestClient(app) as client:
        admin = register_user(client, "assign_admin", "OrgAssign", "administrator", code="ORGASN")
        reviewer = register_user(client, "assign_reviewer", "OrgAssign", "reviewer", code="ORGASN")
        outsider = register_user(client, "assign_outside", "OrgAssign", "general", code="ORGASN")
        admin_token = login_user(client, "assign_admin")
        reviewer_token = login_user(client, "assign_reviewer")
        outsider_token = login_user(client, "assign_outside")

        wf = client.post(
            "/workflows",
            headers=auth_headers(admin_token, admin["organization_id"]),
            json={"business_number": "ASN-1", "workflow_code": "RESOURCE_APPLICATION", "payload": {}, "idempotency_key": "asn-1"},
        )
        assert wf.status_code == 200
        instance_id = wf.json()["workflow_instance_id"]

        assigned = client.post(
            f"/workflows/{instance_id}/assign",
            headers=auth_headers(admin_token, admin["organization_id"]),
            json={"assign_to_user_id": reviewer["user_id"], "note": "please review"},
        )
        assert assigned.status_code == 200
        assignment_id = assigned.json()["assignment_id"]

        forbidden = client.post(
            f"/tasks/{assignment_id}/claim",
            headers=auth_headers(outsider_token, admin["organization_id"]),
            json={"note": "try claim"},
        )
        assert forbidden.status_code == 403

        claimed = client.post(
            f"/tasks/{assignment_id}/claim",
            headers=auth_headers(reviewer_token, admin["organization_id"]),
            json={"note": "claimed"},
        )
        assert claimed.status_code == 200
        assert claimed.json()["status"] == "CLAIMED"


def test_workflow_allocation_stage_after_approval():
    with TestClient(app) as client:
        admin = register_user(client, "alloc_admin", "OrgAlloc", "administrator", code="ORGALC")
        reviewer = register_user(client, "alloc_rev", "OrgAlloc", "reviewer", code="ORGALC")
        target = register_user(client, "alloc_target", "OrgAlloc", "general", code="ORGALC")
        admin_token = login_user(client, "alloc_admin")
        reviewer_token = login_user(client, "alloc_rev")

        wf = client.post(
            "/workflows",
            headers=auth_headers(admin_token, admin["organization_id"]),
            json={
                "business_number": "ALLOC-1",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {"risk_level": "LOW_RISK"},
                "idempotency_key": "alloc-1",
            },
        )
        assert wf.status_code == 200
        instance_id = wf.json()["workflow_instance_id"]

        before_approval = client.post(
            f"/workflows/{instance_id}/allocate",
            headers=auth_headers(admin_token, admin["organization_id"]),
            json={"allocate_to_user_id": target["user_id"], "department": "ops", "note": "before approve"},
        )
        assert before_approval.status_code == 400

        approve = client.post(
            f"/workflows/{instance_id}/decision",
            headers=auth_headers(reviewer_token, admin["organization_id"]),
            json={"decision": "APPROVE", "comment": "ok"},
        )
        assert approve.status_code == 200
        assert approve.json()["status"] == "APPROVED"

        allocated = client.post(
            f"/workflows/{instance_id}/allocate",
            headers=auth_headers(admin_token, admin["organization_id"]),
            json={"allocate_to_user_id": target["user_id"], "department": "ops", "note": "ready"},
        )
        assert allocated.status_code == 200


def test_audit_chain_continuity():
    with TestClient(app) as client:
        user = register_user(client, "audit_user", "OrgAudit", "administrator", code="ORGAUD")
        token = login_user(client, "audit_user")
        wf = client.post(
            "/workflows",
            headers=auth_headers(token, user["organization_id"]),
            json={
                "business_number": "AUD-1",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {},
                "idempotency_key": "aud-1",
            },
        )
        assert wf.status_code == 200
        client.get("/operations/report", headers=auth_headers(token, user["organization_id"]))

        from pure_backend.db.models import AuditLog
        from pure_backend.db.session import SessionLocal

        db = SessionLocal()
        try:
            rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
            assert len(rows) >= 2
            for idx in range(1, len(rows)):
                assert rows[idx].previous_hash == rows[idx - 1].current_hash
        finally:
            db.close()

        integrity = client.get("/governance/audit/integrity", headers=auth_headers(token, user["organization_id"]))
        assert integrity.status_code == 200
        assert integrity.json()["integrity_ok"] is True


def test_audit_logs_append_only_trigger_blocks_update_delete():
    with TestClient(app) as client:
        user = register_user(client, "audit_guard", "OrgAuditGuard", "administrator", code="ORGAG")
        token = login_user(client, "audit_guard")
        client.get("/operations/report", headers=auth_headers(token, user["organization_id"]))

        from sqlalchemy import text
        from pure_backend.db.session import SessionLocal

        db = SessionLocal()
        try:
            row = db.execute(text("SELECT id FROM audit_logs ORDER BY id LIMIT 1")).fetchone()
            assert row is not None
            row_id = row[0]

            update_failed = False
            try:
                db.execute(text("UPDATE audit_logs SET message='tamper' WHERE id=:id"), {"id": row_id})
                db.commit()
            except Exception:
                db.rollback()
                update_failed = True
            assert update_failed is True

            delete_failed = False
            try:
                db.execute(text("DELETE FROM audit_logs WHERE id=:id"), {"id": row_id})
                db.commit()
            except Exception:
                db.rollback()
                delete_failed = True
            assert delete_failed is True
        finally:
            db.close()


def test_encrypted_fields_are_not_stored_in_plaintext():
    with TestClient(app) as client:
        register = client.post(
            "/auth/register",
            json={
                "username": "enc_user",
                "password": "abc12345",
                "id_number": "ID-PLAINTEXT-123",
                "contact": "0900000000",
                "organization_name": "OrgEnc",
                "organization_code": "ORGENC",
                "role": "administrator",
            },
        )
        assert register.status_code == 200

        from pure_backend.db.models import User
        from pure_backend.db.session import SessionLocal

        db = SessionLocal()
        try:
            row = db.query(User).filter(User.username == "enc_user").first()
            assert row is not None
            assert row.encrypted_id_number != "ID-PLAINTEXT-123"
            assert row.encrypted_contact != "0900000000"
        finally:
            db.close()


def test_lockout_time_window_allows_after_old_failures():
    with TestClient(app) as client:
        register_user(client, "lock_window", "OrgLockWindow", "administrator", code="ORGLW")

        from pure_backend.db.models import LoginAttempt
        from pure_backend.db.session import SessionLocal
        from pure_backend.main import now_utc, timedelta

        db = SessionLocal()
        try:
            for _ in range(5):
                db.add(LoginAttempt(username="lock_window", success=False, attempted_at=now_utc() - timedelta(minutes=11)))
            db.commit()
        finally:
            db.close()

        login = client.post("/auth/login", json={"username": "lock_window", "password": "abc12345"})
        assert login.status_code == 200


def test_metrics_duplicate_source_key_rejections():
    with TestClient(app) as client:
        user = register_user(client, "dup_metrics", "OrgDup", "administrator", code="ORGDUP")
        token = login_user(client, "dup_metrics")
        headers = auth_headers(token, user["organization_id"])

        duplicate_in_request = client.post(
            "/metrics/ingest",
            headers=headers,
            json={
                "items": [
                    {"metric_type": "attendance", "metric_value": 4, "source_key": "dup1", "recorded_at": "2026-03-24T10:00:00"},
                    {"metric_type": "attendance", "metric_value": 5, "source_key": "dup1", "recorded_at": "2026-03-24T11:00:00"},
                ]
            },
        )
        assert duplicate_in_request.status_code == 400

        first = client.post(
            "/metrics/ingest",
            headers=headers,
            json={"items": [{"metric_type": "attendance", "metric_value": 4, "source_key": "dup2", "recorded_at": "2026-03-24T10:00:00"}]},
        )
        assert first.status_code == 200
        duplicate_db = client.post(
            "/metrics/ingest",
            headers=headers,
            json={"items": [{"metric_type": "attendance", "metric_value": 6, "source_key": "dup2", "recorded_at": "2026-03-24T12:00:00"}]},
        )
        assert duplicate_db.status_code == 400


def test_pagination_boundaries_and_unsupported_rollback_entity():
    with TestClient(app) as client:
        user = register_user(client, "page_user", "OrgPage", "administrator", code="ORGPAGE")
        token = login_user(client, "page_user")
        headers = auth_headers(token, user["organization_id"])

        bad_page = client.get("/operations/search", headers=headers, params={"metric_type": "attendance", "page": 0})
        assert bad_page.status_code == 400

        bad_page_size = client.get("/operations/search", headers=headers, params={"metric_type": "attendance", "page_size": 201})
        assert bad_page_size.status_code == 400

        unsupported = client.post(
            "/versioning/rollback/UnknownEntity/123/1",
            headers=headers,
        )
        assert unsupported.status_code in (400, 404)


def test_file_upload_validation_size_and_mime():
    with TestClient(app) as client:
        user = register_user(client, "file_guard", "OrgFileGuard", "administrator", code="ORGFILE")
        token = login_user(client, "file_guard")
        headers = {**auth_headers(token, user["organization_id"]), "X-Business-Type": "WORKFLOW", "X-Business-ID": "FG-1"}

        bad_mime = client.post(
            "/files/upload",
            headers=headers,
            files={"file": ("a.txt", BytesIO(b"hello"), "text/plain")},
        )
        assert bad_mime.status_code == 400

        huge = BytesIO(b"x" * (20 * 1024 * 1024 + 1))
        too_large = client.post(
            "/files/upload",
            headers=headers,
            files={"file": ("b.csv", huge, "text/csv")},
        )
        assert too_large.status_code == 400


def test_workflow_reminder_and_role_guard():
    with TestClient(app) as client:
        creator = register_user(client, "creator_u", "OrgWF", "administrator", code="ORGWF")
        reviewer = register_user(client, "review_u", "OrgWF", "reviewer", code="ORGWF")
        general = register_user(client, "gen_u", "OrgWF", "general", code="ORGWF")
        creator_token = login_user(client, "creator_u")
        reviewer_token = login_user(client, "review_u")
        general_token = login_user(client, "gen_u")

        wf = client.post(
            "/workflows",
            headers=auth_headers(creator_token, creator["organization_id"]),
            json={
                "business_number": "WF-RM-1",
                "workflow_code": "RESOURCE_APPLICATION",
                "payload": {},
                "idempotency_key": "wf-rm-1",
            },
        )
        assert wf.status_code == 200
        instance_id = wf.json()["workflow_instance_id"]

        denied = client.post(
            f"/workflows/{instance_id}/reminder",
            headers=auth_headers(general_token, creator["organization_id"]),
            json={"before_minutes": 60},
        )
        assert denied.status_code == 403

        ok = client.post(
            f"/workflows/{instance_id}/reminder",
            headers=auth_headers(reviewer_token, creator["organization_id"]),
            json={"before_minutes": 60},
        )
        assert ok.status_code == 200
