"""End-to-end API integration tests (against temp DB)."""
from app.core.constants import FindingStatus


def test_auth_and_me(client, auth_headers):
    r = client.get("/api/v1/auth/me", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "admin@cybershieldplatform.com"
    assert "super_admin" in body["roles"]


def test_auth_required(client):
    assert client.get("/api/v1/assets").status_code == 401


def test_roles_catalog(client, auth_headers):
    r = client.get("/api/v1/users/roles", headers=auth_headers)
    assert r.status_code == 200
    names = [x["name"] for x in r.json()]
    assert "super_admin" in names and "ciso" in names and "auditor" in names


def test_create_and_list_asset(client, auth_headers):
    r = client.post("/api/v1/assets", json={
        "hostname": "srv-test-01", "ip_address": "10.0.0.9", "asset_type": "server",
        "criticality": "medium", "os_name": "Ubuntu"}, headers=auth_headers)
    assert r.status_code in (200, 201), r.text
    asset_id = r.json()["id"]
    lst = client.get("/api/v1/assets", headers=auth_headers).json()
    assert lst["total"] >= 1


def test_scan_requires_safety_confirmation(client, auth_headers):
    r = client.post("/api/v1/scans", json={
        "name": "bad scan", "mode": "web", "profile": "safe",
        "targets": [{"kind": "domain", "value": "example.com", "in_scope": True}],
        "safety": {"scope_confirmed": False, "safety_confirmed": False},
    }, headers=auth_headers)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "scan_safety"


def test_dashboard_endpoints(client, auth_headers):
    for path in ["/api/v1/dashboard/summary", "/api/v1/dashboard/posture",
                 "/api/v1/dashboard/sla", "/api/v1/dashboard/top-priorities"]:
        assert client.get(path, headers=auth_headers).status_code == 200


def test_report_generation_all_formats(client, auth_headers):
    for fmt in ["csv", "json", "html", "pdf", "xlsx"]:
        r = client.post("/api/v1/reports", json={
            "name": "test", "report_type": "technical", "format": fmt, "scope": {}},
            headers=auth_headers)
        assert r.status_code in (200, 201), r.text
        rid = r.json()["id"]
        dl = client.get(f"/api/v1/reports/{rid}/download", headers=auth_headers)
        assert dl.status_code == 200
        assert len(dl.content) > 0


def test_audit_logged_and_chain(client, auth_headers):
    r = client.get("/api/v1/audit", headers=auth_headers)
    assert r.status_code == 200
    # at least login recorded
    assert r.json()["total"] >= 1
    chain = client.get("/api/v1/audit/verify-chain", headers=auth_headers).json()
    assert chain["valid"] is True


def test_advisor(client, auth_headers):
    r = client.post("/api/v1/ai/advisor", json={"question": "What should we fix first?"},
                    headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["is_ai_generated"] is True
    assert r.json()["sources"] == "Platform scan data"
