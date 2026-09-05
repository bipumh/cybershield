"""End-to-end smoke test: run a web scan against a local target and print findings.

Uses only a local, self-owned HTTP server (localhost) — no third-party systems.
"""
import sys
import os
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal
from app.db.models import Scan, ScanTarget
from app.services import scan_service
from app.workers import orchestrator


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><body><h1>index of /</h1><a href='parent/'>parent directory</a><p>server info here</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.2.34 (Debian)")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass


def main():
    srv = HTTPServer(("127.0.0.1", 8099), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    db = SessionLocal()
    try:
        from app.services.bootstrap import bootstrap
        bootstrap(db)

        scan = scan_service.create_scan(
            db, tenant_id=1, user_id=1, name="Smoke web scan", mode="web", profile="safe",
            targets_data=[{"kind": "url", "value": "http://127.0.0.1:8099", "in_scope": True}],
            rate_limit=20, timeout=10, concurrency=2,
            excluded_ips=[], excluded_domains=[], maintenance_window=None,
            safety={"scope_confirmed": True, "safety_confirmed": True},
            auto_approve_scope=False,
        )
        print("SCAN created:", scan.scan_key, scan.status)
        orchestrator.run_scan(scan.id)
        db.refresh(scan)
        print("SCAN final:", scan.status, "progress", scan.progress)
        print("SCAN error:", scan.error or "none")
        from app.db.models import Finding
        from sqlalchemy import select
        findings = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
        print("FINDINGS:", len(findings))
        for f in findings:
            print(f"  - {f.finding_no} [{f.severity}] {f.title} (risk {f.risk_score}, band {f.risk_band}, kev={f.is_kev})")
    finally:
        db.close()
        srv.shutdown()


if __name__ == "__main__":
    main()
