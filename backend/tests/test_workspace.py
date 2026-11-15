import os
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from persistguard.api import app
from persistguard.auth import AuthenticatedUser, database_session, linked_account
from persistguard.models import Endpoint, Organization, User


TEST_DATABASE_URL = os.environ.get("PERSISTGUARD_TEST_DATABASE_URL")


@unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
class WorkspaceTests(unittest.TestCase):
    def test_counts_health_and_writes_are_scoped_to_the_linked_tenant(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        with engine.connect() as connection, connection.begin() as transaction:
            def session():
                with Session(connection, join_transaction_mode="create_savepoint") as db:
                    yield db

            now = datetime.now(timezone.utc)
            with Session(connection, join_transaction_mode="create_savepoint") as db:
                tenant, other = Organization(name="Current"), Organization(name="Other")
                admin = User(organization=tenant, email="admin@example.test", role="admin")
                viewer = User(organization=other, email="viewer@example.test", role="viewer")
                db.add_all([admin, viewer, Endpoint(organization=tenant, hostname="live", os_family="windows",
                                                 status="approved", last_seen=now),
                            Endpoint(organization=tenant, hostname="stale", os_family="windows",
                                     status="approved", last_seen=now - timedelta(minutes=5),
                                     created_at=now - timedelta(days=2)),
                            Endpoint(organization=tenant, hostname="pending", os_family="windows"),
                            Endpoint(organization=other, hostname="foreign", os_family="windows",
                                     status="approved", last_seen=now)])
                db.flush()
                actor = AuthenticatedUser("admin", admin.id, tenant.id, "admin", True)
                outsider = AuthenticatedUser("viewer", viewer.id, other.id, "viewer", True)
                db.commit()

            overrides = app.dependency_overrides.copy()
            app.dependency_overrides.update({database_session: session, linked_account: lambda: actor})
            try:
                with TestClient(app) as client:
                    def snapshot(section="dashboard"):
                        response = client.get("/api/workspace", params={"section": section})
                        self.assertEqual(response.status_code, 200, response.text)
                        return response.json()

                    enrollments = snapshot("endpoints")
                    self.assertEqual(enrollments["endpoint_counts"], {
                        "total": 3, "new_installed": 2, "connected": 1, "disconnected": 1,
                    })
                    self.assertEqual({entry["hostname"]: entry["connected"] for entry in enrollments["endpoints"]},
                                     {"live": True, "stale": False, "pending": False})
                    response = client.post("/api/workspace/cases", json={"title": "Investigate startup change"})
                    self.assertEqual(response.status_code, 201, response.text)
                    case_id = response.json()["id"]
                    self.assertEqual(response.json()["status"], "new")
                    response = client.patch(f"/api/workspace/cases/{case_id}", json={"status": "in_progress"})
                    self.assertEqual(response.status_code, 200, response.text)
                    indicator = {"kind": "domain", "value": "HOST.EXAMPLE.TEST."}
                    response = client.post("/api/workspace/iocs", json=indicator)
                    self.assertEqual(response.status_code, 201, response.text)
                    self.assertEqual(response.json()["value"], "host.example.test")
                    self.assertEqual(client.post("/api/workspace/iocs", json=indicator).status_code, 409)
                    self.assertEqual(client.post("/api/workspace/iocs", json={"kind": "ip", "value": "bad"}).status_code, 422)
                    overview = snapshot()
                    self.assertEqual(overview["tenant"], {"name": "Current", "count": 1})
                    self.assertEqual(overview["case_counts"], {"new": 0, "in_progress": 1, "resolved": 0})
                    self.assertEqual(overview["indicator_count"], 1)

                    admin_actor = actor
                    evidence_path = "/api/attack-coverage/D-T1053.005/validations"
                    execution_path = "/api/attack-coverage/C-T1053.005/validations"
                    trial = {"result": "passed", "tested_on": "2026-11-15", "reference": "LAB-2026-001"}
                    response = client.post(evidence_path, json=trial)
                    self.assertEqual(response.status_code, 201, response.text)
                    saved = response.json()
                    self.assertEqual((saved["recorded_by"], saved["recorded_role"]), (str(admin_actor.user_id), "admin"))
                    duplicate = client.post(evidence_path, json=trial)
                    self.assertEqual((duplicate.status_code, duplicate.json()["id"]), (200, saved["id"]))
                    self.assertEqual(client.get(execution_path).json()["records"], [])
                    self.assertEqual(client.post(evidence_path, json=trial | {"tested_on": "2026-02-30"}).status_code, 422)
                    self.assertEqual(client.post("/api/attack-coverage/Z-T1053.005/validations", json=trial).status_code, 404)
                    actor = AuthenticatedUser("analyst", admin_actor.user_id, admin_actor.organization_id, "analyst", True)
                    failed = client.post(evidence_path, json=trial | {"result": "failed", "tested_on": "2026-11-14"})
                    self.assertEqual(failed.status_code, 201, failed.text)
                    actor = AuthenticatedUser("viewer", admin_actor.user_id, admin_actor.organization_id, "viewer", True)
                    page = client.get(evidence_path).json()
                    self.assertFalse(page["can_manage"])
                    self.assertEqual([record["id"] for record in page["records"]], [saved["id"], failed.json()["id"]])
                    self.assertEqual(client.post(evidence_path, json=trial).status_code, 403)

                    actor = outsider
                    self.assertEqual(client.get(evidence_path).json()["records"], [])
                    self.assertEqual(snapshot()["indicator_count"], 0)
                    self.assertEqual(snapshot("cases")["cases"], [])
                    self.assertEqual(client.post("/api/workspace/cases", json={"title": "Forbidden"}).status_code, 403)
                    actor = AuthenticatedUser("viewer", outsider.user_id, outsider.organization_id, "analyst", True)
                    foreign_trial = client.post(evidence_path, json=trial)
                    self.assertEqual(foreign_trial.status_code, 201, foreign_trial.text)
                    self.assertNotEqual(foreign_trial.json()["id"], saved["id"])
                    response = client.patch(f"/api/workspace/cases/{case_id}", json={"status": "resolved"})
                    self.assertEqual(response.status_code, 404, response.text)
            finally:
                app.dependency_overrides.clear()
                app.dependency_overrides.update(overrides)
                transaction.rollback()
