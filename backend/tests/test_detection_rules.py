import os
import unittest
from datetime import datetime, timezone
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from persistguard.api import app
from persistguard.auth import AuthenticatedUser, database_session, linked_account
from persistguard.models import AuditEvent, Endpoint, Organization, ScanJob, User


TEST_DATABASE_URL = os.environ.get("PERSISTGUARD_TEST_DATABASE_URL")
EXAMPLE = """schema_version: 1
title: Imported fixture rule
platform: windows
conditions: {source: services, field: command, contains: fixture-agent.exe}
risk: {base_score: 40}
"""


@unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
class DetectionRulesTests(unittest.TestCase):
    def test_draft_preview_activation_and_assessment_are_tenant_scoped(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        fixture_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        other_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        with engine.connect() as connection, connection.begin() as transaction:
            def database():
                with Session(connection, join_transaction_mode="create_savepoint") as session:
                    yield session

            with Session(connection, join_transaction_mode="create_savepoint") as session:
                tenants = [Organization(name="Rule test tenant"), Organization(name="Rule isolation tenant")]
                users = [User(organization=tenant, email="admin@example.test", role="admin") for tenant in tenants]
                endpoints = [Endpoint(organization=tenant, hostname="fixture", os_family="windows") for tenant in tenants]
                session.add_all(users + endpoints)
                session.flush()
                report = {"collectors": {"services": {"status": "collected", "report": {
                    "os_family": "windows", "coverage": {"status": "collected"}, "entries": [
                        {"mechanism": "windows_service", "name": "FixtureAgent", "display_name": "Fixture Agent",
                         "state": "running", "command": r"C:\Fixtures\FIXTURE-AGENT.EXE --host ioc.example.test",
                         "executable_sha256": fixture_hash.upper()},
                        {"mechanism": "windows_service", "name": "Ordinary", "display_name": "Ordinary",
                         "state": "running", "command": r"C:\Fixtures\other.exe --host ioc.example.test.invalid",
                         "executable_sha256": other_hash},
                    ],
                }}}}
                jobs = [ScanJob(organization_id=user.organization_id, endpoint_id=endpoint.id, requested_by=user.id,
                                scan_type="persistence_full_scan", status="completed", result=report,
                                finished_at=datetime.now(timezone.utc)) for user, endpoint in zip(users, endpoints, strict=True)]
                session.add_all(jobs)
                session.flush()
                job_ids = [job.id for job in jobs]
                admins = [AuthenticatedUser("admin", user.id, user.organization_id, "admin", True) for user in users]
                actor = admins[0]
                session.commit()

            overrides = app.dependency_overrides.copy()
            app.dependency_overrides.update({database_session: database, linked_account: lambda: actor})
            try:
                with TestClient(app) as client:
                    def findings(job_id):
                        response = client.get(f"/api/scan-jobs/{job_id}/assessment")
                        self.assertEqual(response.status_code, 200, response.text)
                        return response.json()["collectors"]["services"]["assessments"]

                    base = "/api/detection-rules"
                    validation = client.post(f"{base}/import/validate", json={"yaml": EXAMPLE})
                    self.assertEqual(validation.status_code, 200, validation.text)
                    self.assertEqual((validation.json()["source"], validation.json()["score"]), ("services", 40))
                    self.assertEqual(client.get(base).json()["rules"], [])
                    invalid_import = client.post(f"{base}/import", json={"yaml": EXAMPLE + "enabled: true\n"})
                    self.assertEqual(invalid_import.status_code, 422, invalid_import.text)
                    self.assertIn("enabled", invalid_import.json()["detail"])
                    imported = client.post(f"{base}/import", json={"yaml": EXAMPLE})
                    self.assertEqual(imported.status_code, 201, imported.text)
                    draft = imported.json()
                    self.assertEqual((draft["enabled"], draft["tested"], draft["published_version"]), (False, False, None))
                    self.assertEqual(client.put(f"{base}/{draft['id']}/activation", json={"revision": draft["revision"], "enabled": True}).status_code, 409)
                    definition = {"name": "Fixture command", "source": "services", "field": "command",
                                  "pattern": "fixture-agent.exe", "score": 40}
                    response = client.post(base, json=definition)
                    self.assertEqual(response.status_code, 201, response.text)
                    rule = response.json()
                    url = f"{base}/{rule['id']}"
                    self.assertFalse(rule["enabled"] or rule["tested"])
                    activation = {"revision": rule["revision"], "enabled": True}
                    self.assertEqual(client.put(f"{url}/activation", json=activation).status_code, 409)

                    sample = {"path": "FixtureAgent", "command": r"C:\Fixtures\FIXTURE-AGENT.EXE"}
                    ordinary = {"path": "Ordinary", "command": "other.exe"}
                    response = client.post(f"{url}/test", json={"revision": rule["revision"], "samples": [ordinary]})
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(response.json()["matched_indices"], [])
                    self.assertFalse(response.json()["rule"]["tested"])
                    response = client.post(f"{url}/test", json={"revision": rule["revision"], "samples": [sample, ordinary]})
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(response.json()["matched_indices"], [0])
                    self.assertEqual([item["score"] for item in findings(job_ids[0])], [0, 0])

                    response = client.put(f"{url}/activation", json=activation)
                    self.assertEqual(response.status_code, 200, response.text)
                    enabled = response.json()
                    self.assertTrue(enabled["enabled"])
                    matched, unmatched = findings(job_ids[0])
                    self.assertEqual((matched["score"], matched["reasons"], matched["verdict"]),
                                     (40, ["Rule: Fixture command"], "suspicious"))
                    self.assertEqual(unmatched["score"], 0)

                    actor = admins[1]
                    self.assertEqual(client.get(base).json()["rules"], [])
                    self.assertEqual(client.get(f"{url}/versions").status_code, 404)
                    self.assertEqual(client.get(f"{url}/export?version=1").status_code, 404)
                    self.assertEqual([item["score"] for item in findings(job_ids[1])], [0, 0])
                    self.assertEqual(client.put(url, json=definition | {"revision": enabled["revision"]}).status_code, 404)
                    actor = AuthenticatedUser("analyst", admins[0].user_id, admins[0].organization_id, "analyst", True)
                    self.assertFalse(client.get(base).json()["can_manage"])
                    self.assertEqual(client.post(base, json=definition).status_code, 403)
                    self.assertEqual(client.post(f"{base}/import", json={"yaml": EXAMPLE}).status_code, 403)
                    self.assertEqual(client.get(f"{url}/export").status_code, 403)
                    actor = AuthenticatedUser("viewer", admins[0].user_id, admins[0].organization_id, "viewer", True)
                    self.assertEqual(client.get(f"{url}/export?version=1").status_code, 403)

                    actor = admins[0]
                    self.assertEqual(client.put(url, json=definition | {"revision": rule["revision"]}).status_code, 409)
                    response = client.put(url, json=definition | {"revision": enabled["revision"], "score": 50})
                    self.assertEqual(response.status_code, 200, response.text)
                    updated = response.json()
                    self.assertTrue(updated["enabled"])
                    self.assertFalse(updated["tested"])
                    self.assertEqual((updated["published_version"], updated["draft_version"]), (1, 2))
                    self.assertEqual(client.get(f"{url}/export", params={"revision": enabled["revision"]}).status_code, 409)
                    draft_yaml = client.get(f"{url}/export", params={"revision": updated["revision"]})
                    live_yaml = client.get(f"{url}/export", params={"version": 1})
                    self.assertEqual(draft_yaml.status_code, 200, draft_yaml.text)
                    self.assertEqual(live_yaml.status_code, 200, live_yaml.text)
                    self.assertEqual(draft_yaml.headers["Cache-Control"], "no-store")
                    with Session(connection, join_transaction_mode="create_savepoint") as session:
                        events = session.scalars(select(AuditEvent.action).where(
                            AuditEvent.actor_id == actor.user_id, AuditEvent.target_id == UUID(rule["id"]),
                            AuditEvent.status_code == 200, AuditEvent.action.startswith("detection_rules.export."),
                        )).all()
                    self.assertCountEqual(events, ["detection_rules.export.draft", "detection_rules.export.published"])
                    self.assertTrue(draft_yaml.json()["filename"].endswith("-draft-v2.yaml"))
                    self.assertTrue(live_yaml.json()["filename"].endswith("-published-v1.yaml"))
                    self.assertEqual(client.get(f"{url}/export?version=2").status_code, 404)
                    restored_draft = client.post(f"{base}/import", json={"yaml": draft_yaml.json()["yaml"]})
                    self.assertEqual(restored_draft.status_code, 201, restored_draft.text)
                    restored = restored_draft.json()
                    self.assertEqual({key: restored[key] for key in definition}, definition | {"score": 50})
                    self.assertFalse(restored["enabled"] or restored["tested"])
                    restored_live = client.post(f"{base}/import/validate", json={"yaml": live_yaml.json()["yaml"]})
                    self.assertEqual(restored_live.json(), definition)
                    self.assertEqual(findings(job_ids[0])[0]["score"], 40)
                    activation = {"revision": updated["revision"], "enabled": True}
                    self.assertEqual(client.put(f"{url}/activation", json=activation).status_code, 409)
                    self.assertEqual(client.post(f"{url}/test", json={"revision": updated["revision"], "samples": [sample]}).status_code, 200)
                    self.assertEqual(findings(job_ids[0])[0]["score"], 40)
                    published = client.put(f"{url}/activation", json=activation)
                    self.assertEqual(published.status_code, 200, published.text)
                    self.assertEqual(findings(job_ids[0])[0]["score"], 50)
                    versions = client.get(f"{url}/versions").json()
                    self.assertEqual([(item["version"], item["score"]) for item in versions], [(2, 50), (1, 40)])
                    self.assertEqual(client.get(f"{url}/versions", params={"before": 2}).json(), versions[1:])
                    actor = admins[1]
                    self.assertEqual(client.post(f"{url}/rollback", json={
                        "revision": published.json()["revision"], "version": 1}).status_code, 404)
                    actor = AuthenticatedUser("analyst", admins[0].user_id, admins[0].organization_id, "analyst", True)
                    self.assertEqual(client.post(f"{url}/rollback", json={
                        "revision": published.json()["revision"], "version": 1}).status_code, 403)
                    actor = admins[0]
                    self.assertEqual(client.post(f"{url}/rollback", json={
                        "revision": published.json()["revision"], "version": 999}).status_code, 404)
                    rollback = client.post(f"{url}/rollback", json={
                        "revision": published.json()["revision"], "version": 1})
                    self.assertEqual(rollback.status_code, 200, rollback.text)
                    self.assertEqual((rollback.json()["published_version"], rollback.json()["draft_version"]), (1, 2))
                    self.assertEqual(findings(job_ids[0])[0]["score"], 40)
                    self.assertEqual(client.post(f"{url}/rollback", json={
                        "revision": published.json()["revision"], "version": 2}).status_code, 409)
                    self.assertEqual(client.post(f"{url}/rollback", json={
                        "revision": rollback.json()["revision"], "version": 1}).status_code, 409)
                    self.assertEqual(len(client.get(f"{url}/versions").json()), 2)
                    with Session(connection, join_transaction_mode="create_savepoint") as session:
                        self.assertIsNotNone(session.scalar(select(AuditEvent.id).where(
                            AuditEvent.actor_id == actor.user_id, AuditEvent.target_id == UUID(rule["id"]),
                            AuditEvent.action == "detection_rules.rollback", AuditEvent.status_code == 200)))
                    disabled = client.put(f"{url}/activation", json={"revision": rollback.json()["revision"], "enabled": False})
                    self.assertEqual(disabled.status_code, 200, disabled.text)
                    self.assertEqual([item["score"] for item in findings(job_ids[0])], [0, 0])

                    response = client.post("/api/workspace/iocs", json={"kind": "domain", "value": "IOC.EXAMPLE.TEST"})
                    self.assertEqual(response.status_code, 201, response.text)
                    matched, unmatched = findings(job_ids[0])
                    self.assertEqual((matched["score"], matched["reasons"]), (60, ["IOC match: domain ioc.example.test"]))
                    self.assertEqual(unmatched["score"], 0)
                    response = client.post("/api/workspace/iocs", json={"kind": "sha256", "value": fixture_hash.upper()})
                    self.assertEqual(response.status_code, 201, response.text)
                    matched, unmatched = findings(job_ids[0])
                    self.assertEqual(matched["score"], 60)
                    self.assertEqual(matched["reasons"], [f"IOC match: domain ioc.example.test, SHA-256 {fixture_hash}"])
                    self.assertEqual(unmatched["score"], 0)
                    actor = admins[1]
                    self.assertEqual([item["score"] for item in findings(job_ids[1])], [0, 0])
            finally:
                app.dependency_overrides.clear()
                app.dependency_overrides.update(overrides)
                transaction.rollback()
