import os
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from persistguard.api import app
from persistguard.auth import AuthenticatedUser, database_session, linked_account
from persistguard.models import AuditEvent, CaseRecord, Endpoint, Organization, ScanJob, User


TEST_DATABASE_URL = os.environ.get("PERSISTGUARD_TEST_DATABASE_URL")


@unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
class CaseFindingTests(unittest.TestCase):
    def test_attach_preserves_evidence_and_enforces_roles_and_tenant_scope(self):
        engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(engine.dispose)
        with engine.connect() as connection, connection.begin() as transaction:
            def database():
                with Session(connection, join_transaction_mode="create_savepoint") as session:
                    yield session

            with Session(connection, join_transaction_mode="create_savepoint") as session:
                tenants = [Organization(name="Investigation fixture"), Organization(name="Other fixture tenant")]
                users = [User(organization=tenant, role="analyst", email="analyst@example.test") for tenant in tenants]
                endpoints = [Endpoint(organization=tenant, hostname="fixture", os_family="windows") for tenant in tenants]
                session.add_all(users + endpoints)
                session.flush()
                cases = [CaseRecord(organization_id=tenant.id, title="Fixture case") for tenant in tenants]
                report = {"collectors": {"services": {"status": "collected", "report": {
                    "os_family": "windows", "coverage": {"status": "collected"}, "entries": [
                        {"mechanism": "windows_service", "name": "Sample", "display_name": "Sample", "state": "stopped",
                         "command": "powershell.exe -EncodedCommand FIXTURE --host ioc.example.test"},
                        {"mechanism": "windows_service", "name": "Ordinary", "display_name": "Ordinary", "state": "running"},
                    ],
                }}}}
                jobs = [ScanJob(organization_id=user.organization_id, endpoint_id=endpoint.id, requested_by=user.id,
                                scan_type="persistence_full_scan", status="completed", result=report)
                        for user, endpoint in zip(users, endpoints, strict=True)]
                second_job = ScanJob(organization_id=users[0].organization_id, endpoint_id=endpoints[0].id,
                                     requested_by=users[0].id, scan_type="persistence_full_scan",
                                     status="completed", result=report)
                session.add_all(cases + jobs + [second_job])
                session.flush()
                case_id, other_case = [case.id for case in cases]
                job_id, other_job = [job.id for job in jobs]
                second_job_id = second_job.id
                actor = AuthenticatedUser("fixture", users[0].id, tenants[0].id, "analyst", True)
                analyst = actor
                session.commit()

            overrides = app.dependency_overrides.copy()
            app.dependency_overrides.update({database_session: database, linked_account: lambda: actor})
            try:
                with TestClient(app) as client:
                    path = f"/api/workspace/cases/{case_id}/findings"
                    assessment_url = f"/api/scan-jobs/{job_id}/assessment"
                    findings = client.get(assessment_url).json()["collectors"]["services"]["assessments"]
                    self.assertNotIn("fingerprint", findings[1])
                    payload = {"scan_job_id": str(job_id), "source": "services", "artifact_index": 0,
                               "fingerprint": findings[0]["fingerprint"]}
                    rollup = client.get("/api/findings", params={"query": "encoded T1543.003"})
                    self.assertEqual(rollup.status_code, 200, rollup.text)
                    feed = rollup.json()
                    self.assertEqual((feed["scan_count"], feed["total"], feed["counts"]["low"]), (2, 2, 2))
                    self.assertEqual({row["scan_job_id"] for row in feed["findings"]}, {str(job_id), str(second_job_id)})
                    row = next(row for row in feed["findings"] if row["scan_job_id"] == str(job_id))
                    self.assertEqual(row["fingerprint"], payload["fingerprint"])
                    high = client.get("/api/findings", params={"severity": "high"}).json()
                    self.assertEqual((high["total"], high["counts"]["low"], high["findings"]), (0, 2, []))
                    unrelated = client.get("/api/findings", params={"query": "no such reason"}).json()
                    self.assertEqual((unrelated["total"], sum(unrelated["counts"].values())), (0, 0))
                    older = client.get("/api/findings", params={"scan_offset": 1}).json()
                    self.assertEqual((older["scan_count"], older["total"], older["has_older_scans"]), (1, 1, False))
                    picker = client.get("/api/workspace", params={"section": "cases", "case_query": "fixture"}).json()
                    self.assertEqual([item["id"] for item in picker["cases"]], [str(case_id)])
                    self.assertEqual(client.get("/api/workspace", params={"section": "cases", "case_query": "%"}).json()["cases"], [])
                    self.assertEqual(client.get(path).json(), [])
                    self.assertEqual(client.post(f"/api/workspace/cases/{other_case}/findings", json=payload).status_code, 404)
                    self.assertEqual(client.get(f"/api/workspace/cases/{other_case}/findings").status_code, 404)
                    self.assertEqual(client.post(path, json=payload | {"scan_job_id": str(other_job)}).status_code, 404)
                    self.assertEqual(client.post(path, json=payload | {"artifact_index": 1}).status_code, 404)
                    self.assertEqual(client.post(path, json=payload | {"fingerprint": "0" * 64}).status_code, 409)
                    attached = client.post(path, json=payload)
                    self.assertEqual(attached.status_code, 201, attached.text)
                    saved = attached.json()
                    self.assertEqual(saved["evidence"]["attack_technique"], "T1543.003")
                    self.assertEqual(saved["evidence"]["score"], 25)

                    response = client.post("/api/workspace/iocs", json={"kind": "domain", "value": "ioc.example.test"})
                    self.assertEqual(response.status_code, 201, response.text)
                    new_finding = client.get(assessment_url).json()["collectors"]["services"]["assessments"][0]
                    self.assertEqual(new_finding["score"], 85)
                    self.assertEqual(client.post(path, json=payload | {"fingerprint": new_finding["fingerprint"]}).status_code, 409)
                    retry = client.post(path, json=payload)
                    self.assertEqual((retry.status_code, retry.json()), (200, saved))
                    actor = AuthenticatedUser("fixture", analyst.user_id, analyst.organization_id, "viewer", True)
                    self.assertFalse(client.get("/api/findings").json()["can_manage"])
                    self.assertEqual(client.get(path).json(), [saved])
                    self.assertEqual(client.post(path, json=payload).status_code, 403)
                    with Session(connection, join_transaction_mode="create_savepoint") as session:
                        events = session.scalar(select(func.count()).select_from(AuditEvent).where(
                            AuditEvent.organization_id == analyst.organization_id,
                            AuditEvent.action == "cases.findings.attach", AuditEvent.status_code == 201,
                        ))
                    self.assertEqual(events, 1)
            finally:
                app.dependency_overrides.clear()
                app.dependency_overrides.update(overrides)
                transaction.rollback()
