from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
from time import monotonic, sleep
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from persistguard.api import app
from persistguard.auth import AuthenticatedUser, database_session, linked_account
from persistguard.models import AuditEvent, Endpoint, Organization, ScanJob, ScanSchedule, User
from persistguard.scan_schedules import process_due_schedules


TEST_DATABASE_URL = os.environ.get("PERSISTGUARD_TEST_DATABASE_URL")


@unittest.skipUnless(TEST_DATABASE_URL, "Requires a migrated PostgreSQL test database")
class ScanScheduleTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(TEST_DATABASE_URL)
        self.addCleanup(self.engine.dispose)
        self.org, self.other_org = uuid4(), uuid4()
        self.analyst, self.admin, self.viewer, self.other_admin = (uuid4() for _ in range(4))
        self.ready, self.other_endpoint, self.linux, self.pending = (uuid4() for _ in range(4))
        with Session(self.engine) as session, session.begin():
            org = Organization(id=self.org, name="Schedule fixture")
            other = Organization(id=self.other_org, name="Other schedule tenant")
            for name, org_row, role, user_id in (
                ("analyst", org, "analyst", self.analyst), ("admin", org, "admin", self.admin),
                ("viewer", org, "viewer", self.viewer), ("other", other, "admin", self.other_admin),
            ):
                session.add(User(id=user_id, organization=org_row, role=role, email=f"{name}@example.test",
                                 identity_issuer="https://fixture.example.test", identity_subject=str(user_id)))
            session.add_all([
                Endpoint(id=self.ready, organization=org, hostname="fixture-pc", os_family="windows", status="approved"),
                Endpoint(id=self.linux, organization=org, hostname="linux", os_family="linux", status="approved"),
                Endpoint(id=self.pending, organization=org, hostname="pending", os_family="windows", status="pending"),
                Endpoint(id=self.other_endpoint, organization=other, hostname="other-pc", os_family="windows", status="approved"),
            ])
        self.addCleanup(self.clean_records)

        def database():
            with Session(self.engine) as session:
                yield session

        self.set_actor(self.analyst, "analyst")
        self.enterContext(patch.dict(app.dependency_overrides, {database_session: database, linked_account: lambda: self.actor}))
        self.enterContext(patch.dict(os.environ))
        os.environ.pop("PERSISTGUARD_DATABASE_URL", None)
        self.client = self.enterContext(TestClient(app))
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.payload = {"endpoint_id": str(self.ready), "frequency": "daily", "scan_type": "persistence_services_scan",
                        "next_run_at": (self.now + timedelta(hours=1)).isoformat()}

    def clean_records(self):
        with Session(self.engine) as session, session.begin():
            for model in (AuditEvent, ScanJob, ScanSchedule, Endpoint, User):
                session.execute(delete(model).where(model.organization_id.in_((self.org, self.other_org))))
            session.execute(delete(Organization).where(Organization.id.in_((self.org, self.other_org))))

    def set_actor(self, actor_id, role, org_id=None):
        self.actor = AuthenticatedUser("fixture", actor_id, org_id or self.org, role, True)

    def create_schedule(self):
        response = self.client.post("/api/scan-schedules", json=self.payload)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def set_due(self, schedule_id, when):
        with Session(self.engine) as session, session.begin():
            session.get(ScanSchedule, schedule_id).next_run_at = when

    def test_schedule_management_is_tenant_scoped_and_viewer_is_read_only(self):
        route = "/api/scan-schedules"
        for endpoint in (self.linux, self.pending):
            self.assertEqual(self.client.post(route, json=self.payload | {"endpoint_id": str(endpoint)}).status_code, 409)
        self.assertEqual(self.client.post(route, json=self.payload | {"endpoint_id": str(self.other_endpoint)}).status_code, 404)
        self.assertEqual(self.client.post(route, json=self.payload | {"next_run_at": "2020-01-01T00:00:00Z"}).status_code, 422)
        self.assertEqual(self.client.post(route, json=self.payload | {"next_run_at": "2030-01-01T00:00:00"}).status_code, 422)
        created = self.create_schedule()
        schedule_route = f"{route}/{created['id']}"
        self.assertEqual(self.client.post(route, json=self.payload).status_code, 409)

        self.set_actor(self.other_admin, "admin", self.other_org)
        self.assertEqual(self.client.get(route).json()["schedules"], [])
        self.assertEqual(self.client.patch(schedule_route, json={"enabled": False}).status_code, 404)
        self.set_actor(self.viewer, "viewer")
        self.assertEqual(self.client.get(route).json()["schedules"], [created])
        self.assertEqual(self.client.post(route, json=self.payload).status_code, 403)
        self.assertEqual(self.client.patch(schedule_route, json={"enabled": False}).status_code, 403)

        self.set_actor(self.admin, "admin")
        self.assertFalse(self.client.patch(schedule_route, json={"enabled": False}).json()["enabled"])
        missed = self.now - timedelta(days=2, hours=1)
        self.set_due(created["id"], missed)
        process_due_schedules(self.engine)
        self.assertEqual(self.client.get("/api/scan-jobs").json(), [])
        resumed = self.client.patch(schedule_route, json={"enabled": True}).json()
        self.assertEqual(datetime.fromisoformat(resumed["next_run_at"]), missed + timedelta(days=3))
        edited = self.client.patch(schedule_route, json={"timing": {
            "frequency": "weekly", "next_run_at": (self.now + timedelta(hours=2)).isoformat(),
        }}).json()
        self.assertEqual(edited["frequency"], "weekly")
        self.assertEqual(datetime.fromisoformat(edited["next_run_at"]), self.now + timedelta(hours=2))

    def test_workers_queue_once_skip_busy_runs_and_pause_when_access_is_lost(self):
        schedule_id = self.create_schedule()["id"]
        overdue = self.now - timedelta(days=3, hours=2)
        self.set_due(schedule_id, overdue)
        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(process_due_schedules, self.engine)
            second = workers.submit(process_due_schedules, self.engine)
            first.result(timeout=10)
            second.result(timeout=10)

        job, = self.client.get("/api/scan-jobs").json()
        self.assertEqual((job["status"], job["scan_type"], job["schedule_id"]),
                         ("queued", "persistence_services_scan", schedule_id))
        schedule, = self.client.get("/api/scan-schedules").json()["schedules"]
        self.assertEqual(schedule["last_outcome"], "queued")
        self.assertEqual(datetime.fromisoformat(schedule["next_run_at"]), overdue + timedelta(days=4))
        with Session(self.engine) as session:
            event = session.scalars(select(AuditEvent).where(AuditEvent.target_id == job["id"])).one()
            self.assertEqual((event.action, event.actor_id), ("scan_jobs.schedule", self.analyst))

        self.set_due(schedule_id, overdue)
        process_due_schedules(self.engine)
        self.assertEqual(self.client.get("/api/scan-jobs").json(), [job])
        schedule, = self.client.get("/api/scan-schedules").json()["schedules"]
        self.assertEqual(schedule["last_outcome"], "skipped_busy")

        with Session(self.engine) as session, session.begin():
            session.get(User, self.analyst).role = "viewer"
        self.set_due(schedule_id, overdue)
        process_due_schedules(self.engine)
        schedule, = self.client.get("/api/scan-schedules").json()["schedules"]
        self.assertEqual((schedule["enabled"], schedule["last_outcome"]), (False, "paused_owner"))

        self.set_actor(self.admin, "admin")
        route = f"/api/scan-schedules/{schedule_id}"
        self.assertTrue(self.client.patch(route, json={"enabled": True}).json()["enabled"])
        self.assertEqual(self.client.post(f"/api/endpoints/{self.ready}/revoke").status_code, 200)
        self.set_due(schedule_id, overdue)
        process_due_schedules(self.engine)
        schedule, = self.client.get("/api/scan-schedules").json()["schedules"]
        self.assertEqual((schedule["enabled"], schedule["last_outcome"]), (False, "paused_endpoint"))
        self.assertEqual(self.client.patch(route, json={"enabled": True}).status_code, 409)

    def test_api_startup_processes_persisted_due_schedule(self):
        schedule_id = self.create_schedule()["id"]
        self.set_due(schedule_id, self.now - timedelta(hours=1))
        with patch.dict(os.environ, {"PERSISTGUARD_DATABASE_URL": TEST_DATABASE_URL}), TestClient(app) as client:
            deadline = monotonic() + 5
            jobs = []
            while monotonic() < deadline:
                jobs = client.get("/api/scan-jobs").json()
                if jobs:
                    break
                sleep(0.05)
            self.assertEqual([job["schedule_id"] for job in jobs], [schedule_id])
