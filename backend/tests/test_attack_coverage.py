import unittest
from uuid import uuid4

from fastapi.testclient import TestClient

from persistguard.api import app
from persistguard.attack_coverage import attack_coverage
from persistguard.auth import AuthenticatedUser, linked_account
from persistguard.scan_assessment import assess_scan_report


class AttackCoverageTests(unittest.TestCase):
    def test_catalog_distinguishes_use_cases_that_share_a_technique(self):
        rows = attack_coverage()
        self.assertEqual(len(rows), 148)
        partial = [row for row in rows if row.coverage == "partial"]
        self.assertEqual({row.technique_id for row in partial}, {"T1547.001", "T1053.005", "T1543.003"})
        self.assertEqual(len(partial), 3)
        self.assertTrue(all(row.group == "Persistence" and row.evidence and row.evidence.validation for row in partial))
        planned = next(row for row in rows if row.use_case == "Scheduled task execution")
        self.assertEqual((planned.technique_id, planned.coverage, planned.evidence), ("T1053.005", "planned", None))

    def test_endpoint_returns_evidence_as_separate_fields(self):
        before = app.dependency_overrides.copy()
        user = AuthenticatedUser("fixture", uuid4(), uuid4(), "viewer", True)
        app.dependency_overrides[linked_account] = lambda: user
        try:
            with TestClient(app) as client:
                response = client.get("/api/attack-coverage")
            self.assertEqual(response.status_code, 200, response.text)
            row = next(row for row in response.json() if row["use_case"] == "Windows service persistence")
            self.assertEqual(set(row["evidence"]), {"telemetry", "rule", "validation"})
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        finally:
            app.dependency_overrides.clear()
            app.dependency_overrides.update(before)

    def test_service_and_task_persistence_fixtures_require_comparable_snapshots(self):
        service = {"mechanism": "windows_service", "name": "Fixture", "display_name": "Fixture", "state": "stopped"}
        task = {"mechanism": "scheduled_task", "path": r"\Fixture", "actions": [], "triggers": [],
                "state": "Ready", "enabled": True, "hidden": False}

        def report(source, entries, status="collected"):
            coverage = {"status": status}
            if source == "scheduled_tasks":
                coverage["folders_visited"] = 1
            return {"collectors": {source: {"status": status, "report": {
                "os_family": "windows", "entries": entries, "coverage": coverage,
            }}}}

        for source, entry, technique in (("services", service, "T1543.003"), ("scheduled_tasks", task, "T1053.005")):
            current = report(source, [entry])
            for baseline, expected_status, score in ((report(source, []), "new", 10),
                                                       (current, "existing", 0),
                                                       (report(source, [], "partial"), "unknown", 0)):
                with self.subTest(source=source, status=expected_status):
                    result = assess_scan_report(current, "fixture", baseline)["collectors"][source]["assessments"][0]
                    self.assertEqual((result["baseline_status"], result["score"]), (expected_status, score))
                    self.assertEqual(result.get("attack_technique"), technique if score else None)
