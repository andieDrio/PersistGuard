import unittest

from persistguard.assess_inventory import ArtifactEvidence, assess_inventory, has_encoded_command
from persistguard.normalize_inventory import ArtifactCommand, normalize_inventory
from persistguard.scan_assessment import assess_scan_report


class AssessInventoryTests(unittest.TestCase):
    def test_normalized_artifacts_are_scored_and_coverage_is_preserved(self):
        base = {"mechanism": "windows_service", "display_name": "Fixture", "state": "stopped"}
        coverage = {"status": "partial", "issues": [{"name": "Restricted", "code": "access_denied"}]}
        inventory = normalize_inventory("services", {
            "os_family": "windows",
            "entries": [
                {**base, "name": "Normal", "command": r"C:\Fixture\agent.exe -EncodedCommand PLACEHOLDER"},
                {**base, "name": "Observed", "command": r'"C:\Fixture Path\powershell.exe" -EncodedCommand PLACEHOLDER'},
                {**base, "name": "Restricted", "known_malicious_hash": True},
            ],
            "coverage": coverage,
        })
        baseline = assess_inventory(inventory, "fixture-endpoint", {})
        self.assertEqual([entry["score"] for entry in baseline["assessments"]], [0, 25, 0])
        self.assertTrue(all(entry["verdict"] == "unknown" for entry in baseline["assessments"]))

        result = assess_inventory(inventory, "fixture-endpoint", {1: ArtifactEvidence(signature_status="invalid")})
        finding = result["assessments"][1]
        self.assertEqual((finding["artifact_index"], finding["score"], finding["verdict"]), (1, 40, "suspicious"))
        self.assertEqual(finding["reasons"], ["Encoded startup command", "Invalid signature"])
        self.assertEqual(result["coverage"], [coverage])
        with self.assertRaisesRegex(ValueError, "outside the report"):
            assess_inventory(inventory, "fixture-endpoint", {3: ArtifactEvidence(is_new=True)})

    def test_structured_command_signal_uses_the_executable_and_argument(self):
        self.assertTrue(has_encoded_command(ArtifactCommand(executable="pwsh.exe", arguments="-enc PLACEHOLDER")))
        self.assertFalse(has_encoded_command(ArtifactCommand(executable="pwsh.exe", arguments="-enc")))
        self.assertFalse(has_encoded_command(ArtifactCommand(executable="pwsh.exe", arguments='-Command "fixture -enc data"')))

    def test_invalid_collector_does_not_block_other_assessments(self):
        report = {"collectors": {
            "registry": {"status": "collected", "report": {"os_family": "windows", "entries": ["bad"], "coverage": []}},
            "scheduled_tasks": {"status": "error", "error": "fixture unavailable"},
            "services": {"status": "collected", "report": {"os_family": "windows", "entries": [
                {"mechanism": "windows_service", "name": "Ordinary", "display_name": "Ordinary", "state": "running"},
            ], "coverage": {"status": "collected"}}},
        }}
        result = assess_scan_report(report, "test-endpoint")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["collectors"]["registry"]["error"], "invalid_collector_report")
        self.assertEqual(result["collectors"]["services"]["assessments"][0]["score"], 0)

    def test_baseline_marks_only_comparable_registry_locations(self):
        def scope(hive, path, view, status):
            return {"hive": hive, "key_path": path, "registry_view": view, "status": status}

        def entry(coverage, name):
            return {key: value for key, value in coverage.items() if key != "status"} | {
                "mechanism": "registry_run_key", "value_type": "REG_SZ", "value_name": name, "command": "fixture.exe",
            }

        machine = scope("HKLM", r"Software\Test\Run", "64-bit", "collected")
        second_view = scope("HKLM", machine["key_path"], "32-bit", "collected")
        user = scope("HKCU", machine["key_path"], "shared", "collected")
        missing_before = scope("HKLM", r"Software\Other\Run", "64-bit", "collected")

        def report(entries, coverage):
            return {"collectors": {"registry": {"status": "partial", "report": {
                "os_family": "windows", "entries": entries, "coverage": coverage,
            }}}}

        prior = report([entry(machine, "AlreadyThere")], [machine, second_view | {"status": "error"}, user,
                                                          missing_before | {"status": "absent"}])
        current = report([
            entry(machine, "alreadythere"), entry(machine, "new"), entry(second_view, "unknown view"),
            entry(user, "unknown account"), entry(missing_before, "new key"),
        ], [machine, second_view, user, missing_before])
        items = assess_scan_report(current, "device", prior)["collectors"]["registry"]["assessments"]
        self.assertEqual([item["baseline_status"] for item in items], ["existing", "new", "unknown", "unknown", "new"])
        self.assertEqual([item["score"] for item in items], [0, 10, 0, 0, 10])

    def test_partial_service_baseline_does_not_mark_new_entry(self):
        def report(status, entries):
            return {"collectors": {"services": {"status": status, "report": {
                "os_family": "windows", "entries": entries, "coverage": {"status": status},
            }}}}

        service = {"mechanism": "windows_service", "name": "fixture", "display_name": "Fixture", "state": "stopped"}
        current = report("collected", [service])
        for prior, expected in (("partial", "unknown"), ("collected", "new")):
            result = assess_scan_report(current, "device", report(prior, []))
            self.assertEqual(result["collectors"]["services"]["assessments"][0]["baseline_status"], expected)
