import unittest

from persistguard.ioc_matching import build_ioc_index, match_iocs
from persistguard.scan_assessment import assess_scan_report


class IOCMatchingTests(unittest.TestCase):
    def test_matches_complete_tokens_and_url_authorities(self):
        index = build_ioc_index([
            ("domain", "example.test"), ("ip", "192.0.2.1"), ("ip", "2001:db8::1"),
            ("url", "https://EXAMPLE.test:443/Path?q=One"), ("sha256", "a" * 64),
        ])
        self.assertEqual(match_iocs([
            "--url='HTTPS://Example.Test./Path?q=One' --host=192.0.2.1:8080 --peer [2001:0db8::1]:443",
            "--host example.TEST --host 192.0.2.1",
        ], index), [
            ("domain", "example.test"), ("ip", "192.0.2.1"), ("ip", "2001:db8::1"),
            ("url", "https://example.test/Path?q=One"),
        ])
        self.assertEqual(match_iocs([r'--log C:\temp\log=example.test',
                                     '--host example.test2 --host sub.example.test --host 192.0.2.10',
                                     '--url https://external.test/?next=https://example.test/Path?q=One',
                                     '--url https://[2001:db8::1]suffix/path --host example.test"suffix"',
                                     'https://example.test@external.test/Path?q=One', 'a' * 64], index), [])
        self.assertEqual(match_iocs(["https://EXAMPLE.test/path?q=one"], index), [("domain", "example.test")])

    def test_assessment_scores_observed_arguments_only_once_per_artifact(self):
        service = {"mechanism": "windows_service", "display_name": "Fixture", "state": "stopped"}
        task = {"mechanism": "scheduled_task", "path": r"\Fixture", "triggers": [], "state": "Ready",
                "enabled": True, "hidden": False, "actions": [
                    {"type": "Exec", "command": r"C:\Fixture\agent.exe", "arguments": "--host 192.0.2.1"},
                ]}
        report = {"collectors": {
            "services": {"status": "collected", "report": {"os_family": "windows", "coverage": {"status": "collected"},
                "entries": [
                    {**service, "name": "Matched", "command": '"C:\\Fixture Path\\agent.exe" --url https://example.test/a'},
                    {**service, "name": "ExecutableOnly", "command": 'example.test --host example.test.invalid'},
                ]}},
            "scheduled_tasks": {"status": "collected", "report": {"os_family": "windows", "entries": [task],
                "coverage": {"status": "collected", "folders_visited": 1}}},
        }}
        indicators = build_ioc_index([("domain", "example.test"), ("url", "https://example.test/a"), ("ip", "192.0.2.1")])
        collectors = assess_scan_report(report, "fixture", indicators=indicators)["collectors"]
        matched, unmatched = collectors["services"]["assessments"]
        self.assertEqual(matched["score"], 60)
        self.assertEqual(matched["attack_technique"], "T1543.003")
        self.assertEqual(matched["verdict"], "suspicious")
        self.assertEqual(matched["reasons"], ["IOC match: domain example.test, URL https://example.test/a"])
        self.assertEqual(unmatched["score"], 0)
        self.assertNotIn("attack_technique", unmatched)
        self.assertEqual(collectors["scheduled_tasks"]["assessments"][0]["reasons"], ["IOC match: IP 192.0.2.1"])

    def test_matches_only_reported_executable_hashes_across_collectors(self):
        digest = "ab" * 32
        index = build_ioc_index([("sha256", digest)])
        task = {"mechanism": "scheduled_task", "path": r"\Fixture", "triggers": [], "state": "Ready",
                "enabled": True, "hidden": False, "actions": [
                    {"type": "Exec", "command": r"C:\Fixture\agent.exe", "executable_sha256": digest},
                    {"type": "Exec", "command": r"C:\Fixture\agent.exe", "executable_sha256": digest.upper()},
                ]}
        registry = {"mechanism": "registry_run_key", "hive": "HKLM", "key_path": r"Software\Fixture\Run",
                    "registry_view": "64-bit", "value_name": "Fixture", "value_type": "REG_SZ",
                    "command": f'agent.exe --digest {digest}'}
        report = {"collectors": {
            "scheduled_tasks": {"status": "collected", "report": {"os_family": "windows", "entries": [task],
                "coverage": {"status": "collected", "folders_visited": 1}}},
            "registry": {"status": "collected", "report": {"os_family": "windows", "coverage": [], "entries": [
                registry, registry | {"value_name": "Invalid", "executable_sha256": [digest]},
                registry | {"value_name": "Hashed", "executable_sha256": digest},
            ]}},
        }}
        collectors = assess_scan_report(report, "fixture", indicators=index)["collectors"]
        finding = collectors["scheduled_tasks"]["assessments"][0]
        self.assertEqual(finding["attack_technique"], "T1053.005")
        self.assertEqual((finding["score"], finding["reasons"]), (60, [f"IOC match: SHA-256 {digest}"]))
        self.assertEqual([item["score"] for item in collectors["registry"]["assessments"]], [0, 0, 60])
        self.assertEqual(collectors["registry"]["assessments"][2]["attack_technique"], "T1547.001")
