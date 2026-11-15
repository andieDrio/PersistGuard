import unittest

from pydantic import ValidationError

from persistguard.normalize_inventory import normalize_inventory


class NormalizeInventoryTests(unittest.TestCase):
    def test_registry_preserves_view_default_value_and_partial_coverage(self):
        entry = {
            "mechanism": "registry_run_key", "hive": "HKLM", "key_path": r"Software\Fixture\Run",
            "registry_view": "32-bit", "value_name": "", "value_type": "REG_EXPAND_SZ",
            "command": r'"%EXAMPLE%\café fixture.exe" --demo',
        }
        coverage = {"status": "partial", "hive": entry["hive"], "registry_view": entry["registry_view"],
                    "key_path": entry["key_path"], "issues": [{"value_name": "Missing", "code": "not_found"}]}
        result = normalize_inventory("registry", {"os_family": "windows", "entries": [entry], "coverage": [coverage]})
        self.assertEqual(result.schema_version, 1)
        self.assertEqual(result.coverage, [coverage])
        artifact, = result.artifacts
        self.assertEqual(artifact.path, r"HKLM\Software\Fixture\Run")
        self.assertEqual(artifact.commands[0].command_line, entry["command"])
        self.assertEqual((artifact.metadata["value_name"], artifact.metadata["registry_view"]), ("", "32-bit"))

    def test_task_preserves_all_actions_and_separates_executable_arguments(self):
        actions = [
            {"type": "Exec", "command": r"C:\Fixture with spaces\one.exe", "arguments": '--label "one two"'},
            {"type": "ComHandler", "class_id": "{11111111-1111-1111-1111-111111111111}"},
            {"type": "Exec", "command": "fixture.exe", "working_directory": r"C:\Fixture"},
        ]
        triggers = [{"type": "LogonTrigger", "enabled": False}]
        coverage = {"status": "collected", "folders_visited": 1}
        entry = {"mechanism": "scheduled_task", "path": r"\Fixture", "actions": actions, "triggers": triggers,
                 "hidden": True, "enabled": False, "state": "disabled"}
        result = normalize_inventory("scheduled_tasks", {"os_family": "windows", "entries": [entry], "coverage": coverage})
        artifact, = result.artifacts
        self.assertEqual(artifact.metadata["actions"], actions)
        self.assertEqual(artifact.metadata["triggers"], triggers)
        self.assertEqual([command.action_index for command in artifact.commands], [0, 2])
        self.assertEqual(artifact.commands[0].arguments, actions[0]["arguments"])
        self.assertEqual(artifact.commands[1].working_directory, actions[2]["working_directory"])
        self.assertEqual(result.coverage, [coverage])

    def test_service_without_config_has_empty_commands_and_retains_coverage(self):
        entry = {"mechanism": "windows_service", "name": "Fixture", "display_name": "Fixture Service", "state": "running"}
        coverage = {"status": "partial", "issues": [{"name": "Fixture", "operation": "query_config", "code": "access_denied"}]}
        report = {"os_family": "windows", "entries": [entry], "coverage": coverage}
        result = normalize_inventory("services", report)
        artifact, = result.artifacts
        self.assertEqual(artifact.path, "Fixture")
        self.assertEqual(artifact.commands, [])
        self.assertEqual(artifact.metadata["state"], "running")
        self.assertEqual(result.coverage, [coverage])

        for malformed in ({**report, "os_family": "linux"}, {**report, "entries": [{**entry, "state": 4}]}):
            with self.subTest(malformed=malformed), self.assertRaises(ValidationError):
                normalize_inventory("services", malformed)
