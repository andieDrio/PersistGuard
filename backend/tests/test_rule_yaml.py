import unittest

from persistguard.rule_yaml import MAX_RULE_YAML_BYTES, RuleDefinition, RuleYAMLError, export_rule_yaml, parse_rule_yaml


EXAMPLE = """schema_version: 1
title: Fixture rule
platform: windows
conditions:
  source: services
  field: command
  contains: fixture-agent.exe
risk:
  base_score: 40
response:
  action: alert_only
"""


class RuleYAMLTests(unittest.TestCase):
    def test_export_round_trip_preserves_yaml_like_text_and_unicode(self):
        rule = RuleDefinition(name="no", source="registry", field="path", pattern="例: #fixture\nregistry", score=61)
        self.assertEqual(parse_rule_yaml(export_rule_yaml(rule)), rule)

    def test_import_profile_maps_to_existing_rule_definition(self):
        rule = parse_rule_yaml(EXAMPLE)
        self.assertEqual(rule.model_dump(), {"name": "Fixture rule", "source": "services", "field": "command",
                                            "pattern": "fixture-agent.exe", "score": 40})

    def test_reports_invalid_field_paths(self):
        for text, field in (
            (EXAMPLE.replace("field: command", "field: executable"), "conditions.field"),
            (EXAMPLE.replace("base_score: 40", "base_score: true"), "risk.base_score"),
            (EXAMPLE.replace("schema_version: 1", "schema_version: 2"), "schema_version"),
            (EXAMPLE.replace("alert_only", "quarantine"), "response.action"),
            (EXAMPLE + "enabled: true\n", "enabled"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(RuleYAMLError, field):
                parse_rule_yaml(text)

    def test_rejects_duplicate_fields_anchors_tags_multiple_documents_and_oversize(self):
        for text, reason in (
            (EXAMPLE + "title: Second title\n", "Duplicate YAML field 'title' at line"),
            (EXAMPLE.replace("Fixture rule", "&ref Fixture rule"), "anchors"),
            (EXAMPLE.replace("Fixture rule", "*ref"), "aliases"),
            (EXAMPLE.replace("Fixture rule", "!!str Fixture rule"), "explicit tags"),
            (EXAMPLE + "---\ntitle: Extra\n", "one rule document"),
            (EXAMPLE + "#" + "a" * MAX_RULE_YAML_BYTES, "16 KiB"),
            ("value: " + "[" * 20 + "1" + "]" * 20, "nesting depth"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(RuleYAMLError, reason):
                parse_rule_yaml(text)
