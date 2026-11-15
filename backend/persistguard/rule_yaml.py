from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from persistguard.normalize_inventory import Source


MAX_RULE_YAML_BYTES = 16 * 1024
RuleTitle = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100, pattern=r"^[^\x00]+$")]
MatchText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[^\x00]+$")]
RuleField = Literal["path", "command"]
RuleScore = Annotated[int, Field(ge=1, le=100, strict=True)]


class RuleDefinition(BaseModel):
    name: RuleTitle
    source: Source
    field: RuleField
    pattern: MatchText
    score: RuleScore


class YAMLConditions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Source
    field: RuleField
    contains: MatchText


class YAMLRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_score: RuleScore


class YAMLResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["alert_only"]


class YAMLRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Annotated[int, Field(ge=1, le=1, strict=True)]
    title: RuleTitle
    platform: Literal["windows"]
    conditions: YAMLConditions
    risk: YAMLRisk
    response: YAMLResponse | None = None


class RuleYAMLError(ValueError):
    pass


def position(mark) -> str:
    return f"line {mark.line + 1}, column {mark.column + 1}"


class RuleLoader(yaml.SafeLoader):
    def __init__(self, text: str):
        super().__init__(text)
        self.depth = 0

    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) or getattr(event, "tag", None):
            raise RuleYAMLError(f"YAML aliases, anchors, and explicit tags are unsupported at {position(event.start_mark)}.")
        if self.depth >= 12:
            raise RuleYAMLError(f"YAML exceeds the supported nesting depth at {position(event.start_mark)}.")
        self.depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            if key_node.tag != "tag:yaml.org,2002:str":
                raise RuleYAMLError(f"YAML mapping keys must be text at {position(key_node.start_mark)}.")
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise RuleYAMLError(f"Duplicate YAML field {key!r} at {position(key_node.start_mark)}.")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def parse_rule_yaml(text: str) -> RuleDefinition:
    try:
        if len(text.encode("utf-8")) > MAX_RULE_YAML_BYTES:
            raise RuleYAMLError("Rule YAML exceeds the 16 KiB limit.")
    except UnicodeEncodeError as error:
        raise RuleYAMLError("Rule YAML must contain valid Unicode text.") from error
    try:
        loader = RuleLoader(text)
        try:
            raw = loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        location = f" at {position(mark)}" if mark is not None else ""
        raise RuleYAMLError(f"Invalid YAML{location}. Enter one rule document.") from error
    except (ValueError, OverflowError) as error:
        if isinstance(error, RuleYAMLError):
            raise
        raise RuleYAMLError("Invalid YAML scalar value.") from error
    if not isinstance(raw, dict):
        raise RuleYAMLError("Rule YAML must contain a single mapping.")
    try:
        rule = YAMLRule.model_validate(raw)
    except ValidationError as error:
        errors = error.errors(include_url=False, include_input=False, include_context=False)
        messages = [f"{'.'.join(map(str, item['loc']))}: {item['msg']}" for item in errors[:8]]
        raise RuleYAMLError(". ".join(messages)) from error
    return RuleDefinition(name=rule.title, source=rule.conditions.source, field=rule.conditions.field,
                          pattern=rule.conditions.contains, score=rule.risk.base_score)


def export_rule_yaml(rule: RuleDefinition) -> str:
    return yaml.safe_dump({
        "schema_version": 1,
        "title": rule.name,
        "platform": "windows",
        "conditions": {"source": rule.source, "field": rule.field, "contains": rule.pattern},
        "risk": {"base_score": rule.score},
        "response": {"action": "alert_only"},
    }, sort_keys=False, allow_unicode=True)
