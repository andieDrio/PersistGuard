import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


BASELINE = Path(__file__).resolve().parents[2] / "XDRCapabilities.md"
GROUP = re.compile(r"^### ([A-Z])\. (.+)$")
USE_CASE = re.compile(r"^\|\s*([^|]+?)\s*\|\s*(T\d{4}(?:\.\d{3})?)\s*\|\s*(P[123])\s*\|$")


@dataclass(frozen=True)
class CoverageEvidence:
    telemetry: str
    rule: str
    validation: str


EVIDENCE = {
    ("D", "Registry Run Keys/Startup Folder", "T1547.001"): CoverageEvidence(
        "Run and RunOnce Registry inventory. Startup Folder inventory is pending.",
        "New-entry scoring for comparable HKLM Run and RunOnce scopes. HKCU lacks a comparable user identity.",
        "Fixture tests cover a new HKLM entry, an existing entry, and unavailable baseline scopes.",
    ),
    ("D", "Scheduled task persistence", "T1053.005"): CoverageEvidence(
        "Read-only Windows Scheduled Task inventory.",
        "New-task scoring when both snapshots have complete collector coverage.",
        "Fixture tests cover a newly inventoried task, an existing task, and incomplete collection.",
    ),
    ("D", "Windows service persistence", "T1543.003"): CoverageEvidence(
        "Read-only Windows Service inventory.",
        "New-service scoring when both snapshots have complete collector coverage.",
        "Fixture tests cover a newly inventoried service, an existing service, and incomplete collection.",
    ),
}


@dataclass(frozen=True)
class CoverageUseCase:
    id: str
    group: str
    use_case: str
    technique_id: str
    priority: str
    coverage: Literal["partial", "planned"]
    evidence: CoverageEvidence | None


def parse_attack_coverage(markdown: str) -> list[CoverageUseCase]:
    rows = []
    group = None
    seen = set()
    identifiers = set()
    in_catalog = False
    for line in markdown.splitlines():
        if line.startswith("## "):
            if in_catalog:
                break
            in_catalog = line.startswith("## 2. MITRE ATT&CK DETECTION CATALOG")
        if not in_catalog:
            continue
        if heading := GROUP.fullmatch(line):
            group = heading.groups()
            continue
        if match := USE_CASE.fullmatch(line):
            if group is None:
                raise ValueError("XDR catalog use case has no group")
            name, technique, priority = match.groups()
            key = (group[0], name, technique)
            if key in seen:
                raise ValueError("Duplicate XDR catalog use case")
            seen.add(key)
            identifier = f"{group[0]}-{technique}"
            if identifier in identifiers:
                raise ValueError("Duplicate XDR catalog identifier")
            identifiers.add(identifier)
            evidence = EVIDENCE.get(key)
            rows.append(CoverageUseCase(identifier, group[1].title(), name, technique, priority,
                                        "partial" if evidence else "planned", evidence))
    if not rows or EVIDENCE.keys() - seen:
        raise ValueError("XDR catalog is missing required use cases")
    return rows


def attack_coverage() -> list[CoverageUseCase]:
    return parse_attack_coverage(BASELINE.read_text(encoding="utf-8-sig"))
