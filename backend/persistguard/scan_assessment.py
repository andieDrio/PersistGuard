from typing import get_args

from pydantic import ValidationError

from persistguard.assess_inventory import ArtifactEvidence, assess_inventory
from persistguard.custom_rules import CustomRule
from persistguard.normalize_inventory import Source, normalize_inventory
from persistguard.scan_baseline import compare_inventory


def assess_scan_report(report: dict, endpoint_id: str, baseline_report: dict | None = None,
                       rules: tuple[CustomRule, ...] = (), indicators: frozenset[tuple[str, str]] = frozenset(),
                       *, target_source: Source | None = None) -> dict:
    collectors = report.get("collectors") if isinstance(report, dict) else None
    if not isinstance(collectors, dict):
        collectors = {}
    previous_collectors = baseline_report.get("collectors") if isinstance(baseline_report, dict) else None

    results = {}
    for source in (target_source,) if target_source else get_args(Source):
        collector = collectors.get(source)
        if not isinstance(collector, dict):
            results[source] = {"status": "error", "error": "missing_collector_report", "coverage": [], "assessments": []}
            continue

        raw = collector.get("report")
        status = collector.get("status")
        if status not in ("collected", "partial", "error"):
            status = "error"
        if raw is None:
            reason = collector.get("error")
            results[source] = {
                "status": "error", "error": reason if isinstance(reason, str) and reason else "missing_collector_report",
                "coverage": [], "assessments": [],
            }
            continue

        try:
            normalized = normalize_inventory(source, raw)
        except ValidationError:
            coverage = raw.get("coverage") if isinstance(raw, dict) else None
            results[source] = {
                "status": "error", "error": "invalid_collector_report",
                "coverage": coverage if isinstance(coverage, list) else [coverage] if isinstance(coverage, dict) else [],
                "assessments": [],
            }
            continue

        comparisons = ["unknown"] * len(normalized.artifacts)
        previous = previous_collectors.get(source) if isinstance(previous_collectors, dict) else None
        if isinstance(previous, dict) and previous.get("status") in ("collected", "partial"):
            try:
                baseline = normalize_inventory(source, previous.get("report"))
            except ValidationError:
                pass
            else:
                comparisons = compare_inventory(normalized, baseline, current_status=status, baseline_status=previous["status"])

        evidence = {index: ArtifactEvidence(is_new=True) for index, value in enumerate(comparisons) if value == "new"}
        source_rules = tuple(rule for rule in rules if rule.source == source)
        assessment = assess_inventory(normalized, endpoint_id, evidence, source_rules, indicators)
        for artifact, comparison in zip(assessment["assessments"], comparisons, strict=True):
            artifact["baseline_status"] = comparison
        results[source] = {
            "status": status,
            "coverage": assessment["coverage"],
            "assessments": assessment["assessments"],
        }

    statuses = [result["status"] for result in results.values()]
    status = "partial"
    if all(value == "collected" for value in statuses):
        status = "collected"
    elif all(value == "error" for value in statuses):
        status = "error"
    return {"schema_version": 1, "endpoint_id": endpoint_id, "status": status, "collectors": results}
