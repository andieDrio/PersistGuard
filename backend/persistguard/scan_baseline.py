from typing import Literal

from persistguard.normalize_inventory import CollectedArtifact, NormalizedInventory


BaselineStatus = Literal["new", "existing", "unknown"]


def registry_scope(values: dict) -> tuple[str, str, str] | None:
    hive, path, view = (values.get(key) for key in ("hive", "key_path", "registry_view"))
    # The report has no user SID, so HKCU keys cannot safely be compared across runs.
    if hive != "HKLM" or not isinstance(path, str) or not isinstance(view, str):
        return None
    return hive, path.casefold(), view


def artifact_key(inventory: NormalizedInventory, artifact: CollectedArtifact) -> tuple[str, ...] | None:
    if inventory.source != "registry":
        return (artifact.path.casefold(),)
    scope = registry_scope(artifact.metadata)
    name = artifact.metadata.get("value_name")
    if scope is None or not isinstance(name, str):
        return None
    return (*scope, name.casefold())


def compare_inventory(
    current: NormalizedInventory, baseline: NormalizedInventory, *, current_status: str, baseline_status: str,
) -> list[BaselineStatus]:
    if current.source != baseline.source or "error" in (current_status, baseline_status):
        return ["unknown"] * len(current.artifacts)

    if current.source == "registry":
        covered_now = {registry_scope(result) for result in current.coverage if result.get("status") == "collected"}
        covered_before = {
            registry_scope(result) for result in baseline.coverage if result.get("status") in ("collected", "absent")
        }
        comparable = covered_now & covered_before
    elif (current_status != "collected" or baseline_status != "collected" or
          any(result.get("status") != "collected" for result in current.coverage + baseline.coverage)):
        return ["unknown"] * len(current.artifacts)

    known = {artifact_key(baseline, artifact) for artifact in baseline.artifacts}
    comparisons: list[BaselineStatus] = []
    for artifact in current.artifacts:
        key = artifact_key(current, artifact)
        if key is None or (current.source == "registry" and key[:3] not in comparable):
            comparisons.append("unknown")
        else:
            comparisons.append("existing" if key in known else "new")
    return comparisons
