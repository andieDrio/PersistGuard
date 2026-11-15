import argparse
import json
import ntpath
import re
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field

from persistguard.custom_rules import CustomRule
from persistguard.detection import Artifact, assess
from persistguard.ioc_matching import IOC_MATCH_POINTS, match_iocs
from persistguard.normalize_inventory import ArtifactCommand, NormalizedInventory


class ArtifactEvidence(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    signature_status: Literal["unknown", "valid", "invalid", "unsigned"] = "unknown"
    is_new: bool = False
    user_writable_executable: bool = False
    known_malicious_hash: bool = False


class EvidenceFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    artifacts: dict[int, ArtifactEvidence]


RAW_EXECUTABLE = re.compile(r'^(?:"([^"\r\n]+)"|([^\s"\r\n]+))(?=\s|$)')
ENCODED_ARGUMENT = re.compile(r"^\s*-(?:encodedcommand|enc)\s+\S", re.IGNORECASE)
PERSISTENCE_TECHNIQUES = {
    "registry_run_key": "T1547.001",
    "registry_run_once_key": "T1547.001",
    "scheduled_task": "T1053.005",
    "windows_service": "T1543.003",
}


def command_parts(command: ArtifactCommand) -> tuple[str | None, str]:
    if command.command_line is None:
        return command.executable, command.arguments or ""
    command_line = command.command_line.lstrip()
    parsed = RAW_EXECUTABLE.match(command_line)
    if parsed is None:
        return None, ""
    quoted, unquoted = parsed.groups()
    return quoted or unquoted, command_line[parsed.end():]


def has_encoded_command(command: ArtifactCommand) -> bool:
    executable, arguments = command_parts(command)
    if not executable or ntpath.basename(executable.strip('"')).lower() not in {
        "powershell", "powershell.exe", "pwsh", "pwsh.exe"
    }:
        return False
    return ENCODED_ARGUMENT.match(arguments) is not None


def assess_inventory(
    inventory: NormalizedInventory, endpoint_id: str, evidence: Mapping[int, ArtifactEvidence],
    rules: tuple[CustomRule, ...] = (), indicators: frozenset[tuple[str, str]] = frozenset(),
) -> dict:
    if any(index < 0 or index >= len(inventory.artifacts) for index in evidence):
        raise ValueError("Evidence references an artifact outside the report")

    results = []
    for index, record in enumerate(inventory.artifacts):
        verified = evidence.get(index)
        signals = verified.model_dump() if verified is not None else {}
        artifact = Artifact(
            endpoint_id=endpoint_id,
            os_family=inventory.os_family,
            mechanism=record.mechanism,
            path=record.path,
            encoded_command=any(has_encoded_command(command) for command in record.commands),
            **signals,
        )
        custom_signals = tuple((rule.score, f"Rule: {rule.name}") for rule in rules if rule.matches(record.path, record.commands))
        if indicators:
            matches = match_iocs((command_parts(command)[1] for command in record.commands), indicators,
                                 (command.executable_sha256 for command in record.commands if command.executable_sha256))
            if matches:
                labels = {"domain": "domain", "ip": "IP", "url": "URL", "sha256": "SHA-256"}
                values = ", ".join(f"{labels[kind]} {value}" for kind, value in matches)
                custom_signals += ((IOC_MATCH_POINTS, f"IOC match: {values}"),)
        result = {"artifact_index": index, "mechanism": record.mechanism, "path": record.path,
                  **assess(artifact, custom_signals)}
        if result["score"] > 0 and (technique := PERSISTENCE_TECHNIQUES.get(record.mechanism)):
            result["attack_technique"] = technique
        results.append(result)

    return {
        "schema_version": 1,
        "endpoint_id": endpoint_id,
        "os_family": inventory.os_family,
        "source": inventory.source,
        "coverage": inventory.coverage,
        "assessments": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Assess a normalized Windows artifact inventory locally")
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--endpoint-id", required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        raw = args.inventory.read_bytes()
        inventory = NormalizedInventory.model_validate(json.loads(raw))
        digest = sha256(raw).hexdigest()
        evidence = {}
        if args.evidence is not None:
            provided = EvidenceFile.model_validate(json.loads(args.evidence.read_bytes()))
            if provided.report_sha256 != digest:
                parser.exit(1, "The evidence file belongs to a different inventory.\n")
            evidence = provided.artifacts
        result = assess_inventory(inventory, args.endpoint_id, evidence)
    except OSError:
        parser.exit(1, "Could not read the inventory or evidence file.\n")
    except ValueError:
        parser.exit(1, "The inventory or evidence is invalid.\n")
    print(json.dumps({"report_sha256": digest, **result}, ensure_ascii=True))


if __name__ == "__main__":
    main()
