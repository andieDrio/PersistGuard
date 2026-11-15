import argparse
import json
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, JsonValue


Source = Literal["registry", "scheduled_tasks", "services"]


def parse_sha256(value: object) -> str | None:
    return value.lower() if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) else None


ExecutableSHA256 = Annotated[str | None, BeforeValidator(parse_sha256)]


class ArtifactCommand(BaseModel):
    command_line: str | None = None
    executable: str | None = None
    arguments: str | None = None
    working_directory: str | None = None
    action_index: int | None = None
    executable_sha256: ExecutableSHA256 = None


class CollectedArtifact(BaseModel):
    mechanism: str
    path: str
    commands: list[ArtifactCommand]
    metadata: dict[str, JsonValue]


class NormalizedInventory(BaseModel):
    schema_version: Literal[1] = 1
    os_family: Literal["windows"] = "windows"
    source: Source
    artifacts: list[CollectedArtifact]
    coverage: list[dict[str, JsonValue]]


class CollectorData(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")


class RegistryEntry(CollectorData):
    mechanism: Literal["registry_run_key", "registry_run_once_key"]
    hive: Literal["HKCU", "HKLM"]
    key_path: str
    registry_view: Literal["shared", "32-bit", "64-bit"]
    value_name: str
    value_type: Literal["REG_SZ", "REG_EXPAND_SZ"]
    command: str
    executable_sha256: ExecutableSHA256 = None


class TaskAction(CollectorData):
    type: str
    command: str | None = None
    arguments: str | None = None
    working_directory: str | None = None
    executable_sha256: ExecutableSHA256 = None


class ScheduledTaskEntry(CollectorData):
    mechanism: Literal["scheduled_task"]
    path: str
    actions: list[TaskAction]
    triggers: list[dict[str, JsonValue]]
    state: str
    enabled: bool
    hidden: bool


class ServiceEntry(CollectorData):
    mechanism: Literal["windows_service"]
    name: str
    display_name: str
    state: str
    command: str | None = None
    executable_sha256: ExecutableSHA256 = None


class Coverage(CollectorData):
    status: Literal["collected", "partial", "error"]


class RegistryCoverage(Coverage):
    status: Literal["collected", "partial", "error", "absent"]
    hive: Literal["HKCU", "HKLM"]
    key_path: str
    registry_view: Literal["shared", "32-bit", "64-bit"]


class ScheduledTaskCoverage(Coverage):
    folders_visited: int = Field(ge=0)


class CollectorReport(CollectorData):
    os_family: Literal["windows"]


class RegistryReport(CollectorReport):
    entries: list[RegistryEntry]
    coverage: list[RegistryCoverage]


class ScheduledTasksReport(CollectorReport):
    entries: list[ScheduledTaskEntry]
    coverage: ScheduledTaskCoverage


class ServicesReport(CollectorReport):
    entries: list[ServiceEntry]
    coverage: Coverage


def normalize_inventory(source: Source, document: object) -> NormalizedInventory:
    if source == "registry":
        report = RegistryReport.model_validate(document)
        artifacts = [
            CollectedArtifact(
                mechanism=entry.mechanism,
                path=f"{entry.hive}\\{entry.key_path}",
                commands=[ArtifactCommand(command_line=entry.command, executable_sha256=entry.executable_sha256)],
                metadata=entry.model_dump(exclude={"mechanism", "command", "executable_sha256"}),
            )
            for entry in report.entries
        ]
        coverage = [result.model_dump() for result in report.coverage]
    elif source == "scheduled_tasks":
        report = ScheduledTasksReport.model_validate(document)
        artifacts = [
            CollectedArtifact(
                mechanism=entry.mechanism,
                path=entry.path,
                commands=[
                    ArtifactCommand(
                        executable=action.command,
                        arguments=action.arguments,
                        working_directory=action.working_directory,
                        action_index=index,
                        executable_sha256=action.executable_sha256,
                    )
                    for index, action in enumerate(entry.actions)
                    if action.type == "Exec" and action.command is not None
                ],
                metadata=entry.model_dump(exclude={"mechanism", "path"}, exclude_unset=True),
            )
            for entry in report.entries
        ]
        coverage = [report.coverage.model_dump()]
    elif source == "services":
        report = ServicesReport.model_validate(document)
        artifacts = [
            CollectedArtifact(
                mechanism=entry.mechanism,
                path=entry.name,
                commands=[] if entry.command is None else [ArtifactCommand(command_line=entry.command,
                                                                            executable_sha256=entry.executable_sha256)],
                metadata=entry.model_dump(exclude={"mechanism", "name", "command", "executable_sha256"}),
            )
            for entry in report.entries
        ]
        coverage = [report.coverage.model_dump()]
    else:
        raise ValueError("Unknown Windows inventory source")
    return NormalizedInventory(source=source, artifacts=artifacts, coverage=coverage)


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize a local Windows inventory report into artifact JSON")
    parser.add_argument("--source", required=True, choices=("registry", "scheduled_tasks", "services"))
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.inventory.read_bytes())
        inventory = normalize_inventory(args.source, document)
    except OSError:
        parser.exit(1, "Could not read the inventory file.\n")
    except ValueError:
        parser.exit(1, "The file is not a valid Windows inventory report for the selected source.\n")
    print(json.dumps(inventory.model_dump(mode="json", exclude_none=True), ensure_ascii=True))


if __name__ == "__main__":
    main()
