from dataclasses import dataclass, field

from persistguard.normalize_inventory import ArtifactCommand


@dataclass(frozen=True)
class CustomRule:
    name: str
    source: str
    field: str
    pattern: str
    score: int
    _needle: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_needle", self.pattern.casefold())

    def matches(self, path: str, commands: list[ArtifactCommand]) -> bool:
        if self.field == "path":
            return self._needle in path.casefold()
        return any(self._needle in command_text(command).casefold() for command in commands)


def command_text(command: ArtifactCommand) -> str:
    if command.command_line is not None:
        return command.command_line
    return " ".join(part for part in (command.executable, command.arguments) if part)
