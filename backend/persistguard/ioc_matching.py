import re
from collections.abc import Iterable
from ipaddress import ip_address
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from persistguard.normalize_inventory import ArtifactCommand


IndicatorKind = Literal["ip", "domain", "sha256", "url"]
IOC_MATCH_POINTS = 60
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
ARGUMENT_TOKEN = re.compile(r'''(?<!\S)(?:[^\s"']|"[^"]*"|'[^']*')+(?=\s|$)''')
ASSIGNMENT = re.compile(r"(?:--?|/)?[a-zA-Z][\w-]*=(.+)")
AUTHORITY = re.compile(r"(?:\[(?P<ipv6>[^\[\]]+)\]|(?P<name>[^:/\\@?#\[\]]+))(?::(?P<port>[0-9]{1,5}))?")


def dns_name(value: str) -> str:
    name = value.encode("idna").decode("ascii").lower().removesuffix(".")
    if len(name) <= 253 and all(DNS_LABEL.fullmatch(label) for label in name.split(".")):
        return name
    raise ValueError("Invalid DNS name")


def host_indicator(value: str) -> tuple[str, str]:
    try:
        return "ip", str(ip_address(value))
    except ValueError:
        return "domain", dns_name(value)


def authority_indicator(value: str) -> tuple[tuple[str, str], int | None]:
    match = AUTHORITY.fullmatch(value)
    if match is None:
        raise ValueError("Invalid authority")
    host = host_indicator(match["ipv6"] or match["name"])
    port = int(match["port"]) if match["port"] is not None else None
    if (match["ipv6"] and (host[0] != "ip" or ":" not in host[1])) or (port is not None and not 1 <= port <= 65535):
        raise ValueError("Invalid address or port")
    return host, port


def url_indicator(value: str) -> tuple[str, tuple[str, str]]:
    if any(character in '\\"\'<>' or character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("Invalid URL token")
    url = urlsplit(value)
    if url.scheme not in {"http", "https"}:
        raise ValueError("Invalid HTTP(S) URL")
    host, port = authority_indicator(url.netloc)
    authority = f"[{host[1]}]" if ":" in host[1] else host[1]
    default_port = 443 if url.scheme == "https" else 80
    if port is not None and port != default_port:
        authority += f":{port}"
    return urlunsplit((url.scheme, authority, url.path or "/", url.query, url.fragment)), host


def normalize_indicator(kind: IndicatorKind, value: str) -> str:
    if len(value.encode("utf-8")) > 2048 or any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("Indicator contains whitespace or control characters")
    if kind == "ip":
        return str(ip_address(value))
    if kind == "sha256" and re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return value.lower()
    if kind == "domain":
        name = dns_name(value)
        if "." in name:
            return name
    if kind == "url":
        url_indicator(value)
        return value
    raise ValueError("Invalid indicator")


def bare_host_indicator(value: str) -> tuple[str, str]:
    try:
        return "ip", str(ip_address(value))
    except ValueError:
        return authority_indicator(value)[0]


def build_ioc_index(indicators: Iterable[tuple[str, str]]) -> frozenset[tuple[str, str]]:
    index = set()
    for kind, value in indicators:
        if kind == "url":
            try:
                key, _ = url_indicator(value)
            except ValueError:
                continue
        elif kind in {"ip", "domain", "sha256"}:
            key = value
        else:
            continue
        index.add((kind, key))
    return frozenset(index)


def unquote(token: str) -> str:
    if len(token) >= 2 and token[0] in {'"', "'"} and token[-1] == token[0]:
        return token[1:-1]
    return token


def match_iocs(arguments: Iterable[str], index: frozenset[tuple[str, str]],
               executable_hashes: Iterable[str] = ()) -> list[tuple[str, str]]:
    matches = {("sha256", digest) for digest in executable_hashes if ("sha256", digest) in index}
    for argument in arguments:
        for match in ARGUMENT_TOKEN.finditer(argument):
            token = unquote(match[0])
            assignment = ASSIGNMENT.fullmatch(token)
            if assignment:
                token = unquote(assignment[1])
            if any(character in token for character in '"\'<>'):
                continue
            try:
                if token[:8].lower().startswith(("http://", "https://")):
                    address, host = url_indicator(token)
                    candidates = (("url", address), host)
                else:
                    candidates = (bare_host_indicator(token),)
            except ValueError:
                continue
            matches.update(candidate for candidate in candidates if candidate in index)
    return sorted(matches)
