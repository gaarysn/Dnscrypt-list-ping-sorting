from __future__ import annotations

import base64
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.request import urlopen

from .models import Resolver

DEFAULT_CATALOG = "public-resolvers"
DEFAULT_SOURCE_URL = "https://download.dnscrypt.info/resolvers-list/json/public-resolvers.json"


@dataclass(frozen=True, slots=True)
class CatalogSpec:
    name: str
    url: str
    cache_name: str
    format: str


OFFICIAL_CATALOGS: dict[str, CatalogSpec] = {
    "public-resolvers": CatalogSpec(
        name="public-resolvers",
        url="https://download.dnscrypt.info/resolvers-list/json/public-resolvers.json",
        cache_name="public-resolvers.json",
        format="json",
    ),
    "relays": CatalogSpec(
        name="relays",
        url="https://download.dnscrypt.info/resolvers-list/v3/relays.md",
        cache_name="relays.md",
        format="markdown",
    ),
    "parental-control": CatalogSpec(
        name="parental-control",
        url="https://download.dnscrypt.info/resolvers-list/v3/parental-control.md",
        cache_name="parental-control.md",
        format="markdown",
    ),
    "opennic": CatalogSpec(
        name="opennic",
        url="https://download.dnscrypt.info/resolvers-list/v3/opennic.md",
        cache_name="opennic.md",
        format="markdown",
    ),
    "onion-services": CatalogSpec(
        name="onion-services",
        url="https://download.dnscrypt.info/resolvers-list/v3/onion-services.md",
        cache_name="onion-services.md",
        format="markdown",
    ),
    "odoh-servers": CatalogSpec(
        name="odoh-servers",
        url="https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md",
        cache_name="odoh-servers.md",
        format="markdown",
    ),
    "odoh-relays": CatalogSpec(
        name="odoh-relays",
        url="https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md",
        cache_name="odoh-relays.md",
        format="markdown",
    ),
}


class SourceError(RuntimeError):
    """Raised when the resolver catalog cannot be loaded."""


def available_catalog_names() -> tuple[str, ...]:
    return tuple(OFFICIAL_CATALOGS.keys())


def expand_catalogs(catalogs: Iterable[str] | None) -> list[str]:
    requested = list(catalogs or [DEFAULT_CATALOG])
    if "all" in requested:
        return list(available_catalog_names())
    return requested


def fetch_catalogs(catalogs: Iterable[str], cache_dir: Path, timeout: float = 15.0) -> list[Resolver]:
    resolved_catalogs = expand_catalogs(catalogs)
    cache_dir.mkdir(parents=True, exist_ok=True)

    collected: list[Resolver] = []
    seen: set[tuple[str, str, str]] = set()

    for catalog_name in resolved_catalogs:
        spec = OFFICIAL_CATALOGS[catalog_name]
        payload = fetch_payload(spec.url, cache_dir / spec.cache_name, timeout=timeout)
        parsed = parse_payload(payload, catalog_name=catalog_name, payload_format=spec.format)
        for resolver in parsed:
            key = (resolver.catalog, resolver.name, resolver.stamp)
            if key in seen:
                continue
            seen.add(key)
            collected.append(resolver)
    return collected


def fetch_catalog(source_url: str, cache_file: Path, timeout: float = 15.0) -> list[Resolver]:
    payload = fetch_payload(source_url, cache_file, timeout=timeout)
    payload_format = "json" if source_url.endswith(".json") else "markdown"
    return parse_payload(payload, catalog_name=DEFAULT_CATALOG, payload_format=payload_format)


def fetch_payload(source_url: str, cache_file: Path, timeout: float = 15.0) -> str:
    payload = None
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with urlopen(source_url, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
        cache_file.write_text(payload, encoding="utf-8")
    except (URLError, TimeoutError, OSError):
        if cache_file.is_file():
            payload = cache_file.read_text(encoding="utf-8")
        else:
            raise SourceError(f"Unable to download resolver catalog from {source_url}")
    return payload


def parse_payload(payload: str, catalog_name: str, payload_format: str) -> list[Resolver]:
    if payload_format == "json":
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SourceError("Resolver catalog is not valid JSON") from exc
        if not isinstance(decoded, list):
            raise SourceError("Resolver catalog JSON root must be a list")
        return list(parse_catalog(decoded, catalog_name=catalog_name))

    if payload_format == "markdown":
        return list(parse_markdown_catalog(payload, catalog_name=catalog_name))

    raise SourceError(f"Unsupported catalog format: {payload_format}")


def parse_catalog(items: Iterable[object], catalog_name: str = DEFAULT_CATALOG) -> Iterable[Resolver]:
    for item in items:
        if not isinstance(item, dict):
            continue
        normalized = dict(item)
        normalized["catalog"] = catalog_name
        resolver = Resolver.from_dict(normalized)
        if resolver.name and resolver.stamp:
            yield resolver


def parse_markdown_catalog(markdown: str, catalog_name: str) -> Iterable[Resolver]:
    current_name: str | None = None
    description_lines: list[str] = []
    stamps: list[str] = []

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        if line.startswith("## "):
            if current_name and stamps:
                yield from build_markdown_resolvers(
                    catalog_name=catalog_name,
                    section_name=current_name,
                    description="\n".join(description_lines).strip(),
                    stamps=stamps,
                )
            current_name = line[3:].strip()
            description_lines = []
            stamps = []
            continue

        if current_name is None:
            continue

        if line.startswith("sdns://"):
            stamps.append(line.strip())
        else:
            description_lines.append(line)

    if current_name and stamps:
        yield from build_markdown_resolvers(
            catalog_name=catalog_name,
            section_name=current_name,
            description="\n".join(description_lines).strip(),
            stamps=stamps,
        )


def build_markdown_resolvers(
    catalog_name: str,
    section_name: str,
    description: str,
    stamps: list[str],
) -> Iterable[Resolver]:
    country = infer_country(section_name, description)
    for index, stamp in enumerate(stamps, start=1):
        decoded = decode_stamp(stamp)
        if decoded is None:
            continue
        name = section_name if len(stamps) == 1 else f"{section_name}-{index}"
        payload = {
            "catalog": catalog_name,
            "name": name,
            "proto": decoded["proto"],
            "stamp": stamp,
            "country": country,
            "description": description,
            "dnssec": decoded["dnssec"],
            "nofilter": decoded["nofilter"],
            "nolog": decoded["nolog"],
            "ipv6": decoded["ipv6"],
            "addrs": list(decoded["addrs"]),
            "ports": list(decoded["ports"]),
            "location": None,
        }
        yield Resolver.from_dict(payload)


def decode_stamp(stamp: str) -> dict[str, object] | None:
    raw = stamp.removeprefix("sdns://")
    raw += "=" * (-len(raw) % 4)
    try:
        data = base64.urlsafe_b64decode(raw)
    except (ValueError, base64.binascii.Error):
        return None

    if not data:
        return None

    proto_id = data[0]
    if proto_id in {0x01, 0x02, 0x05}:
        if len(data) < 10:
            return None
        props = int.from_bytes(data[1:9], "little")
        address, offset = read_lp_string(data, 9)
        addrs, ports = split_host_port_list(address)

        if proto_id == 0x01:
            offset += 32
            _, _ = read_lp_string(data, offset)
            proto = "DNSCrypt"
        elif proto_id == 0x02:
            offset += 32
            hostname, offset = read_lp_string(data, offset)
            _, _ = read_lp_string(data, offset)
            if not addrs and hostname:
                addrs, ports = split_host_port_list(hostname, default_port=443)
            proto = "DoH"
        else:
            hostname, offset = read_lp_string(data, 9)
            _, _ = read_lp_string(data, offset)
            addrs, ports = split_host_port_list(hostname, default_port=443)
            proto = "ODoH"

        return {
            "proto": proto,
            "dnssec": bool(props & 0x01),
            "nolog": bool(props & 0x02),
            "nofilter": bool(props & 0x04),
            "ipv6": any(is_ipv6_address(addr) for addr in addrs),
            "addrs": addrs,
            "ports": ports,
        }

    if proto_id in {0x81, 0x85}:
        address, _ = read_lp_string(data, 1)
        addrs, ports = split_host_port_list(address)
        return {
            "proto": "ODoH relay" if proto_id == 0x85 else "DNSCrypt relay",
            "dnssec": False,
            "nolog": False,
            "nofilter": False,
            "ipv6": any(is_ipv6_address(addr) for addr in addrs),
            "addrs": addrs,
            "ports": ports,
        }

    return None


def read_lp_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(data):
        return "", offset
    length = data[offset]
    offset += 1
    end = min(len(data), offset + length)
    return data[offset:end].decode("utf-8", errors="replace"), end


def split_host_port_list(address: str, default_port: int | None = None) -> tuple[tuple[str, ...], tuple[int, ...]]:
    if not address:
        return tuple(), tuple()

    host, port = split_host_port(address)
    ports = (port,) if port is not None else ((default_port,) if default_port is not None else tuple())
    return (host,), ports


def split_host_port(address: str) -> tuple[str, int | None]:
    if address.startswith("[") and "]" in address:
        host, remainder = address[1:].split("]", 1)
        if remainder.startswith(":") and remainder[1:].isdigit():
            return host, int(remainder[1:])
        return host, None

    if address.count(":") == 1:
        host, maybe_port = address.rsplit(":", 1)
        if maybe_port.isdigit():
            return host, int(maybe_port)

    return address, None


def is_ipv6_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return ":" in value
    except ValueError:
        return False


def infer_country(name: str, description: str) -> str:
    haystack = f"{name}\n{description}"
    patterns = (
        r"\b(?:in|based in|hosted in)\s+([A-Z][A-Za-z]+(?:[ -][A-Z][A-Za-z]+)*)\b",
        r"^([A-Z][A-Za-z]+(?:[ -][A-Z][A-Za-z]+)*)\s*,",
    )
    for pattern in patterns:
        match = re.search(pattern, haystack, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
    return ""
