from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable

from .models import Resolver

SUPPORTED_PROTOCOLS = (
    "DNSCrypt",
    "DoH",
    "ODoH",
    "DNSCrypt relay",
    "ODoH relay",
)

IP_VERSION_OPTIONS = ("any", "ipv4", "ipv6")


@dataclass(frozen=True, slots=True)
class ResolverFilterCriteria:
    allowed_protocols: frozenset[str] | None = None
    require_nofilter: bool = False
    require_nolog: bool = False
    require_dnssec: bool = False
    ip_version: str = "any"
    countries: tuple[str, ...] = ()


def filter_resolvers(
    resolvers: Iterable[Resolver],
    criteria: ResolverFilterCriteria | None = None,
) -> list[Resolver]:
    criteria = criteria or ResolverFilterCriteria()
    validate_filter_criteria(criteria)
    return [resolver for resolver in resolvers if is_target_resolver(resolver, criteria=criteria)]


def is_target_resolver(
    resolver: Resolver,
    criteria: ResolverFilterCriteria | None = None,
) -> bool:
    criteria = criteria or ResolverFilterCriteria()
    validate_filter_criteria(criteria)

    if not is_measurable(resolver):
        return False
    if criteria.allowed_protocols is not None and resolver.proto not in criteria.allowed_protocols:
        return False
    if criteria.require_nofilter and not resolver.nofilter:
        return False
    if criteria.require_nolog and not resolver.nolog:
        return False
    if criteria.require_dnssec and not resolver.dnssec:
        return False
    if not matches_ip_version(resolver, criteria.ip_version):
        return False
    if criteria.countries and not matches_countries(resolver, criteria.countries):
        return False
    return True


def validate_filter_criteria(criteria: ResolverFilterCriteria) -> None:
    if criteria.ip_version not in IP_VERSION_OPTIONS:
        raise ValueError(f"Unsupported ip_version: {criteria.ip_version}")


def is_measurable(resolver: Resolver) -> bool:
    return resolver.stamp.startswith("sdns://") and bool(resolver.addrs)


def matches_ip_version(resolver: Resolver, ip_version: str) -> bool:
    if ip_version == "any":
        return True
    has_ipv6 = any(is_ipv6_candidate(address) for address in resolver.addrs)
    has_ipv4 = any(not is_ipv6_candidate(address) for address in resolver.addrs)
    if ip_version == "ipv4":
        return has_ipv4
    if ip_version == "ipv6":
        return has_ipv6
    raise ValueError(f"Unsupported ip_version: {ip_version}")


def matches_countries(resolver: Resolver, countries: tuple[str, ...]) -> bool:
    haystack = "\n".join((resolver.country, resolver.name, resolver.description)).lower()
    return any(re.search(rf"\b{re.escape(country.lower())}\b", haystack) for country in countries)


def is_ipv6_candidate(value: str) -> bool:
    return ":" in value


def describe_filter_criteria(criteria: ResolverFilterCriteria) -> str:
    parts: list[str] = []
    if criteria.require_nofilter:
        parts.append("nofilter")
    if criteria.require_nolog:
        parts.append("nolog")
    if criteria.require_dnssec:
        parts.append("dnssec")
    if criteria.ip_version != "any":
        parts.append(criteria.ip_version)
    if criteria.countries:
        parts.append(f"countries={', '.join(criteria.countries)}")
    if not parts:
        return "measurable endpoints only"
    return ", ".join(parts)
