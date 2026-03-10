import unittest

from dnscrypt_sorter.filters import ResolverFilterCriteria, filter_resolvers, is_target_resolver
from dnscrypt_sorter.models import GeoLocation, Resolver


def make_resolver(**overrides) -> Resolver:
    payload = {
        "catalog": "public-resolvers",
        "name": "dnscry.pt-paris-ipv4",
        "proto": "DNSCrypt",
        "stamp": "sdns://AQcAAAAAAAAA",
        "country": "France",
        "description": "Paris, France DNSCrypt resolver",
        "dnssec": True,
        "nofilter": True,
        "nolog": True,
        "ipv6": False,
        "addrs": ("51.158.147.132",),
        "ports": (443,),
        "location": GeoLocation(lat=48.8566, lon=2.3522),
    }
    payload.update(overrides)
    return Resolver(**payload)


class FilterResolversTests(unittest.TestCase):
    def test_accepts_measurable_resolver_by_default(self) -> None:
        resolver = make_resolver()
        self.assertTrue(is_target_resolver(resolver))

    def test_rejects_missing_stamp_or_address(self) -> None:
        missing_stamp = make_resolver(stamp="")
        missing_address = make_resolver(addrs=())

        self.assertFalse(is_target_resolver(missing_stamp))
        self.assertFalse(is_target_resolver(missing_address))

    def test_filter_resolvers_applies_protocol_filter(self) -> None:
        dnscrypt = make_resolver(proto="DNSCrypt")
        doh = make_resolver(name="doh-sample", proto="DoH")

        filtered = filter_resolvers(
            [dnscrypt, doh],
            criteria=ResolverFilterCriteria(allowed_protocols=frozenset({"DoH"})),
        )

        self.assertEqual([resolver.name for resolver in filtered], ["doh-sample"])

    def test_filter_resolvers_applies_privacy_and_dnssec_flags(self) -> None:
        candidates = [
            make_resolver(),
            make_resolver(name="with-logs", nolog=False),
            make_resolver(name="filtered", nofilter=False),
            make_resolver(name="no-dnssec", dnssec=False),
        ]

        filtered = filter_resolvers(
            candidates,
            criteria=ResolverFilterCriteria(require_nofilter=True, require_nolog=True, require_dnssec=True),
        )

        self.assertEqual([resolver.name for resolver in filtered], ["dnscry.pt-paris-ipv4"])

    def test_filter_resolvers_applies_ip_version_selection(self) -> None:
        ipv4 = make_resolver(name="ipv4")
        ipv6 = make_resolver(name="ipv6", ipv6=True, addrs=("[2001:db8::1]",))

        filtered = filter_resolvers(
            [ipv4, ipv6],
            criteria=ResolverFilterCriteria(ip_version="ipv6"),
        )

        self.assertEqual([resolver.name for resolver in filtered], ["ipv6"])

    def test_country_filter_matches_country_and_description(self) -> None:
        germany = make_resolver(name="doh-berlin", proto="DoH", country="", description="DoH server in Germany")
        france = make_resolver(name="dnscry.pt-paris-ipv4", country="France")

        filtered = filter_resolvers(
            [germany, france],
            criteria=ResolverFilterCriteria(countries=("Germany",)),
        )

        self.assertEqual([resolver.name for resolver in filtered], ["doh-berlin"])


if __name__ == "__main__":
    unittest.main()
