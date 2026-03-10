import unittest
from threading import Event
from unittest.mock import patch

from dnscrypt_sorter.latency import ProbeOptions, measure_resolver, summarize_samples
from dnscrypt_sorter.models import GeoLocation, Resolver


def make_resolver() -> Resolver:
    return Resolver(
        catalog="public-resolvers",
        name="dnscry.pt-paris-ipv4",
        proto="DNSCrypt",
        stamp="sdns://AQcAAAAAAAAA",
        country="France",
        description="Paris, France DNSCrypt resolver",
        dnssec=True,
        nofilter=True,
        nolog=True,
        ipv6=False,
        addrs=("51.158.147.132",),
        ports=(443,),
        location=GeoLocation(lat=48.8566, lon=2.3522),
    )


class LatencyTests(unittest.TestCase):
    def test_summarize_samples_returns_mean_stderr_and_reliability(self) -> None:
        mean_value, stderr, reliability = summarize_samples([0.05, 0.07], attempts=3)

        self.assertAlmostEqual(mean_value, 0.06, places=6)
        self.assertAlmostEqual(stderr, 0.0070710678, places=6)
        self.assertAlmostEqual(reliability, 2 / 3, places=6)

    def test_measure_resolver_aggregates_successful_attempts(self) -> None:
        options = ProbeOptions(attempts=3, ping_delay=0.0, timeout=0.5, tcp_only=False)
        responses = [(0.05, 443), (None, None), (0.07, 443)]

        with patch("dnscrypt_sorter.latency.probe_once", side_effect=responses):
            result = measure_resolver(make_resolver(), options)

        assert result is not None
        self.assertEqual(result.port, 443)
        self.assertEqual(result.successful_attempts, 2)
        self.assertEqual(result.attempted_probes, 3)
        self.assertAlmostEqual(result.reliability, 2 / 3, places=6)

    def test_measure_resolver_stops_when_cancelled(self) -> None:
        options = ProbeOptions(attempts=3, ping_delay=0.0, timeout=0.5, tcp_only=False)
        cancel_event = Event()
        cancel_event.set()

        result = measure_resolver(make_resolver(), options, cancel_event=cancel_event)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
