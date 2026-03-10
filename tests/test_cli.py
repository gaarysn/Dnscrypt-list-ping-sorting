import unittest
from argparse import Namespace
import json
import tempfile
from pathlib import Path

from dnscrypt_sorter.cli import (
    PROBE_PROFILES,
    RunArtifacts,
    build_default_export_name,
    build_text_export,
    describe_output_selection,
    expand_protocols,
    interrupt_hint,
    main_menu_options,
    normalize_country_filters,
    no_matches_message,
    resolve_filter_criteria,
    resolve_output_count,
    resolve_probe_options,
    save_results,
    should_prompt_for_selection,
    validate_country_list,
    validate_positive_int,
)
from dnscrypt_sorter.filters import ResolverFilterCriteria
from dnscrypt_sorter.models import GeoLocation, MeasurementResult, Resolver
from dnscrypt_sorter.ui import (
    RunSummary,
    compact_stamp,
    format_country,
    is_back_command,
    is_exit_command,
    parse_multi_select,
    render_plain_table,
    resolve_effective_stamp_mode,
    resolve_result_columns,
)


def make_result() -> MeasurementResult:
    resolver = Resolver(
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
    return MeasurementResult(
        resolver=resolver,
        address="51.158.147.132",
        port=443,
        latency_seconds=0.05,
        stderr_seconds=0.005,
        reliability=1.0,
        successful_attempts=3,
        attempted_probes=3,
    )


class CliHelpersTests(unittest.TestCase):
    def test_resolve_output_count_supports_top_and_all(self) -> None:
        self.assertEqual(resolve_output_count(Namespace(all=False, top=10), 87), 10)
        self.assertEqual(resolve_output_count(Namespace(all=True, top=10), 87), 87)

    def test_probe_profile_can_be_overridden(self) -> None:
        options = resolve_probe_options(
            Namespace(number_ping=None, ping_delay=None, time_out=None, tcp_only=False),
            PROBE_PROFILES["balanced"],
        )
        self.assertEqual(options.attempts, PROBE_PROFILES["balanced"].attempts)

        overridden = resolve_probe_options(
            Namespace(number_ping=9, ping_delay=0.2, time_out=1.5, tcp_only=True),
            PROBE_PROFILES["fast"],
        )
        self.assertEqual(overridden.attempts, 9)
        self.assertEqual(overridden.ping_delay, 0.2)
        self.assertEqual(overridden.timeout, 1.5)
        self.assertTrue(overridden.tcp_only)

    def test_compact_stamp_shortens_long_values(self) -> None:
        stamp = "sdns://ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        compact = compact_stamp(stamp, prefix=8, suffix=6)
        self.assertTrue(compact.startswith("sdns://A"))
        self.assertTrue(compact.endswith("456789"))
        self.assertIn("...", compact)

    def test_effective_stamp_mode_hides_stamp_on_narrow_width(self) -> None:
        self.assertEqual(resolve_effective_stamp_mode(120, "compact"), "hidden")
        self.assertEqual(resolve_effective_stamp_mode(120, "full"), "hidden")
        self.assertEqual(resolve_effective_stamp_mode(160, "compact"), "compact")

    def test_format_country_compacts_long_values(self) -> None:
        country = format_country("Completely free and family friendly", 100)
        self.assertLessEqual(len(country), 12)
        self.assertTrue(country.endswith("…"))

    def test_result_columns_change_with_terminal_width(self) -> None:
        narrow = resolve_result_columns(70, "compact")
        medium = resolve_result_columns(120, "compact")
        wide = resolve_result_columns(170, "compact")

        self.assertEqual(narrow, ("#", "name", "latency_ms", "rel_%"))
        self.assertIn("country", medium)
        self.assertNotIn("stamp", medium)
        self.assertIn("stamp", wide)
        self.assertGreater(len(wide), len(medium))

    def test_render_plain_table_uses_adaptive_columns(self) -> None:
        resolver = make_result().resolver
        long_country_result = MeasurementResult(
            resolver=Resolver(
                catalog=resolver.catalog,
                name=resolver.name,
                proto=resolver.proto,
                stamp="sdns://ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                country="Completely free and family friendly",
                description=resolver.description,
                dnssec=resolver.dnssec,
                nofilter=resolver.nofilter,
                nolog=resolver.nolog,
                ipv6=resolver.ipv6,
                addrs=resolver.addrs,
                ports=resolver.ports,
                location=resolver.location,
            ),
            address="51.158.147.132",
            port=443,
            latency_seconds=0.05,
            stderr_seconds=0.005,
            reliability=1.0,
            successful_attempts=3,
            attempted_probes=3,
        )

        narrow = render_plain_table([long_country_result], stamp_mode="compact", terminal_width=70)
        medium = render_plain_table([long_country_result], stamp_mode="compact", terminal_width=120)
        wide = render_plain_table([long_country_result], stamp_mode="compact", terminal_width=170)

        self.assertNotIn("stamp", narrow.splitlines()[0])
        self.assertNotIn("country", narrow.splitlines()[0])
        self.assertIn("country", medium.splitlines()[0])
        self.assertIn("Completely …", medium)
        self.assertIn("stamp", wide.splitlines()[0])
        self.assertIn("sdns://ABCDEFGHIJKLM", wide)

    def test_expand_protocols_supports_all_alias(self) -> None:
        self.assertIn("DNSCrypt", expand_protocols(None))
        self.assertIn("ODoH relay", expand_protocols(None))
        expanded = expand_protocols(["all"])
        self.assertIn("DNSCrypt", expanded)
        self.assertIn("ODoH relay", expanded)

    def test_main_menu_contains_ip_check(self) -> None:
        self.assertEqual(main_menu_options(), ("Start new check", "Check IP"))

    def test_interrupt_hint_varies_by_screen(self) -> None:
        self.assertIn("exit", interrupt_hint(in_main_menu=True).lower())
        self.assertIn("main menu", interrupt_hint(in_main_menu=False).lower())

    def test_normalize_country_filters_supports_repeated_and_comma_values(self) -> None:
        countries = normalize_country_filters(["Germany, France", "Germany", "Canada"])
        self.assertEqual(countries, ("Germany", "France", "Canada"))

    def test_should_prompt_only_without_explicit_selection(self) -> None:
        args = Namespace(json=False, list_catalogs=False, list_protos=False, catalogs=None, protocols=None)
        self.assertIsInstance(should_prompt_for_selection(args), bool)

    def test_parse_multi_select_returns_selected_values(self) -> None:
        values = parse_multi_select("1,3", ["a", "b", "c"])
        self.assertEqual(values, ["a", "c"])

    def test_zero_is_used_for_back_and_exit_navigation(self) -> None:
        self.assertTrue(is_back_command("0"))
        self.assertTrue(is_exit_command("0"))
        self.assertFalse(is_back_command("back"))
        self.assertFalse(is_exit_command("exit"))

    def test_describe_output_selection_supports_top_and_all(self) -> None:
        self.assertEqual(describe_output_selection("top", 10, 10), "top 10")
        self.assertEqual(describe_output_selection("all", 10, 87), "all (87)")

    def test_no_matches_message_describes_selected_filters(self) -> None:
        message = no_matches_message(
            ResolverFilterCriteria(require_nolog=True, ip_version="ipv6", countries=("Germany",)),
            ("public-resolvers",),
            ("DoH",),
        )
        self.assertIn("Proto: DoH", message)
        self.assertIn("Filters: nolog, ipv6, countries=Germany", message)

    def test_validate_positive_int_rejects_invalid_values(self) -> None:
        self.assertEqual(validate_positive_int("15"), "15")
        with self.assertRaises(ValueError):
            validate_positive_int("0")

    def test_validate_country_list_rejects_empty_values(self) -> None:
        self.assertEqual(validate_country_list("Germany, France"), "Germany, France")
        with self.assertRaises(ValueError):
            validate_country_list(" , ")

    def test_resolve_filter_criteria_builds_explicit_criteria(self) -> None:
        criteria = resolve_filter_criteria(
            Namespace(
                require_nofilter=True,
                require_nolog=False,
                dnssec_only=True,
                ip_version="ipv4",
                countries=["Germany, France"],
            ),
            ("DoH",),
        )
        self.assertEqual(criteria.allowed_protocols, frozenset({"DoH"}))
        self.assertTrue(criteria.require_nofilter)
        self.assertTrue(criteria.require_dnssec)
        self.assertEqual(criteria.ip_version, "ipv4")
        self.assertEqual(criteria.countries, ("Germany", "France"))

    def test_save_results_supports_txt_json_and_csv(self) -> None:
        result = make_result()
        artifacts = RunArtifacts(
            all_results=[result],
            displayed_results=[result],
            summary=RunSummary(
                catalogs=("public-resolvers",),
                protocols=("DNSCrypt",),
                filter_selection="nofilter, nolog",
                output_selection="top 1",
                total_loaded=1,
                total_filtered=1,
                total_responded=1,
                total_displayed=1,
                profile="balanced",
                expected_attempts=3,
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            txt_path = Path(tmp) / "result.txt"
            json_path = Path(tmp) / "result.json"
            csv_path = Path(tmp) / "result.csv"
            save_results(artifacts, txt_path, "txt")
            save_results(artifacts, json_path, "json")
            save_results(artifacts, csv_path, "csv")

            self.assertIn("Run Summary", txt_path.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload[0]["proto"], "DNSCrypt")
            self.assertIn("sdns", csv_path.read_text(encoding="utf-8"))

    def test_build_default_export_name_uses_date_and_selected_categories(self) -> None:
        result = make_result()
        artifacts = RunArtifacts(
            all_results=[result],
            displayed_results=[result],
            summary=RunSummary(
                catalogs=("public-resolvers", "relays"),
                protocols=("DNSCrypt", "DoH"),
                filter_selection="nofilter, nolog, ipv4, countries=Germany",
                output_selection="top 1",
                total_loaded=1,
                total_filtered=1,
                total_responded=1,
                total_displayed=1,
                profile="balanced",
                expected_attempts=3,
            ),
        )

        name = build_default_export_name(artifacts, "csv", date_prefix="20260310")
        self.assertTrue(name.startswith("dnscrypt-results"))
        self.assertIn(
            "20260310-catalogs-public-resolvers-relays-protos-dnscrypt-doh-filters-nofilter-nolog-ipv4-countries-germany.csv",
            name,
        )

    def test_build_text_export_contains_output_selection(self) -> None:
        result = make_result()
        artifacts = RunArtifacts(
            all_results=[result],
            displayed_results=[result],
            summary=RunSummary(
                catalogs=("public-resolvers",),
                protocols=("DNSCrypt",),
                filter_selection="measurable endpoints only",
                output_selection="all (1)",
                total_loaded=1,
                total_filtered=1,
                total_responded=1,
                total_displayed=1,
                profile="balanced",
                expected_attempts=3,
            ),
        )
        text = build_text_export(artifacts)
        self.assertIn("output: all (1)", text)
        self.assertIn("filters: measurable endpoints only", text)


if __name__ == "__main__":
    unittest.main()
