from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import sys
from typing import Callable, Iterable, Sequence

from .models import MeasurementResult

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    Console = None
    Progress = None
    RICH_AVAILABLE = False


@dataclass(frozen=True, slots=True)
class RunSummary:
    catalogs: tuple[str, ...]
    protocols: tuple[str, ...]
    filter_selection: str
    output_selection: str
    total_loaded: int
    total_filtered: int
    total_responded: int
    total_displayed: int
    profile: str
    expected_attempts: int


class ProbeMonitor:
    def __init__(self, enabled: bool, total: int, expected_attempts: int) -> None:
        self.enabled = enabled and RICH_AVAILABLE
        self.total = total
        self.expected_attempts = expected_attempts
        self.success = 0
        self.failed = 0

        if self.enabled:
            self.console = Console(file=sys.stderr, highlight=False)
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                TextColumn("{task.fields[details]}"),
                console=self.console,
                transient=False,
            )
            self.scheduled_task = self.progress.add_task("Queueing resolvers", total=total, details="")
            self.completed_task = self.progress.add_task(
                "Checking latency",
                total=total,
                details=f"attempts={expected_attempts}",
            )

    def __enter__(self) -> "ProbeMonitor":
        if self.enabled:
            self.progress.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self.enabled:
            self.progress.stop()
        return False

    def scheduled(self) -> None:
        if self.enabled:
            self.progress.advance(self.scheduled_task, 1)

    def completed(self, result: MeasurementResult | None) -> None:
        if result is not None:
            self.success += 1
        else:
            self.failed += 1

        if self.enabled:
            self.progress.advance(self.completed_task, 1)
            details = f"ok={self.success} fail={self.failed} attempts={self.expected_attempts}"
            self.progress.update(self.completed_task, details=details)


class PromptBack(Exception):
    """Raised when the user requests to go back in the wizard."""


class PromptExit(Exception):
    """Raised when the user requests to exit the wizard."""


class TerminalUI:
    def __init__(self, enable_rich: bool = True) -> None:
        self.use_rich = enable_rich and RICH_AVAILABLE
        self.stderr_console = Console(file=sys.stderr, highlight=False) if self.use_rich else None
        self.stdout_console = Console(highlight=False) if self.use_rich else None

    @contextmanager
    def status(self, message: str):
        if self.use_rich:
            with self.stderr_console.status(message, spinner="dots"):
                yield
        else:
            print(message, file=sys.stderr)
            yield

    def create_probe_monitor(self, total: int, expected_attempts: int) -> ProbeMonitor:
        return ProbeMonitor(enabled=self.use_rich, total=total, expected_attempts=expected_attempts)

    def prompt_multi_select(
        self,
        title: str,
        options: Sequence[str],
        default: Sequence[str] | None = None,
        allow_back: bool = False,
        allow_exit: bool = False,
    ) -> list[str]:
        has_default = default is not None
        default = list(default or [])
        default_hint = ", ".join(str(options.index(item) + 1) for item in default if item in options)
        prompt = (
            f"{title}\n"
            + "\n".join(f"  {index}. {option}" for index, option in enumerate(options, start=1))
            + "\n"
            + "Enter numbers separated by commas. "
        )
        if default_hint:
            prompt += f"Enter = {default_hint}: "
        else:
            prompt += "e.g. 1,3,5: "
        if allow_back:
            prompt += "0 = back: "
        elif allow_exit:
            prompt += "0 = exit: "

        while True:
            answer = self._input(prompt).strip()
            if allow_back and is_back_command(answer):
                raise PromptBack()
            if allow_exit and is_exit_command(answer):
                raise PromptExit()
            if not answer and has_default:
                return list(default)
            try:
                return parse_multi_select(answer, options)
            except ValueError as exc:
                self._print_error(str(exc))

    def prompt_single_select(
        self,
        title: str,
        options: Sequence[str],
        default: str | None = None,
        allow_back: bool = False,
        allow_exit: bool = False,
    ) -> str:
        default_hint = str(options.index(default) + 1) if default in options else ""
        prompt = (
            f"{title}\n"
            + "\n".join(f"  {index}. {option}" for index, option in enumerate(options, start=1))
            + "\n"
            + "Enter option number. "
        )
        if default_hint:
            prompt += f"Enter = {default_hint}: "
        else:
            prompt += "e.g. 2: "
        if allow_back:
            prompt += "0 = back: "
        elif allow_exit:
            prompt += "0 = exit: "

        while True:
            answer = self._input(prompt).strip()
            if allow_back and is_back_command(answer):
                raise PromptBack()
            if allow_exit and is_exit_command(answer):
                raise PromptExit()
            if not answer and default:
                return default
            try:
                values = parse_multi_select(answer, options)
                if len(values) != 1:
                    raise ValueError("Select exactly one option.")
                return values[0]
            except ValueError as exc:
                self._print_error(str(exc))

    def prompt_text(
        self,
        title: str,
        default: str | None = None,
        allow_back: bool = False,
        allow_exit: bool = False,
        validator: Callable[[str], str] | None = None,
    ) -> str:
        prompt = title
        if default:
            prompt += f" Enter = {default}"
        if allow_back:
            prompt += " (0 = back)"
        elif allow_exit:
            prompt += " (0 = exit)"
        prompt += ": "

        while True:
            answer = self._input(prompt).strip()
            if allow_back and is_back_command(answer):
                raise PromptBack()
            if allow_exit and is_exit_command(answer):
                raise PromptExit()
            if not answer and default is not None:
                answer = default
            if not answer:
                self._print_error("Value cannot be empty.")
                continue
            if validator is not None:
                try:
                    return validator(answer)
                except ValueError as exc:
                    self._print_error(str(exc))
                    continue
            return answer

    def print_message(self, message: str, style: str | None = None) -> None:
        if self.use_rich and style:
            self.stderr_console.print(f"[{style}]{message}[/{style}]")
        else:
            print(message, file=sys.stderr)

    def print_results(
        self,
        results: list[MeasurementResult],
        summary: RunSummary,
        stamp_mode: str,
    ) -> None:
        if self.use_rich:
            self.stdout_console.print(self._build_summary_panel(summary))
            self.stdout_console.print(self._build_results_table(results, stamp_mode=stamp_mode))
            if stamp_mode == "full":
                self.stdout_console.print(self._build_full_stamp_table(results))
            return

        print(self._build_plain_summary(summary))
        print(render_plain_table(results, stamp_mode=stamp_mode))
        if stamp_mode == "full":
            print(render_plain_full_stamps(results))

    def _build_summary_panel(self, summary: RunSummary):
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan")
        grid.add_column()
        grid.add_row("Catalogs", ", ".join(summary.catalogs))
        grid.add_row("Proto", ", ".join(summary.protocols))
        grid.add_row("Filters", summary.filter_selection)
        grid.add_row("Output", summary.output_selection)
        grid.add_row("Profile", summary.profile)
        grid.add_row("Loaded", str(summary.total_loaded))
        grid.add_row("Candidates", str(summary.total_filtered))
        grid.add_row("Responded", str(summary.total_responded))
        grid.add_row("Displayed", str(summary.total_displayed))
        grid.add_row("Expected probes", str(summary.expected_attempts))
        return Panel(grid, title="Run Summary", box=box.ROUNDED)

    def _build_results_table(self, results: list[MeasurementResult], stamp_mode: str):
        table = Table(box=box.SIMPLE_HEAVY, expand=True, show_lines=False)
        table.add_column("#", justify="right", no_wrap=True)
        table.add_column("name", overflow="fold")
        table.add_column("catalog", no_wrap=True)
        table.add_column("proto", no_wrap=True)
        table.add_column("country", no_wrap=True)
        table.add_column("address", overflow="fold")
        table.add_column("port", justify="right", no_wrap=True)
        table.add_column("latency_ms", justify="right", no_wrap=True)
        table.add_column("stderr_ms", justify="right", no_wrap=True)
        table.add_column("rel_%", justify="right", no_wrap=True)
        if stamp_mode != "hidden":
            max_width = 24 if stamp_mode == "compact" else 48
            table.add_column("stamp", overflow="fold", max_width=max_width)

        for index, result in enumerate(results, start=1):
            row = [
                str(index),
                result.resolver.name,
                result.resolver.catalog,
                result.resolver.proto,
                result.resolver.country or "-",
                result.address,
                str(result.port or "-"),
                f"{result.latency_ms:.2f}",
                f"{result.stderr_ms:.2f}",
                f"{result.reliability_percent:.1f}",
            ]
            if stamp_mode != "hidden":
                row.append(compact_stamp(result.resolver.stamp) if stamp_mode == "compact" else result.resolver.stamp)
            table.add_row(*row)
        return table

    def _build_full_stamp_table(self, results: list[MeasurementResult]):
        table = Table(title="Full stamps", box=box.SIMPLE, expand=True)
        table.add_column("#", justify="right", no_wrap=True)
        table.add_column("name", no_wrap=True)
        table.add_column("stamp", overflow="fold")
        for index, result in enumerate(results, start=1):
            table.add_row(str(index), result.resolver.name, result.resolver.stamp)
        return table

    def _build_plain_summary(self, summary: RunSummary) -> str:
        return "\n".join(
            [
                "Run Summary",
                f"catalogs: {', '.join(summary.catalogs)}",
                f"proto: {', '.join(summary.protocols)}",
                f"filters: {summary.filter_selection}",
                f"output: {summary.output_selection}",
                f"profile: {summary.profile}",
                f"loaded: {summary.total_loaded}",
                f"candidates: {summary.total_filtered}",
                f"responded: {summary.total_responded}",
                f"displayed: {summary.total_displayed}",
                f"expected_probes: {summary.expected_attempts}",
            ]
        )

    def _input(self, message: str) -> str:
        if self.use_rich:
            return self.stderr_console.input(message)
        return input(message)

    def _print_error(self, message: str) -> None:
        if self.use_rich:
            self.stderr_console.print(f"[red]{message}[/red]")
        else:
            print(message, file=sys.stderr)


def compact_stamp(stamp: str, prefix: int = 20, suffix: int = 10) -> str:
    if len(stamp) <= prefix + suffix + 3:
        return stamp
    return f"{stamp[:prefix]}...{stamp[-suffix:]}"


def parse_multi_select(answer: str, options: Sequence[str]) -> list[str]:
    if not answer:
        raise ValueError("Select at least one option.")

    selected: list[str] = []
    seen: set[int] = set()
    for chunk in answer.split(","):
        value = chunk.strip()
        if not value:
            continue
        if not value.isdigit():
            raise ValueError("Use option numbers only, e.g. 1,3")
        index = int(value)
        if index < 1 or index > len(options):
            raise ValueError(f"Number {index} is out of range 1..{len(options)}")
        if index in seen:
            continue
        seen.add(index)
        selected.append(options[index - 1])

    if not selected:
        raise ValueError("Select at least one option.")
    return selected


def is_back_command(answer: str) -> bool:
    return answer.strip() == "0"


def is_exit_command(answer: str) -> bool:
    return answer.strip() == "0"


def render_plain_table(results: list[MeasurementResult], stamp_mode: str) -> str:
    headers = ["#", "name", "catalog", "proto", "country", "address", "port", "latency_ms", "stderr_ms", "rel_%"]
    if stamp_mode != "hidden":
        headers.append("stamp")

    rows = []
    for index, result in enumerate(results, start=1):
        row = [
            str(index),
            result.resolver.name,
            result.resolver.catalog,
            result.resolver.proto,
            result.resolver.country or "-",
            result.address,
            str(result.port or "-"),
            f"{result.latency_ms:.2f}",
            f"{result.stderr_ms:.2f}",
            f"{result.reliability_percent:.1f}",
        ]
        if stamp_mode != "hidden":
            row.append(compact_stamp(result.resolver.stamp) if stamp_mode == "compact" else result.resolver.stamp)
        rows.append(row)

    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    lines = [
        " ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        " ".join("-" * widths[index] for index in range(len(headers))),
    ]
    lines.extend(" ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows)
    return "\n".join(lines)


def render_plain_full_stamps(results: Iterable[MeasurementResult]) -> str:
    lines = ["", "Full stamps:"]
    for index, result in enumerate(results, start=1):
        lines.append(f"{index}. {result.resolver.name}")
        lines.append(result.resolver.stamp)
    return "\n".join(lines)
