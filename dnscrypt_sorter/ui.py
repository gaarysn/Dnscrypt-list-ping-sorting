from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import shutil
import signal
import sys
from typing import Callable, Iterable, Sequence

from . import __version__
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
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    Console = None
    Progress = None
    RICH_AVAILABLE = False

BANNER = r"""
 ____  _   _ ____                       _     ____             _
|  _ \| \ | / ___|  ___ _ __ _   _ _ __ | |_  / ___|  ___  _ __| |_ ___ _ __
| | | |  \| \___ \ / __| '__| | | | '_ \| __| \___ \ / _ \| '__| __/ _ \ '__|
| |_| | |\  |___) | (__| |  | |_| | |_) | |_   ___) | (_) | |  | ||  __/ |
|____/|_| \_|____/ \___|_|   \__, | .__/ \__| |____/ \___/|_|   \__\___|_|
                              |___/|_|
"""

WIZARD_STEPS = 5


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


@dataclass(frozen=True, slots=True)
class ResultColumn:
    key: str
    header: str
    min_width: int
    justify: str = "left"
    no_wrap: bool = False
    overflow: str = "fold"
    max_width: int | None = None
    style: str = "white"


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


RESULT_COLUMNS: dict[str, ResultColumn] = {
    "#": ResultColumn("#", "#", min_width=4, justify="right", no_wrap=True, style="bold yellow"),
    "name": ResultColumn("name", "name", min_width=16, overflow="fold", style="white"),
    "catalog": ResultColumn("catalog", "catalog", min_width=18, no_wrap=True, style="dim cyan"),
    "proto": ResultColumn("proto", "proto", min_width=12, no_wrap=True, style="bright_magenta"),
    "country": ResultColumn("country", "country", min_width=14, no_wrap=True, style="green"),
    "address": ResultColumn("address", "address", min_width=18, overflow="fold", style="white"),
    "port": ResultColumn("port", "port", min_width=6, justify="right", no_wrap=True, style="dim"),
    "latency_ms": ResultColumn(
        "latency_ms",
        "latency_ms",
        min_width=12,
        justify="right",
        no_wrap=True,
        style="bold bright_green",
    ),
    "stderr_ms": ResultColumn(
        "stderr_ms",
        "stderr_ms",
        min_width=11,
        justify="right",
        no_wrap=True,
        style="dim green",
    ),
    "rel_%": ResultColumn("rel_%", "rel_%", min_width=8, justify="right", no_wrap=True, style="bright_cyan"),
    "stamp": ResultColumn("stamp", "stamp", min_width=26, overflow="fold", style="dim"),
}

MANDATORY_RESULT_COLUMNS = ("#", "name", "latency_ms", "rel_%")
OPTIONAL_RESULT_COLUMNS = ("proto", "catalog", "country", "address", "port", "stderr_ms", "stamp")
STAMP_MIN_WIDTH = 145
DEFAULT_TERMINAL_WIDTH = 120


class PromptBack(Exception):
    """Raised when the user requests to go back in the wizard."""


class PromptExit(Exception):
    """Raised when the user requests to exit the wizard."""


class TerminalUI:
    def __init__(self, enable_rich: bool = True) -> None:
        self.use_rich = enable_rich and RICH_AVAILABLE
        self.stderr_console = Console(file=sys.stderr, highlight=False) if self.use_rich else None
        self.stdout_console = Console(highlight=False) if self.use_rich else None
        self._header_fn: Callable[[], None] | None = None
        self._prompt_fn: Callable[[], None] | None = None
        if self.use_rich and hasattr(signal, "SIGWINCH"):
            signal.signal(signal.SIGWINCH, self._on_terminal_resize)

    def _on_terminal_resize(self, signum: int, frame: object) -> None:
        if self._prompt_fn is not None:
            self.clear_screen()
            if self._header_fn:
                self._header_fn()
            self._prompt_fn()
            if self.stderr_console:
                self.stderr_console.print("  [bold green]>[/bold green] ", end="")

    def set_header(self, fn: Callable[[], None] | None) -> None:
        self._header_fn = fn

    def clear_screen(self) -> None:
        if self.use_rich:
            self.stderr_console.clear()
        else:
            print("\033[2J\033[H", file=sys.stderr, end="", flush=True)

    def print_banner(self) -> None:
        if self.use_rich:
            width = self.stderr_console.size.width
            if width >= 80:
                content = Text(BANNER.rstrip("\n"), style="bold bright_cyan")
            else:
                content = Text("DNSCrypt-Sorter", style="bold bright_cyan", justify="center")
            panel = Panel(
                content,
                box=box.DOUBLE,
                border_style="bright_blue",
                subtitle=f"[dim white]DNSCrypt-Sorter v{__version__}[/dim white]",
                padding=(0, 2),
            )
            self.stderr_console.print(panel)
        else:
            print(BANNER, file=sys.stderr)

    def print_step_header(self, step: int, total: int = WIZARD_STEPS) -> None:
        if self.use_rich:
            self.stderr_console.print()
            self.stderr_console.print(
                f"  [bold magenta]Step {step} of {total}[/bold magenta]",
            )
            self.stderr_console.print()
        else:
            print(f"\n  Step {step} of {total}\n", file=sys.stderr)

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

        self._prompt_fn = lambda: self._render_select_prompt(
            title=title, options=options, default_hint=default_hint,
            allow_back=allow_back, allow_exit=allow_exit, multi=True,
        )
        try:
            while True:
                self._render_select_prompt(
                    title=title,
                    options=options,
                    default_hint=default_hint,
                    allow_back=allow_back,
                    allow_exit=allow_exit,
                    multi=True,
                )
                answer = self._styled_input().strip()
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
        finally:
            self._prompt_fn = None

    def prompt_single_select(
        self,
        title: str,
        options: Sequence[str],
        default: str | None = None,
        allow_back: bool = False,
        allow_exit: bool = False,
    ) -> str:
        default_hint = str(options.index(default) + 1) if default in options else ""

        self._prompt_fn = lambda: self._render_select_prompt(
            title=title, options=options, default_hint=default_hint,
            allow_back=allow_back, allow_exit=allow_exit, multi=False,
        )
        try:
            while True:
                self._render_select_prompt(
                    title=title,
                    options=options,
                    default_hint=default_hint,
                    allow_back=allow_back,
                    allow_exit=allow_exit,
                    multi=False,
                )
                answer = self._styled_input().strip()
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
        finally:
            self._prompt_fn = None

    def prompt_text(
        self,
        title: str,
        default: str | None = None,
        allow_back: bool = False,
        allow_exit: bool = False,
        validator: Callable[[str], str] | None = None,
    ) -> str:
        self._prompt_fn = lambda: self._render_text_prompt(
            title=title, default=default,
            allow_back=allow_back, allow_exit=allow_exit,
        )
        try:
            while True:
                self._render_text_prompt(
                    title=title,
                    default=default,
                    allow_back=allow_back,
                    allow_exit=allow_exit,
                )
                answer = self._styled_input().strip()
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
        finally:
            self._prompt_fn = None

    def print_message(self, message: str, style: str | None = None) -> None:
        if self.use_rich and style:
            self.stderr_console.print(f"  [{style}]{message}[/{style}]")
        else:
            print(message, file=sys.stderr)

    def print_results(
        self,
        results: list[MeasurementResult],
        summary: RunSummary,
        stamp_mode: str,
    ) -> None:
        if self.use_rich:
            width = self.stdout_console.size.width
            effective_stamp_mode = resolve_effective_stamp_mode(width, stamp_mode)
            self.stdout_console.print(self._build_summary_panel(summary))
            self.stdout_console.print(
                self._build_results_table(results, stamp_mode=effective_stamp_mode, terminal_width=width),
            )
            if effective_stamp_mode == "full":
                self.stdout_console.print(self._build_full_stamp_table(results))
            return

        print(self._build_plain_summary(summary))
        width = detect_terminal_width()
        effective_stamp_mode = resolve_effective_stamp_mode(width, stamp_mode)
        print(render_plain_table(results, stamp_mode=effective_stamp_mode, terminal_width=width))
        if effective_stamp_mode == "full":
            print(render_plain_full_stamps(results))

    def _render_select_prompt(
        self,
        title: str,
        options: Sequence[str],
        default_hint: str,
        allow_back: bool,
        allow_exit: bool,
        multi: bool,
    ) -> None:
        if not self.use_rich:
            return

        con = self.stderr_console
        con.print()
        con.print(Rule(title, style="bold cyan"))
        con.print()

        options_lines = Text()
        for index, option in enumerate(options, start=1):
            options_lines.append(f"    {index}", style="bold yellow")
            options_lines.append(". ", style="yellow")
            options_lines.append(option, style="white")
            if index < len(options):
                options_lines.append("\n")

        con.print(Panel(
            options_lines,
            box=box.ROUNDED,
            border_style="bright_blue",
            padding=(1, 4),
        ))
        con.print()

        hint_parts: list[str] = []
        if multi:
            hint_parts.append("[dim]Comma-separated numbers, e.g. 1,3,5[/dim]")
        else:
            hint_parts.append("[dim]Enter option number[/dim]")
        if default_hint:
            hint_parts.append(f"[dim cyan]Enter = {default_hint}[/dim cyan]")
        if allow_back:
            hint_parts.append("[dim italic]0 = back[/dim italic]")
        elif allow_exit:
            hint_parts.append("[dim italic]0 = exit[/dim italic]")

        con.print("  " + "    ".join(hint_parts))

    def _render_text_prompt(
        self,
        title: str,
        default: str | None,
        allow_back: bool,
        allow_exit: bool,
    ) -> None:
        if not self.use_rich:
            return

        con = self.stderr_console
        con.print()
        con.print(Rule(title, style="bold cyan"))
        con.print()

        hint_parts: list[str] = []
        if default:
            hint_parts.append(f"[dim cyan]Enter = {default}[/dim cyan]")
        if allow_back:
            hint_parts.append("[dim italic]0 = back[/dim italic]")
        elif allow_exit:
            hint_parts.append("[dim italic]0 = exit[/dim italic]")
        if hint_parts:
            con.print("  " + "    ".join(hint_parts))

    def _styled_input(self) -> str:
        if self.use_rich:
            return self.stderr_console.input("  [bold green]>[/bold green] ")
        return input("> ")

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
        return Panel(grid, title="[bold bright_cyan]Run Summary[/bold bright_cyan]", box=box.ROUNDED, border_style="bright_blue")

    def _build_results_table(self, results: list[MeasurementResult], stamp_mode: str, terminal_width: int):
        columns = resolve_result_columns(terminal_width, stamp_mode)
        table = Table(box=box.SIMPLE_HEAVY, expand=True, show_lines=False, header_style="bold yellow")
        for key in columns:
            column = RESULT_COLUMNS[key]
            max_width = resolve_column_max_width(key, terminal_width, stamp_mode)
            table.add_column(
                column.header,
                justify=column.justify,
                no_wrap=column.no_wrap,
                overflow=column.overflow,
                max_width=max_width,
                style=column.style,
            )

        for index, result in enumerate(results, start=1):
            row = [
                format_result_cell(result, key, index=index, stamp_mode=stamp_mode, terminal_width=terminal_width)
                for key in columns
            ]
            table.add_row(*row)
        return table

    def _build_full_stamp_table(self, results: list[MeasurementResult]):
        table = Table(title="[bold bright_cyan]Full stamps[/bold bright_cyan]", box=box.SIMPLE, expand=True)
        table.add_column("#", justify="right", no_wrap=True, style="bold yellow")
        table.add_column("name", no_wrap=True, style="white")
        table.add_column("stamp", overflow="fold", style="dim")
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
            self.stderr_console.print(f"  [bold red]! {message}[/bold red]")
        else:
            print(message, file=sys.stderr)


def compact_stamp(stamp: str, prefix: int = 20, suffix: int = 10) -> str:
    if len(stamp) <= prefix + suffix + 3:
        return stamp
    return f"{stamp[:prefix]}...{stamp[-suffix:]}"


def compact_text(value: str, max_length: int) -> str:
    if max_length <= 1:
        return value[:max_length]
    if len(value) <= max_length:
        return value
    return f"{value[:max_length - 1]}…"


def detect_terminal_width(default: int = DEFAULT_TERMINAL_WIDTH) -> int:
    return shutil.get_terminal_size((default, 20)).columns


def resolve_effective_stamp_mode(terminal_width: int, stamp_mode: str) -> str:
    if stamp_mode == "hidden":
        return "hidden"
    if terminal_width < STAMP_MIN_WIDTH:
        return "hidden"
    return stamp_mode


def resolve_country_max_length(terminal_width: int) -> int:
    if terminal_width < 90:
        return 10
    if terminal_width < 130:
        return 12
    if terminal_width < 150:
        return 16
    return 20


def resolve_column_max_width(column_key: str, terminal_width: int, stamp_mode: str) -> int | None:
    if column_key == "country":
        return resolve_country_max_length(terminal_width)
    if column_key == "stamp":
        return 24 if stamp_mode == "compact" else 48
    return RESULT_COLUMNS[column_key].max_width


def resolve_result_columns(terminal_width: int, stamp_mode: str) -> tuple[str, ...]:
    effective_stamp_mode = resolve_effective_stamp_mode(terminal_width, stamp_mode)
    if terminal_width < 80:
        return MANDATORY_RESULT_COLUMNS

    columns = list(MANDATORY_RESULT_COLUMNS)
    if terminal_width >= 80:
        columns.append("proto")
    if terminal_width >= 96:
        columns.append("catalog")
    if terminal_width >= 108:
        columns.append("country")
    if terminal_width >= 124:
        columns.append("address")
    if terminal_width >= 136:
        columns.append("port")
    if terminal_width >= 148:
        columns.append("stderr_ms")
    if effective_stamp_mode != "hidden":
        columns.append("stamp")

    return tuple(columns)


def format_country(country: str, terminal_width: int) -> str:
    value = country or "-"
    return compact_text(value, resolve_country_max_length(terminal_width))


def format_result_cell(
    result: MeasurementResult,
    column_key: str,
    *,
    index: int,
    stamp_mode: str,
    terminal_width: int,
) -> str:
    if column_key == "#":
        return str(index)
    if column_key == "name":
        return result.resolver.name
    if column_key == "catalog":
        return result.resolver.catalog
    if column_key == "proto":
        return result.resolver.proto
    if column_key == "country":
        return format_country(result.resolver.country, terminal_width)
    if column_key == "address":
        return result.address
    if column_key == "port":
        return str(result.port or "-")
    if column_key == "latency_ms":
        return f"{result.latency_ms:.2f}"
    if column_key == "stderr_ms":
        return f"{result.stderr_ms:.2f}"
    if column_key == "rel_%":
        return f"{result.reliability_percent:.1f}"
    if column_key == "stamp":
        return compact_stamp(result.resolver.stamp) if stamp_mode == "compact" else result.resolver.stamp
    raise KeyError(f"Unknown result column: {column_key}")


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


def render_plain_table(
    results: list[MeasurementResult],
    stamp_mode: str,
    terminal_width: int | None = None,
) -> str:
    width = terminal_width or 10_000
    effective_stamp_mode = resolve_effective_stamp_mode(width, stamp_mode)
    columns = resolve_result_columns(width, effective_stamp_mode)
    headers = [RESULT_COLUMNS[key].header for key in columns]

    rows = []
    for index, result in enumerate(results, start=1):
        row = [
            format_result_cell(result, key, index=index, stamp_mode=effective_stamp_mode, terminal_width=width)
            for key in columns
        ]
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
