from __future__ import annotations

import math
import random
import select
import socket
import struct
import time
from dataclasses import dataclass
from statistics import fmean, pstdev
from threading import Event

from .models import MeasurementResult, Resolver


@dataclass(frozen=True, slots=True)
class ProbeOptions:
    attempts: int = 5
    ping_delay: float = 0.0
    timeout: float = 0.5
    tcp_only: bool = False


def measure_resolver(
    resolver: Resolver,
    options: ProbeOptions,
    cancel_event: Event | None = None,
) -> MeasurementResult | None:
    address = resolver.addrs[0]
    ports = tuple(sorted(set(resolver.ports or (443, 53))))
    samples: list[float] = []
    selected_port: int | None = None

    for attempt_index in range(options.attempts):
        if cancel_event is not None and cancel_event.is_set():
            break
        if attempt_index:
            time.sleep(options.ping_delay)
            if cancel_event is not None and cancel_event.is_set():
                break

        latency, port = probe_once(
            address=address,
            ports=ports,
            timeout=options.timeout,
            tcp_only=options.tcp_only,
            sequence=attempt_index,
            cancel_event=cancel_event,
        )
        if latency is not None:
            samples.append(latency)
            if selected_port is None:
                selected_port = port

    if not samples:
        return None

    latency_seconds, stderr_seconds, reliability = summarize_samples(
        samples=samples,
        attempts=options.attempts,
    )
    return MeasurementResult(
        resolver=resolver,
        address=address,
        port=selected_port,
        latency_seconds=latency_seconds,
        stderr_seconds=stderr_seconds,
        reliability=reliability,
        successful_attempts=len(samples),
        attempted_probes=options.attempts,
    )


def summarize_samples(samples: list[float], attempts: int) -> tuple[float, float, float]:
    if not samples:
        raise ValueError("samples must not be empty")
    if attempts <= 0:
        raise ValueError("attempts must be positive")

    avg = fmean(samples)
    stderr = 0.0
    if len(samples) > 1:
        stderr = pstdev(samples) / math.sqrt(len(samples))
    reliability = len(samples) / attempts
    return avg, stderr, reliability


def probe_once(
    address: str,
    ports: tuple[int, ...],
    timeout: float,
    tcp_only: bool,
    sequence: int,
    cancel_event: Event | None = None,
) -> tuple[float | None, int | None]:
    if cancel_event is not None and cancel_event.is_set():
        return None, None
    for port in ports:
        latency = tcp_connect_latency(address, port, timeout)
        if latency is not None:
            return latency, port

    if tcp_only:
        return None, None

    return icmp_ping_latency(address, timeout=timeout, sequence=sequence), None


def tcp_connect_latency(address: str, port: int, timeout: float) -> float | None:
    started = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return time.perf_counter() - started
    except (ConnectionRefusedError, TimeoutError, OSError):
        return None


def checksum(data: bytes) -> bytes:
    total = sum(value << 8 if index % 2 else value for index, value in enumerate(data)) & 0xFFFFFFFF
    total = (total >> 16) + (total & 0xFFFF)
    total = (total >> 16) + (total & 0xFFFF)
    return struct.pack("<H", ~total & 0xFFFF)


def icmp_ping_latency(address: str, timeout: float, sequence: int) -> float | None:
    packet_id = random.randrange(0, 65536)
    payload = struct.pack("!HH", packet_id, sequence)
    packet = b"\x08\0" + checksum(b"\x08\0\0\0" + payload) + payload

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as conn:
            conn.settimeout(timeout)
            conn.connect((address, 80))
            conn.sendall(packet)
            started = time.perf_counter()

            while True:
                remaining = max(0.0, timeout - (time.perf_counter() - started))
                ready, _, _ = select.select([conn], [], [], remaining)
                if not ready:
                    return None
                data = conn.recv(65536)
                if len(data) < 20 or len(data) < struct.unpack_from("!xxH", data)[0]:
                    continue
                expected = b"\0\0" + checksum(b"\0\0\0\0" + payload) + payload
                if data[20:] == expected:
                    return time.perf_counter() - started
    except (PermissionError, socket.gaierror, TimeoutError, OSError):
        return None
