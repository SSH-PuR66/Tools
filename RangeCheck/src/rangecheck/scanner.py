from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from pathlib import Path

from rangecheck.fingerprint import fingerprint_service
from rangecheck.models import (
    AssessmentReport,
    HostAssessment,
    ServiceFinding,
    utc_now,
)
from rangecheck.rule_engine import RuleEngine

LOGGER = logging.getLogger(__name__)

WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}


class ScanConfigurationError(ValueError):
    pass


def parse_ports(raw: str | None) -> list[int]:
    if not raw:
        return [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995,
                3306, 3389, 5432, 5900, 6379, 8080, 8443]

    ports: list[int] = []

    for segment in raw.split(","):
        segment = segment.strip()

        if "-" in segment:
            parts = segment.split("-", 1)
            start = int(parts[0])
            end = int(parts[1])

            if start < 1 or end > 65535 or start > end:
                raise ScanConfigurationError(
                    f"Invalid port range: {segment}"
                )

            ports.extend(range(start, end + 1))
        else:
            port = int(segment)

            if port < 1 or port > 65535:
                raise ScanConfigurationError(f"Invalid port: {port}")

            ports.append(port)

    return sorted(set(ports))


def _expand_targets(
    target: str,
    max_hosts: int,
    exclusions: list[str],
) -> list[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScanConfigurationError(f"Invalid target: {target}") from exc

    excluded_nets = []
    for exclusion in exclusions:
        try:
            excluded_nets.append(ipaddress.ip_network(exclusion, strict=False))
        except ValueError:
            pass

    hosts: list[str] = []

    for addr in network.hosts() if network.num_addresses > 1 else [network.network_address]:
        if any(addr in net for net in excluded_nets):
            continue
        hosts.append(str(addr))
        if len(hosts) >= max_hosts:
            break

    if not hosts:
        hosts = [str(network.network_address)]

    return hosts


async def _probe_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> ServiceFinding | None:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

            banner = None
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()
            except (asyncio.TimeoutError, Exception):
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            service_name = WELL_KNOWN_SERVICES.get(port, "unknown")

            return ServiceFinding(
                host=host,
                port=port,
                protocol="tcp",
                state="open",
                service_name=service_name,
                banner=banner or None,
            )

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def scan_target(
    *,
    target: str,
    ports: list[int],
    concurrency: int,
    timeout: float,
    max_hosts: int,
    rules_dir: Path,
    exclusions: list[str],
    classification: str,
    distribution: str,
) -> AssessmentReport:
    started = utc_now()

    hosts = _expand_targets(target, max_hosts, exclusions)
    LOGGER.info("Scanning %d host(s) across %d port(s)", len(hosts), len(ports))

    engine = RuleEngine.from_directory(rules_dir)
    semaphore = asyncio.Semaphore(concurrency)

    tasks = [
        _probe_port(host, port, timeout, semaphore)
        for host in hosts
        for port in ports
    ]

    results = await asyncio.gather(*tasks)
    services: list[ServiceFinding] = [r for r in results if r is not None]

    LOGGER.info("Discovered %d open service(s)", len(services))

    # Fingerprint HTTP services
    for i, svc in enumerate(services):
        if svc.service_name in ("http", "https", "http-alt", "https-alt") and not svc.banner:
            fp_banner = await fingerprint_service(svc.host, svc.port, svc.service_name)
            if fp_banner:
                services[i] = ServiceFinding(
                    host=svc.host,
                    port=svc.port,
                    protocol=svc.protocol,
                    state=svc.state,
                    service_name=svc.service_name,
                    banner=fp_banner,
                )

    host_map: dict[str, HostAssessment] = {}

    for svc in services:
        if svc.host not in host_map:
            host_map[svc.host] = HostAssessment(host=svc.host)
        host_map[svc.host].services.append(svc)

        findings = engine.evaluate_service(svc)
        host_map[svc.host].vulnerabilities.extend(findings)

    completed = utc_now()

    return AssessmentReport(
        tool_name="RangeCheck",
        tool_version="0.2.0",
        target=target,
        started_at=started,
        completed_at=completed,
        classification=classification,
        distribution=distribution,
        methodology=(
            "Non-exploitative TCP service discovery with banner fingerprinting, "
            "YAML rule evaluation, CVSS v3.1 scoring, and framework mapping. "
            "Aligned with NIST SP 800-115."
        ),
        hosts=list(host_map.values()),
    )
