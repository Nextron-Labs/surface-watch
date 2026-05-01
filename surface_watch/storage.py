from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from surface_watch.models import (
    Change,
    DiscoveredTarget,
    HostScanRecord,
    PortFinding,
    ScanMetadata,
    ScanResult,
    ScanSnapshot,
)


def initialize_database(path: Path) -> None:
    database_path = path.expanduser().resolve()
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                started_at TEXT,
                finished_at TEXT,
                status TEXT,
                config_hash TEXT,
                tool_version TEXT
            );

            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                hostname TEXT,
                ip TEXT,
                source TEXT,
                parent_domain TEXT,
                record_type TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            );

            CREATE TABLE IF NOT EXISTS host_results (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                hostname TEXT,
                ip TEXT NOT NULL,
                status TEXT,
                error TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            );

            CREATE TABLE IF NOT EXISTS port_findings (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                hostname TEXT,
                ip TEXT NOT NULL,
                protocol TEXT,
                port INTEGER,
                state TEXT,
                service_name TEXT,
                product TEXT,
                version TEXT,
                extra_info TEXT,
                tunnel TEXT,
                confidence INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            );

            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                change_type TEXT,
                severity TEXT,
                hostname TEXT,
                ip TEXT,
                protocol TEXT,
                port INTEGER,
                old_value TEXT,
                new_value TEXT,
                message TEXT,
                created_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            );
            """
        )


def create_scan(
    path: Path,
    *,
    started_at: datetime,
    status: str,
    config_hash: str,
    tool_version: str,
) -> int:
    with _connect(path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (started_at, finished_at, status, config_hash, tool_version)
            VALUES (?, ?, ?, ?, ?)
            """,
            (started_at.isoformat(), None, status, config_hash, tool_version),
        )
        return int(cursor.lastrowid)


def finish_scan(path: Path, scan_id: int, *, finished_at: datetime, status: str) -> None:
    with _connect(path) as connection:
        connection.execute(
            "UPDATE scans SET finished_at = ?, status = ? WHERE id = ?",
            (finished_at.isoformat(), status, scan_id),
        )


def save_discovered_targets(path: Path, scan_id: int, targets: Iterable[DiscoveredTarget]) -> None:
    rows = [
        (
            scan_id,
            target.hostname,
            target.ip,
            target.source,
            target.parent_domain,
            target.record_type,
        )
        for target in targets
    ]
    with _connect(path) as connection:
        if rows:
            connection.executemany(
                """
                INSERT INTO targets (scan_id, hostname, ip, source, parent_domain, record_type)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )


def save_scan_results(path: Path, scan_id: int, results: Iterable[ScanResult]) -> None:
    host_rows: list[tuple[object, ...]] = []
    port_rows: list[tuple[object, ...]] = []
    for result in results:
        for host_record in result.host_records:
            host_rows.append(
                (
                    scan_id,
                    host_record.hostname,
                    host_record.ip,
                    host_record.status,
                    host_record.error,
                )
            )
        for finding in result.open_ports:
            port_rows.append(
                (
                    scan_id,
                    result.hostname,
                    finding.ip,
                    finding.protocol,
                    finding.port,
                    finding.state,
                    finding.service_name,
                    finding.product,
                    finding.version,
                    finding.extra_info,
                    finding.tunnel,
                    finding.confidence,
                )
            )
    with _connect(path) as connection:
        if host_rows:
            connection.executemany(
                """
                INSERT INTO host_results (scan_id, hostname, ip, status, error)
                VALUES (?, ?, ?, ?, ?)
                """,
                host_rows,
            )
        if port_rows:
            connection.executemany(
                """
                INSERT INTO port_findings (
                    scan_id, hostname, ip, protocol, port, state, service_name,
                    product, version, extra_info, tunnel, confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                port_rows,
            )


def get_previous_successful_scan_id(path: Path, current_scan_id: int) -> int | None:
    with _connect(path) as connection:
        row = connection.execute(
            """
            SELECT id
            FROM scans
            WHERE id < ? AND status = 'success'
            ORDER BY id DESC
            LIMIT 1
            """,
            (current_scan_id,),
        ).fetchone()
    return None if row is None else int(row["id"])


def load_scan_snapshot(path: Path, scan_id: int) -> ScanSnapshot:
    with _connect(path) as connection:
        scan_row = connection.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if scan_row is None:
            raise ValueError(f"Scan {scan_id} does not exist.")

        target_rows = connection.execute(
            """
            SELECT hostname, ip, source, parent_domain, record_type
            FROM targets
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
        host_result_rows = connection.execute(
            "SELECT hostname, ip, status, error FROM host_results WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        port_rows = connection.execute(
            """
            SELECT ip, protocol, port, state, service_name, product, version,
                   extra_info, tunnel, confidence
            FROM port_findings
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()

    return ScanSnapshot(
        scan_id=scan_id,
        status=scan_row["status"],
        started_at=_parse_datetime(scan_row["started_at"]),
        finished_at=_parse_datetime(scan_row["finished_at"]),
        targets=[
            DiscoveredTarget(
                hostname=row["hostname"],
                ip=row["ip"],
                source=row["source"],
                parent_domain=row["parent_domain"],
                record_type=row["record_type"],
            )
            for row in target_rows
        ],
        host_results=[
            HostScanRecord(
                hostname=row["hostname"],
                ip=row["ip"],
                status=row["status"],
                error=row["error"],
            )
            for row in host_result_rows
        ],
        port_findings=[
            PortFinding(
                ip=row["ip"],
                protocol=row["protocol"],
                port=int(row["port"]),
                state=row["state"],
                service_name=row["service_name"],
                product=row["product"],
                version=row["version"],
                extra_info=row["extra_info"],
                tunnel=row["tunnel"],
                confidence=row["confidence"],
            )
            for row in port_rows
        ],
    )


def save_changes(path: Path, scan_id: int, changes: Iterable[Change]) -> None:
    rows = [
        (
            scan_id,
            change.change_type,
            change.severity,
            change.hostname,
            change.ip,
            change.protocol,
            change.port,
            change.old_value,
            change.new_value,
            change.message,
            change.created_at.isoformat(),
        )
        for change in changes
    ]
    with _connect(path) as connection:
        if rows:
            connection.executemany(
                """
                INSERT INTO changes (
                    scan_id, change_type, severity, hostname, ip, protocol, port,
                    old_value, new_value, message, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )


def list_scans(path: Path) -> list[ScanMetadata]:
    with _connect(path) as connection:
        rows = connection.execute(
            """
            SELECT id, started_at, finished_at, status, config_hash, tool_version
            FROM scans
            ORDER BY id DESC
            """
        ).fetchall()
    return [
        ScanMetadata(
            scan_id=int(row["id"]),
            started_at=_parse_datetime(row["started_at"]),
            finished_at=_parse_datetime(row["finished_at"]),
            status=row["status"],
            config_hash=row["config_hash"],
            tool_version=row["tool_version"],
        )
        for row in rows
    ]


def load_changes(path: Path, scan_id: int) -> list[Change]:
    with _connect(path) as connection:
        rows = connection.execute(
            """
            SELECT change_type, severity, hostname, ip, protocol, port,
                   old_value, new_value, message, created_at
            FROM changes
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,),
        ).fetchall()
    return [
        Change(
            change_type=row["change_type"],
            severity=row["severity"],
            hostname=row["hostname"],
            ip=row["ip"],
            protocol=row["protocol"],
            port=row["port"],
            old_value=row["old_value"],
            new_value=row["new_value"],
            message=row["message"],
            created_at=_parse_datetime(row["created_at"]) or datetime.min,
        )
        for row in rows
    ]


def _connect(path: Path) -> sqlite3.Connection:
    database_path = path.expanduser().resolve()
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)
