import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.extras


class TimescaleIngestor:
    """Lightweight wrapper for writing scanner events into TimescaleDB."""

    def __init__(self, connection: psycopg2.extensions.connection) -> None:
        self._conn = connection
        self._conn.autocommit = True

    @classmethod
    def from_env(cls) -> Optional["TimescaleIngestor"]:
        """Create an ingestor instance from environment variables."""
        username = os.getenv("POSTGRES_USERNAME")
        password = os.getenv("POSTGRES_PASSWORD")
        database = os.getenv("POSTGRES_DATABASE")
        hostname = os.getenv("POSTGRES_HOSTNAME")
        port = os.getenv("POSTGRES_PORT")

        if not all([username, password, database, hostname, port]):
            print("[WARN] TimescaleDB credentials not fully defined. Ingestion disabled.")
            return None

        try:
            conn = psycopg2.connect(
                dbname=database,
                user=username,
                password=password,
                host=hostname,
                port=port,
                sslmode="require",
            )
        except psycopg2.Error as exc:
            print(f"[ERROR] Failed to connect to TimescaleDB: {exc}")
            return None

        print("[INFO] TimescaleDB ingestion enabled.")
        return cls(conn)

    @contextmanager
    def _cursor(self):
        cur = self._conn.cursor()
        try:
            yield cur
        finally:
            cur.close()

    def close(self) -> None:
        try:
            self._conn.close()
        except psycopg2.Error:
            pass

    def get_or_create_repo(self, repo_name: str) -> Optional[int]:
        query = """
            INSERT INTO repositories (repo_name)
            VALUES (%s)
            ON CONFLICT (repo_name) DO UPDATE SET repo_name = EXCLUDED.repo_name
            RETURNING repo_id;
        """
        with self._cursor() as cur:
            try:
                cur.execute(query, (repo_name,))
                row = cur.fetchone()
                return row[0] if row else None
            except psycopg2.Error as exc:
                print(f"[ERROR] Failed to upsert repository '{repo_name}': {exc}")
                return None

    def log_repo_check(self, repo_id: int, notes: Optional[str] = None) -> None:
        query = """
            INSERT INTO repo_log (checked_at, repo_id, notes)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING;
        """
        checked_at = datetime.now(timezone.utc)
        with self._cursor() as cur:
            try:
                cur.execute(query, (checked_at, repo_id, notes))
            except psycopg2.Error as exc:
                print(f"[ERROR] Failed to insert repo_log for repo_id={repo_id}: {exc}")

    def log_scan(
        self,
        *,
        repo_id: int,
        checked_at: datetime,
        file_path: str,
        sha256: Optional[str],
        scanner_version: Optional[str],
        metadata: Optional[Dict[str, Any]],
        vt_counts: Optional[Dict[str, Any]],
        vt_requested: bool,
        vt_error: Optional[str],
        clamav_threats: Optional[int],
        clamav_scantime_ms: Optional[int],
        outcome: str,
    ) -> None:
        query = """
            INSERT INTO scan_log (
                checked_at,
                repo_id,
                file_path,
                vt_counts,
                vt_requested,
                vt_error,
                clamav_threats,
                clamav_scantime_ms,
                outcome,
                sha256,
                scanner_version,
                metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (repo_id, file_path, checked_at) DO NOTHING;
        """
        with self._cursor() as cur:
            try:
                cur.execute(
                    query,
                    (
                        checked_at,
                        repo_id,
                        file_path,
                        psycopg2.extras.Json(vt_counts) if vt_counts is not None else None,
                        vt_requested,
                        vt_error,
                        clamav_threats,
                        clamav_scantime_ms,
                        outcome,
                        sha256,
                        scanner_version,
                        psycopg2.extras.Json(metadata) if metadata is not None else None,
                    ),
                )
            except psycopg2.Error as exc:
                print(
                    f"[ERROR] Failed to insert scan_log for repo_id={repo_id}, file='{file_path}': {exc}"
                )
