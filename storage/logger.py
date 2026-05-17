"""
storage/logger.py
=================
Persistencia respaldada por SQLite con retención por niveles.

Esquema
-------
Tabla ``traffic_logs``:
    id              INTEGER PRIMARY KEY AUTOINCREMENT
    timestamp       REAL    (segundos epoch, el t de f(t))
    f_t             REAL    (paquetes/s)
    f_prime         REAL    (df/dt)
    f_double_prime  REAL    (d²f/dt²)
    is_anomaly      INTEGER (0/1)
    severity        TEXT    (NULL / LOW / MEDIUM / HIGH)
    tier            TEXT    (HOT / WARM / COLD)

Política de retención
---------------------
Una llamada en segundo plano a `apply_retention()` (planificada desde
main.py) hace downsampling de filas viejas en su lugar:

    HOT   : edad ≤ 24h           → resolución completa por segundo
    WARM  : 24h < edad ≤ 7d      → 1 fila por minuto (agregada)
    COLD  : 7d < edad ≤ 30d      → 1 fila por hora (agregada)
    edad > 30d                   → borrado

La agregación usa media aritmética de f / f' / f''. La columna
``is_anomaly`` se acumula por OR dentro del bucket (1 si algún segundo
fue anómalo), y ``severity`` guarda la peor (HIGH > MEDIUM > LOW)
observada en el bucket.

Concurrencia
------------
Cada método público abre su propia conexión de vida corta. SQLite
serializa las escrituras con su propio locking; activamos
``journal_mode=WAL`` para que las lecturas del dashboard no bloqueen
al escritor.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional


_SEVERITY_RANK = {None: 0, "": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass
class LogRow:
    timestamp: float
    f_t: float
    f_prime: float
    f_double_prime: float
    is_anomaly: bool
    severity: Optional[str]
    tier: str = "HOT"


class TrafficLogger:
    """
    Wrapper thread-safe sobre la tabla SQLite traffic_logs.
    """

    def __init__(self, db_path: str | Path = "derivashield.db") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._init_schema()

    # ----- API pública -----

    def log_sample(
        self,
        timestamp: float,
        f_t: float,
        f_prime: float,
        f_double_prime: float,
        is_anomaly: bool = False,
        severity: Optional[str] = None,
    ) -> None:
        """Inserta una sola muestra por segundo en el nivel HOT."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO traffic_logs
                    (timestamp, f_t, f_prime, f_double_prime,
                     is_anomaly, severity, tier)
                VALUES (?, ?, ?, ?, ?, ?, 'HOT')
                """,
                (
                    float(timestamp),
                    float(f_t),
                    float(f_prime),
                    float(f_double_prime),
                    1 if is_anomaly else 0,
                    severity,
                ),
            )

    def log_many(self, rows: Iterable[LogRow]) -> None:
        """Inserción masiva. La usa el loop principal para amortizar el costo de sqlite."""
        batch = [
            (
                r.timestamp,
                r.f_t,
                r.f_prime,
                r.f_double_prime,
                1 if r.is_anomaly else 0,
                r.severity,
                r.tier,
            )
            for r in rows
        ]
        if not batch:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO traffic_logs
                    (timestamp, f_t, f_prime, f_double_prime,
                     is_anomaly, severity, tier)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                batch,
            )

    def fetch_recent(self, seconds: int = 60) -> List[LogRow]:
        """Devuelve las filas con edad <= `seconds`, ordenadas por timestamp asc."""
        cutoff = time.time() - seconds
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT timestamp, f_t, f_prime, f_double_prime,
                       is_anomaly, severity, tier
                FROM traffic_logs
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (cutoff,),
            )
            return [
                LogRow(
                    timestamp=row[0],
                    f_t=row[1],
                    f_prime=row[2],
                    f_double_prime=row[3],
                    is_anomaly=bool(row[4]),
                    severity=row[5],
                    tier=row[6],
                )
                for row in cur.fetchall()
            ]

    def mark_anomaly(
        self,
        timestamp: float,
        severity: Optional[str],
        tolerance: float = 0.001,
    ) -> bool:
        """
        Marca con is_anomaly=1 una fila previamente persistida cuya timestamp
        coincida (dentro de `tolerance` segundos). Devuelve True si actualizó
        al menos una fila. Idempotente: si ya estaba marcada, sigue OK.

        Es la red de seguridad para el caso en que la persistencia y la
        detección ocurran en distintos ticks del loop principal.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE traffic_logs
                SET is_anomaly = 1,
                    severity = COALESCE(?, severity)
                WHERE ABS(timestamp - ?) <= ?
                """,
                (severity, float(timestamp), float(tolerance)),
            )
            return (cur.rowcount or 0) > 0

    def fetch_anomalies(self, seconds: int = 60) -> List[LogRow]:
        cutoff = time.time() - seconds
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT timestamp, f_t, f_prime, f_double_prime,
                       is_anomaly, severity, tier
                FROM traffic_logs
                WHERE timestamp >= ? AND is_anomaly = 1
                ORDER BY timestamp ASC
                """,
                (cutoff,),
            )
            return [
                LogRow(
                    timestamp=row[0],
                    f_t=row[1],
                    f_prime=row[2],
                    f_double_prime=row[3],
                    is_anomaly=bool(row[4]),
                    severity=row[5],
                    tier=row[6],
                )
                for row in cur.fetchall()
            ]

    def fetch_range(
        self,
        t_from: Optional[float] = None,
        t_to: Optional[float] = None,
        only_anomalies: bool = False,
        limit: Optional[int] = None,
    ) -> List[LogRow]:
        """
        Trae filas en [t_from, t_to]. Ambos extremos son opcionales:
        si `t_from` es None toma desde el inicio, si `t_to` es None toma
        hasta el final. Útil para la página de reportes.
        """
        clauses = []
        params: list = []
        if t_from is not None:
            clauses.append("timestamp >= ?")
            params.append(float(t_from))
        if t_to is not None:
            clauses.append("timestamp <= ?")
            params.append(float(t_to))
        if only_anomalies:
            clauses.append("is_anomaly = 1")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            "SELECT timestamp, f_t, f_prime, f_double_prime, "
            "       is_anomaly, severity, tier "
            "FROM traffic_logs "
            f"{where} "
            "ORDER BY timestamp ASC"
        )
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self._connect() as conn:
            cur = conn.execute(sql, params)
            return [
                LogRow(
                    timestamp=row[0],
                    f_t=row[1],
                    f_prime=row[2],
                    f_double_prime=row[3],
                    is_anomaly=bool(row[4]),
                    severity=row[5],
                    tier=row[6],
                )
                for row in cur.fetchall()
            ]

    def date_bounds(self) -> tuple[Optional[float], Optional[float]]:
        """Min y max timestamp persistidos. (None, None) si la tabla está vacía."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM traffic_logs"
            ).fetchone()
            return (row[0], row[1]) if row else (None, None)

    def apply_retention(self, now: Optional[float] = None) -> dict:
        """
        Aplica los niveles HOT/WARM/COLD/expirado. Devuelve un dict de stats
        para logging. Es seguro llamarla repetidamente (es idempotente — los
        buckets ya agregados se saltan a sí mismos porque su tier ya cambió).
        """
        now = now if now is not None else time.time()
        stats = {
            "promoted_to_warm": 0,
            "promoted_to_cold": 0,
            "deleted": 0,
        }

        # 1) Borrar todo lo más viejo que 30 días.
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM traffic_logs WHERE timestamp < ?",
                (now - 30 * 86400,),
            )
            stats["deleted"] = cur.rowcount or 0

        # 2) Agregar filas HOT en la franja (24h, 7d] a filas WARM por minuto.
        warm_lo = now - 7 * 86400
        warm_hi = now - 1 * 86400
        stats["promoted_to_warm"] = self._aggregate_bucket(
            from_tier="HOT",
            to_tier="WARM",
            lo_ts=warm_lo,
            hi_ts=warm_hi,
            bucket_seconds=60,
        )

        # 3) Agregar WARM (y cualquier HOT remanente) en (7d, 30d] a COLD por hora.
        cold_lo = now - 30 * 86400
        cold_hi = now - 7 * 86400
        stats["promoted_to_cold"] = self._aggregate_bucket(
            from_tier=None,           # cualquier nivel
            to_tier="COLD",
            lo_ts=cold_lo,
            hi_ts=cold_hi,
            bucket_seconds=3600,
        )

        return stats

    def close(self) -> None:
        # No hay nada persistente que cerrar — las conexiones son de vida corta.
        pass

    # ----- internos -----

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       REAL    NOT NULL,
                    f_t             REAL    NOT NULL,
                    f_prime         REAL    NOT NULL,
                    f_double_prime  REAL    NOT NULL,
                    is_anomaly      INTEGER NOT NULL DEFAULT 0,
                    severity        TEXT,
                    tier            TEXT    NOT NULL DEFAULT 'HOT'
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_logs(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_traffic_tier ON traffic_logs(tier)"
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # Serializamos las escrituras con nuestro propio lock así nunca vemos SQLITE_BUSY.
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                yield conn
                conn.commit()
            finally:
                conn.close()

    def _aggregate_bucket(
        self,
        from_tier: Optional[str],
        to_tier: str,
        lo_ts: float,
        hi_ts: float,
        bucket_seconds: int,
    ) -> int:
        """
        Colapsa las filas en [lo_ts, hi_ts) (filtrando opcionalmente por
        from_tier) en una fila por bucket de `bucket_seconds`. Reemplaza
        a las originales. Devuelve el número de buckets escritos.
        """
        with self._connect() as conn:
            # Trae candidatos.
            if from_tier is None:
                cur = conn.execute(
                    """
                    SELECT timestamp, f_t, f_prime, f_double_prime,
                           is_anomaly, severity
                    FROM traffic_logs
                    WHERE timestamp >= ? AND timestamp < ? AND tier != ?
                    """,
                    (lo_ts, hi_ts, to_tier),
                )
            else:
                cur = conn.execute(
                    """
                    SELECT timestamp, f_t, f_prime, f_double_prime,
                           is_anomaly, severity
                    FROM traffic_logs
                    WHERE timestamp >= ? AND timestamp < ? AND tier = ?
                    """,
                    (lo_ts, hi_ts, from_tier),
                )
            rows = cur.fetchall()
            if not rows:
                return 0

            # Agrupa en buckets.
            buckets: dict[int, dict] = {}
            for ts, f_t, fp, fpp, is_an, sev in rows:
                key = int(ts // bucket_seconds) * bucket_seconds
                b = buckets.setdefault(
                    key,
                    {"n": 0, "f_t": 0.0, "fp": 0.0, "fpp": 0.0,
                     "is_an": 0, "sev": None},
                )
                b["n"] += 1
                b["f_t"] += f_t
                b["fp"] += fp
                b["fpp"] += fpp
                b["is_an"] |= int(is_an)
                if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(b["sev"], 0):
                    b["sev"] = sev

            # Borra las originales del rango.
            if from_tier is None:
                conn.execute(
                    "DELETE FROM traffic_logs WHERE timestamp >= ? AND timestamp < ? AND tier != ?",
                    (lo_ts, hi_ts, to_tier),
                )
            else:
                conn.execute(
                    "DELETE FROM traffic_logs WHERE timestamp >= ? AND timestamp < ? AND tier = ?",
                    (lo_ts, hi_ts, from_tier),
                )

            # Inserta las filas agregadas.
            batch = []
            for key, b in buckets.items():
                n = max(1, b["n"])
                batch.append(
                    (
                        float(key + bucket_seconds / 2.0),  # centroide del bucket
                        b["f_t"] / n,
                        b["fp"] / n,
                        b["fpp"] / n,
                        b["is_an"],
                        b["sev"],
                        to_tier,
                    )
                )
            conn.executemany(
                """
                INSERT INTO traffic_logs
                    (timestamp, f_t, f_prime, f_double_prime,
                     is_anomaly, severity, tier)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                batch,
            )
            return len(batch)
