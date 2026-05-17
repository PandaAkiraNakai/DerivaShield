"""
main.py
=======
Punto de entrada de DerivaShield.

Cablea los cuatro subsistemas entre sí:

    capture/sniffer.py     -> produce f(t)
    analysis/derivatives.py-> produce f'(t), f''(t)
    detection/anomaly.py   -> marca muestras donde  f'(t) > μ + kσ  AND  f''(t) > 0
    storage/logger.py      -> persiste cada muestra (HOT) y hace downsampling por edad
    dashboard/app.py       -> visualiza todo en tiempo real

CLI
---
    --live              Captura de la interfaz de red por defecto (requiere sudo).
    --iface <nombre>    Elige una interfaz específica (eth0, wlan0, ...).
    --file <ruta.pcap>  Reproduce paquetes de un PCAP en vez de captura en vivo.
    --k <float>         Factor de sensibilidad (default 2.0). k más alto = menos alertas.
    --port <int>        Puerto HTTP del dashboard (default 8050).
    --db <ruta>         Ruta de SQLite (default ./derivashield.db).
    --no-dashboard      Corre solo el loop de análisis — útil en servidores headless.

Alertas event-driven
--------------------
Cuando el detector marca una muestra, tres cosas pasan en el mismo tick:
    1. la muestra se guarda con is_anomaly=1 en SQLite (logger)
    2. se imprime una alerta coloreada a stdout
    3. el dashboard la levanta en su próximo refresh de 1 segundo
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from typing import Optional

import numpy as np

from analysis.derivatives import compute_derivatives
from capture.sniffer import Sniffer, build_default_sniffer
from dashboard.app import run_dashboard
from detection.anomaly import AnomalyDetector, AnomalyEvent
from storage.logger import LogRow, TrafficLogger


# Colores ANSI para las alertas de consola (degradan a texto plano en terminales tontas).
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"


def _color_for(severity: str) -> str:
    return {
        "HIGH": ANSI_RED,
        "MEDIUM": ANSI_YELLOW,
        "LOW": ANSI_CYAN,
    }.get(severity, "")


def _print_alert(event: AnomalyEvent) -> None:
    color = _color_for(event.severity)
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp))
    msg = (
        f"{color}[{event.severity}] {when} "
        f"f(t)={event.f_t:.1f}  f'(t)={event.f_prime:.2f}  "
        f"f''(t)={event.f_double_prime:.2f}  "
        f"(umbral={event.threshold:.2f}, μ={event.mu:.2f}, σ={event.sigma:.2f})"
        f"{ANSI_RESET}"
    )
    print(msg, flush=True)


def _handle_sniffer_error(e: Exception) -> None:
    """Reporte amigable de errores para el thread de captura."""
    if isinstance(e, PermissionError) or (
        isinstance(e, OSError) and "permitted" in str(e).lower()
    ):
        print(
            "\n[DerivaShield] la captura en vivo necesita privilegios de raw socket.\n"
            "  Prueba alguna de estas opciones:\n"
            "    sudo python main.py --live\n"
            "    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))\n"
            "  Cayendo a tráfico simulado para que la demo igual corra.\n",
            file=sys.stderr,
        )
    elif isinstance(e, FileNotFoundError):
        print(f"\n[DerivaShield] archivo PCAP no encontrado: {e}", file=sys.stderr)
    elif isinstance(e, ImportError):
        print(
            f"\n[DerivaShield] dependencia faltante: {e}.  "
            "Instala con: pip install -r requirements.txt",
            file=sys.stderr,
        )
    else:
        print(f"\n[DerivaShield] error de captura: {e}", file=sys.stderr)


def analysis_loop(
    sniffer: Sniffer,
    detector: AnomalyDetector,
    logger: TrafficLogger,
    stop_event: threading.Event,
    tick_seconds: float = 1.0,
) -> None:
    """
    Maneja el pipeline una vez por segundo:
        1. toma snapshot del buffer (t, f(t)) del sniffer
        2. calcula f'(t), f''(t)
        3. le pide al detector que marque cualquier anomalía nueva
        4. escribe la última muestra en SQLite (los eventos de anomalía
           disparan también el print por consola)

    Corre hasta que `stop_event` se setea.
    """
    last_persisted_ts: Optional[float] = None
    retention_last_run = 0.0

    while not stop_event.is_set():
        t_arr, f_arr = sniffer.counter.snapshot()
        if t_arr.size < 2:
            time.sleep(tick_seconds)
            continue

        series = compute_derivatives(t_arr, f_arr, smooth_window=3)
        events = detector.analyze(series)

        # Lookup para marcar la muestra persistida como anómala y arrastrar
        # la severidad hasta el logger.
        ev_by_ts = {round(ev.timestamp, 3): ev for ev in events}

        # Persistimos solo las muestras ya "asentadas" (mismo margen del
        # borde que usa el detector). Las últimas `edge_margin` muestras
        # todavía tienen f'(t) / f''(t) provisional y se persistirán en
        # el próximo tick, cuando sean interiores del buffer.
        persistable_end = max(0, series.t.size - detector.edge_margin)

        if persistable_end > 0:
            latest_persistable_ts = float(series.t[persistable_end - 1])
            if last_persisted_ts is None or latest_persistable_ts > last_persisted_ts:
                # Rellena cualquier hueco entre last_persisted_ts y el frente
                # persistible.
                start_idx = 0
                if last_persisted_ts is not None:
                    mask = series.t[:persistable_end] > last_persisted_ts
                    if mask.any():
                        start_idx = int(np.argmax(mask))
                rows = []
                for i in range(start_idx, persistable_end):
                    sample_ts = float(series.t[i])
                    ev = ev_by_ts.get(round(sample_ts, 3))
                    rows.append(
                        LogRow(
                            timestamp=sample_ts,
                            f_t=float(series.f[i]),
                            f_prime=float(series.f_prime[i]),
                            f_double_prime=float(series.f_double_prime[i]),
                            is_anomaly=ev is not None,
                            severity=ev.severity if ev else None,
                            tier="HOT",
                        )
                    )
                if rows:
                    logger.log_many(rows)
                    last_persisted_ts = rows[-1].timestamp

        # Alertas por consola (efecto colateral event-driven).
        # Y red de seguridad: garantiza que la fila quede con is_anomaly=1
        # incluso si una carrera entre persistencia y detección la perdió.
        for ev in events:
            _print_alert(ev)
            logger.mark_anomaly(ev.timestamp, ev.severity)

        # Aplica la retención una vez por hora.
        now = time.time()
        if now - retention_last_run > 3600.0:
            try:
                stats = logger.apply_retention(now=now)
                if any(stats.values()):
                    print(
                        f"[DerivaShield] retención: {stats}",
                        flush=True,
                    )
            except Exception as e:  # noqa: BLE001
                print(f"[DerivaShield] error de retención: {e}", file=sys.stderr)
            retention_last_run = now

        time.sleep(tick_seconds)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="derivashield",
        description=(
            "Detecta anomalías de tráfico de red mediante diferenciación numérica. "
            "Marca puntos donde f'(t) > μ + k·σ AND f''(t) > 0."
        ),
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument(
        "--live",
        action="store_true",
        help="Captura tráfico en vivo (requiere privilegios de raw socket).",
    )
    src.add_argument(
        "--file",
        dest="pcap",
        metavar="RUTA",
        help="Reproduce un archivo PCAP en vez de captura en vivo.",
    )
    p.add_argument(
        "--iface",
        default=None,
        help="Interfaz de red para --live (por defecto la de scapy).",
    )
    p.add_argument(
        "--k",
        type=float,
        default=2.0,
        help="Factor de sensibilidad k del umbral μ + k·σ (default: 2.0).",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8050,
        help="Puerto HTTP del dashboard Plotly Dash (default: 8050).",
    )
    p.add_argument(
        "--db",
        default="derivashield.db",
        help="Ruta de la base SQLite (default: derivashield.db).",
    )
    p.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Omite el dashboard; corre solo el pipeline de análisis.",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    # Aviso si pediste --live sin privilegios.
    if args.live and os.geteuid() != 0 and not _has_net_raw():
        print(
            "[DerivaShield] nota: --live normalmente requiere root o "
            "cap_net_raw. Continuando igualmente — si el SO niega el raw "
            "socket caerá a tráfico simulado.",
            file=sys.stderr,
        )

    logger = TrafficLogger(db_path=args.db)
    detector = AnomalyDetector(k=args.k)

    sniffer = build_default_sniffer(
        live=args.live,
        pcap_path=args.pcap,
        iface=args.iface,
        on_error=_handle_sniffer_error,
    )

    stop_event = threading.Event()

    def _on_signal(_signum, _frame):
        print("\n[DerivaShield] cerrando...", flush=True)
        stop_event.set()
        sniffer.stop()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    analysis_thread = threading.Thread(
        target=analysis_loop,
        args=(sniffer, detector, logger, stop_event),
        daemon=True,
    )
    analysis_thread.start()

    print(
        f"[DerivaShield] modo={sniffer.mode}  k={args.k}  db={args.db}"
        + (f"  dashboard=http://127.0.0.1:{args.port}" if not args.no_dashboard else ""),
        flush=True,
    )

    try:
        if args.no_dashboard:
            # Mantiene vivo el thread principal hasta recibir señal.
            while not stop_event.is_set():
                time.sleep(0.5)
        else:
            run_dashboard(
                logger=logger,
                detector=detector,
                host="127.0.0.1",
                port=args.port,
                debug=False,
            )
    finally:
        stop_event.set()
        sniffer.stop()
        analysis_thread.join(timeout=2.0)
        logger.close()

    return 0


def _has_net_raw() -> bool:
    """Chequeo best-effort de CAP_NET_RAW en el proceso actual."""
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    caps = int(line.split()[1], 16)
                    # CAP_NET_RAW es el bit 13.
                    return bool(caps & (1 << 13))
    except OSError:
        pass
    return False


if __name__ == "__main__":
    sys.exit(main())
