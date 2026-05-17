"""
capture/sniffer.py
==================
Capa de captura de paquetes de DerivaShield.

Produce la serie temporal discreta f(t) = paquetes observados en el segundo t.
Esa señal es la entrada del pipeline diferencial corriente abajo:
    f(t)  -> derivatives.py -> f'(t), f''(t) -> anomaly.py

Se soportan tres fuentes:
    1. Captura en vivo con Scapy (requiere privilegios de raw socket).
    2. Reproducción offline de archivos PCAP.
    3. Fallback puramente sintético usado cuando no hay interfaz disponible,
       para que el sistema siga siendo demostrable en máquinas sin root.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Optional

import numpy as np


@dataclass
class PacketCounter:
    """
    Buffer rolling thread-safe de muestras paquetes-por-segundo.

    Cada muestra representa f(t_i): la cantidad entera de paquetes observados
    durante el intervalo de un segundo que termina en t_i. Los consumidores
    (el motor de derivadas) leen las últimas N muestras para reconstruir la
    señal discreta.
    """

    window_seconds: int = 120
    samples: Deque[tuple[float, int]] = field(default_factory=deque)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _current_second: Optional[int] = None
    _current_count: int = 0

    def increment(self, n: int = 1) -> None:
        """Registra `n` paquetes en el bucket del segundo actual de reloj."""
        now = time.time()
        bucket = int(now)
        with self._lock:
            if self._current_second is None:
                self._current_second = bucket
            if bucket != self._current_second:
                # Vaciar el/los segundo(s) ya completados como muestras de f(t).
                self._flush_locked(bucket)
            self._current_count += n

    def tick(self) -> None:
        """
        Fuerza el cierre del segundo actual aunque no haya llegado ningún paquete.

        Hace falta para que los intervalos sin tráfico se registren como
        f(t)=0 en vez de saltarse — las derivadas requieren muestreo
        uniforme en t.
        """
        now = int(time.time())
        with self._lock:
            if self._current_second is None:
                self._current_second = now
                return
            if now != self._current_second:
                self._flush_locked(now)

    def _flush_locked(self, new_bucket: int) -> None:
        # Emite el bucket recién terminado y luego rellena segundos vacíos
        # intermedios con ceros para que la grilla de muestreo siga uniforme
        # (Δt = 1s).
        self.samples.append((float(self._current_second), self._current_count))
        gap = new_bucket - self._current_second - 1
        for k in range(1, gap + 1):
            self.samples.append((float(self._current_second + k), 0))
        self._current_second = new_bucket
        self._current_count = 0
        # Memoria acotada: solo guarda la ventana final.
        while len(self.samples) > self.window_seconds:
            self.samples.popleft()

    def snapshot(self) -> tuple[np.ndarray, np.ndarray]:
        """Devuelve (t_array, f_array) del buffer actual para análisis."""
        with self._lock:
            if not self.samples:
                return np.array([]), np.array([])
            t = np.fromiter((s[0] for s in self.samples), dtype=float)
            f = np.fromiter((s[1] for s in self.samples), dtype=float)
        return t, f


class Sniffer:
    """
    Fuente unificada de paquetes. Elige uno de los tres constructores:
        Sniffer.live(iface=...)
        Sniffer.from_pcap(path)
        Sniffer.simulated()

    Los tres alimentan el mismo PacketCounter, así que el código corriente
    abajo es idéntico.
    """

    def __init__(
        self,
        counter: Optional[PacketCounter] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        self.counter = counter or PacketCounter()
        self._on_error = on_error or (lambda e: None)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._mode: str = "idle"

    # ----- ciclo de vida público -----

    def start_live(self, iface: Optional[str] = None) -> None:
        """Inicia captura en vivo en un thread en segundo plano."""
        self._mode = "live"
        self._thread = threading.Thread(
            target=self._run_live, args=(iface,), daemon=True
        )
        self._thread.start()

    def start_pcap(self, path: str, speed: float = 1.0) -> None:
        """
        Reproduce un archivo PCAP. `speed` reescala el timing entre paquetes
        (1.0 = timing original, >1 más rápido, <1 más lento).
        """
        self._mode = "pcap"
        self._thread = threading.Thread(
            target=self._run_pcap, args=(path, speed), daemon=True
        )
        self._thread.start()

    def start_simulated(self) -> None:
        """
        Genera timestamps sintéticos de paquetes:
            - baseline ~ 100 pkts/s con ruido gaussiano
            - spike de DDoS en t=30s hasta ~800 pkts/s
            - rampa de port-scan en t=60s creciendo de 100 a 400 pkts/s
        """
        self._mode = "simulated"
        self._thread = threading.Thread(target=self._run_simulated, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    @property
    def mode(self) -> str:
        return self._mode

    # ----- runners internos -----

    def _run_live(self, iface: Optional[str]) -> None:
        try:
            from scapy.all import sniff  # type: ignore
        except ImportError as e:
            self._on_error(e)
            return

        def _on_packet(_pkt) -> None:  # noqa: ANN001
            self.counter.increment(1)

        # Thread de heartbeat para que los intervalos f(t)=0 igual se registren.
        threading.Thread(target=self._heartbeat, daemon=True).start()

        try:
            sniff(
                iface=iface,
                prn=_on_packet,
                store=False,
                stop_filter=lambda _p: self._stop.is_set(),
            )
        except PermissionError as e:
            self._on_error(e)
        except OSError as e:
            # Típicamente "Operation not permitted" sin CAP_NET_RAW.
            self._on_error(e)
        except Exception as e:  # noqa: BLE001
            self._on_error(e)

    def _run_pcap(self, path: str, speed: float) -> None:
        try:
            from scapy.all import PcapReader  # type: ignore
        except ImportError as e:
            self._on_error(e)
            return

        threading.Thread(target=self._heartbeat, daemon=True).start()

        try:
            with PcapReader(path) as reader:
                prev_ts: Optional[float] = None
                for pkt in reader:
                    if self._stop.is_set():
                        break
                    ts = float(getattr(pkt, "time", time.time()))
                    if prev_ts is not None and speed > 0:
                        delay = max(0.0, (ts - prev_ts) / speed)
                        time.sleep(min(delay, 1.0))
                    prev_ts = ts
                    self.counter.increment(1)
        except FileNotFoundError as e:
            self._on_error(e)
        except Exception as e:  # noqa: BLE001
            self._on_error(e)

    def _run_simulated(self) -> None:
        """
        Fuente sintética. f(t) ~ baseline + ataques inyectados.
        Sirve tanto de fallback sin permisos como de dataset de demo.
        """
        rng = np.random.default_rng(seed=42)
        t0 = time.time()
        # El heartbeat asegura que los segundos vacíos igual se vacíen.
        threading.Thread(target=self._heartbeat, daemon=True).start()

        while not self._stop.is_set():
            elapsed = time.time() - t0

            # Baseline: ~100 pkts/s con ruido gaussiano.
            rate = 100.0 + rng.normal(0.0, 8.0)

            # Spike de DDoS: 30 <= t < 40, ráfaga gaussiana hasta ~800 pkts/s.
            if 30.0 <= elapsed < 40.0:
                spike = 700.0 * np.exp(-((elapsed - 33.0) ** 2) / 4.0)
                rate += spike

            # Rampa de port-scan: 60 <= t < 90, lineal de 100 a 400 pkts/s extra.
            if 60.0 <= elapsed < 90.0:
                rate += 300.0 * (elapsed - 60.0) / 30.0

            rate = max(0.0, rate)
            # Emite `rate` paquetes distribuidos uniformemente en el siguiente segundo.
            n = int(rate)
            for _ in range(n):
                if self._stop.is_set():
                    return
                self.counter.increment(1)
                # Los reparte para que el segundo se "llene" naturalmente.
                time.sleep(max(1e-4, 1.0 / max(n, 1)))

    def _heartbeat(self) -> None:
        """Hace tick al contador cada 250ms para vaciar segundos ociosos como f(t)=0."""
        while not self._stop.is_set():
            self.counter.tick()
            time.sleep(0.25)


def build_default_sniffer(
    live: bool,
    pcap_path: Optional[str],
    iface: Optional[str],
    on_error: Optional[Callable[[Exception], None]] = None,
) -> Sniffer:
    """
    Factory usada por main.py. Orden de resolución:
        1. --file <path>  -> reproducción de PCAP
        2. --live         -> captura en vivo (cae a simulated si falla)
        3. en otro caso   -> simulated
    """
    sniffer = Sniffer(on_error=on_error)
    if pcap_path:
        sniffer.start_pcap(pcap_path)
    elif live:
        sniffer.start_live(iface=iface)
    else:
        sniffer.start_simulated()
    return sniffer
