"""
detection/anomaly.py
====================
Detector de anomalías basado en cálculo diferencial.

Criterio
--------
Una muestra en el tiempo t se marca como ANOMALÍA cuando se cumplen
las dos condiciones siguientes:

    (1)  f'(t)  >  μ + k · σ           ← la tasa de cambio supera la banda k-sigma
    (2)  f''(t) >  0                   ← Y esa tasa todavía está acelerando

Donde:
    μ  = media corriente de f'(t) sobre una ventana de baseline (excluyendo flagged)
    σ  = desviación estándar de f'(t) sobre esa misma ventana
    k  = factor de sensibilidad (por defecto 2.0)

Intuición
---------
El tráfico de red fluctúa naturalmente, así que un único valor alto de f(t)
no es, por sí solo, evidencia de ataque. Lo que distingue un ataque del
ruido es la FORMA de la curva: una subida rápida (f'(t) grande) que además
está acelerando (f''(t) positivo). El test k-sigma calibra "rápido" contra
el baseline reciente, así que el detector se adapta al régimen local de tráfico.

Niveles de severidad
--------------------
Traducimos la magnitud del exceso de f'(t) por encima del umbral en niveles
discretos que consume el dashboard y el logger:

    LOW     :   μ + k·σ      <  f'(t)  ≤  μ + 2k·σ
    MEDIUM  :   μ + 2k·σ     <  f'(t)  ≤  μ + 4k·σ
    HIGH    :   μ + 4k·σ     <  f'(t)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import numpy as np

from analysis.derivatives import DerivativeSeries


SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"


@dataclass
class AnomalyEvent:
    """Una anomalía detectada. La persiste storage/logger.py y la dibuja el dashboard."""

    timestamp: float            # segundos epoch, el t en el que f'(t) cruzó el umbral
    f_t: float                  # paquetes/s en ese instante
    f_prime: float              # tasa de cambio en ese instante
    f_double_prime: float       # aceleración en ese instante
    threshold: float            # μ + k·σ usado para marcar este punto
    mu: float
    sigma: float
    severity: str               # LOW / MEDIUM / HIGH

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "f_t": self.f_t,
            "f_prime": self.f_prime,
            "f_double_prime": self.f_double_prime,
            "threshold": self.threshold,
            "mu": self.mu,
            "sigma": self.sigma,
            "severity": self.severity,
        }


class AnomalyDetector:
    """
    Detector con estado. `analyze()` se llama repetidamente con la última
    DerivativeSeries de la capa de análisis y devuelve el subconjunto de
    puntos de esa ventana que cumplen el criterio de anomalía.

    El detector mantiene un baseline de largo plazo de valores de f'(t)
    para μ y σ, refrescado en cada llamada. Las muestras flagged se
    excluyen del baseline para que un ataque sostenido no "envenene" a μ
    y enmascare anomalías futuras.
    """

    def __init__(
        self,
        k: float = 2.0,
        min_baseline_samples: int = 10,
        baseline_window: int = 300,
        edge_margin: int = 3,
    ) -> None:
        self.k = float(k)
        self.min_baseline_samples = int(min_baseline_samples)
        self.baseline_window = int(baseline_window)
        # Cuántas muestras del borde derecho del buffer ignoramos en cada
        # análisis. f'(t) y f''(t) se calculan con diferencia central, así
        # que las últimas muestras tienen valores que aún van a cambiar
        # cuando lleguen muestras nuevas. Procesarlas ahora sería leer
        # valores transitorios. Margen = 3 cubre suavizado + las dos
        # aplicaciones recursivas de np.gradient.
        self.edge_margin = int(edge_margin)

        # Baseline rolling de muestras de f'(t) limpias (no anómalas).
        self._baseline: List[float] = []
        # Timestamps ya analizados — garantiza que cada muestra se procese
        # una sola vez (entra al baseline o dispara evento, no las dos).
        self._processed_ts: set[float] = set()

    # ----- API pública -----

    @property
    def mu(self) -> float:
        return float(np.mean(self._baseline)) if self._baseline else 0.0

    @property
    def sigma(self) -> float:
        return float(np.std(self._baseline)) if len(self._baseline) > 1 else 0.0

    @property
    def threshold(self) -> float:
        """μ + k·σ — cota superior actual del f'(t) "normal"."""
        return self.mu + self.k * self.sigma

    def analyze(self, series: DerivativeSeries) -> List[AnomalyEvent]:
        """
        Recorre la ventana reciente de tuplas (t, f, f', f'') y emite
        objetos AnomalyEvent por cada muestra nueva que cumpla:
            f'(t) > μ + k·σ  AND  f''(t) > 0
        """
        if len(series) == 0:
            return []

        new_events: List[AnomalyEvent] = []
        # Snapshot de μ/σ al inicio del pasado para que todas las decisiones
        # dentro de la llamada sean consistentes.
        mu = self.mu
        sigma = self.sigma
        thr = mu + self.k * sigma

        # Solo procesamos muestras lo suficientemente lejos del borde derecho
        # como para que sus valores de f'(t) y f''(t) ya no vayan a cambiar
        # cuando llegue una muestra nueva. Las últimas `edge_margin`
        # muestras se procesarán en la próxima llamada, cuando sean interiores.
        last_processable = max(0, series.t.size - self.edge_margin)

        for i in range(last_processable):
            ts = float(series.t[i])

            # Cada timestamp se procesa una sola vez. Esto evita inflar el
            # baseline al re-añadir muestras viejas en cada tick.
            if ts in self._processed_ts:
                continue
            self._processed_ts.add(ts)

            f_t = float(series.f[i])
            fp = float(series.f_prime[i])
            fpp = float(series.f_double_prime[i])

            # Fase de bootstrap: aún no hay suficiente baseline — acumular, no flaggear.
            if len(self._baseline) < self.min_baseline_samples:
                self._add_to_baseline(fp)
                continue

            is_anomaly = (fp > thr) and (fpp > 0.0)

            if is_anomaly:
                new_events.append(
                    AnomalyEvent(
                        timestamp=ts,
                        f_t=f_t,
                        f_prime=fp,
                        f_double_prime=fpp,
                        threshold=thr,
                        mu=mu,
                        sigma=sigma,
                        severity=self._severity(fp, mu, sigma),
                    )
                )
                # NO sumar fp anómalo al baseline — protege a μ del envenenamiento.
            else:
                self._add_to_baseline(fp)

        # Evita que _processed_ts crezca sin tope: olvida lo anterior al
        # comienzo de la ventana visible (ya nunca volverá a entrar).
        if len(self._processed_ts) > 10_000:
            cutoff = float(series.t[0]) if series.t.size else 0.0
            self._processed_ts = {ts for ts in self._processed_ts if ts >= cutoff}

        return new_events

    def is_anomaly(self, fp: float, fpp: float) -> bool:
        """Predicado puro — útil para tests unitarios y chequeos ad-hoc."""
        if len(self._baseline) < self.min_baseline_samples:
            return False
        return (fp > self.threshold) and (fpp > 0.0)

    def reset_baseline(self) -> None:
        self._baseline.clear()
        self._processed_ts.clear()

    # ----- internos -----

    def _add_to_baseline(self, fp: float) -> None:
        self._baseline.append(float(fp))
        if len(self._baseline) > self.baseline_window:
            # Borra los más viejos en O(n); baseline_window es chico (~300) así que está bien.
            del self._baseline[: len(self._baseline) - self.baseline_window]

    def _severity(self, fp: float, mu: float, sigma: float) -> str:
        """Mapea la magnitud del exceso de f'(t) a LOW / MEDIUM / HIGH."""
        if sigma <= 0.0:
            # Baseline degenerado; tratar cualquier disparo positivo como MEDIUM.
            return SEVERITY_MEDIUM
        excess_in_sigmas = (fp - mu) / sigma
        if excess_in_sigmas > 4.0 * self.k:
            return SEVERITY_HIGH
        if excess_in_sigmas > 2.0 * self.k:
            return SEVERITY_MEDIUM
        return SEVERITY_LOW


def classify_severity(fp: float, mu: float, sigma: float, k: float = 2.0) -> Optional[str]:
    """
    Helper standalone para llamadores que ya tienen μ y σ (por ejemplo el
    dashboard al renderear muestras pasadas). Devuelve None para puntos que
    no cruzan el umbral.
    """
    if sigma <= 0.0:
        return None
    if fp <= mu + k * sigma:
        return None
    excess = (fp - mu) / sigma
    if excess > 4.0 * k:
        return SEVERITY_HIGH
    if excess > 2.0 * k:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW
