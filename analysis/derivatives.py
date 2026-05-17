"""
analysis/derivatives.py
=======================
Diferenciación numérica de la señal de tasa de paquetes f(t).

Tratamos f(t) como una señal discreta muestreada uniformemente con Δt = 1 segundo.
Se producen dos derivadas por diferencias finitas:

    f'(t)  ≈ ( f(t + Δt) - f(t) ) / Δt       (tasa de cambio del tráfico)
    f''(t) ≈ ( f'(t + Δt) - f'(t) ) / Δt     (aceleración del tráfico)

Para los puntos interiores usamos el esquema de diferencia central provisto
por ``numpy.gradient``, con precisión O(Δt²). En los extremos numpy
automáticamente cae a una diferencia unilateral, lo que coincide con las
definiciones formales hacia adelante y hacia atrás de arriba.

Interpretación:
    f(t)   "¿cuánto tráfico hay ahora?"        — magnitud
    f'(t)  "¿el tráfico crece o decrece?"      — pendiente / velocidad
    f''(t) "¿ese crecimiento se acelera?"      — concavidad / aceleración

Un DDoS o un port-scan empieza como un f'(t) positivo y súbito con f''(t)
positivo: no es solo "más tráfico", sino "más tráfico y acelerando". Esa
condición conjunta es la que dispara el detector en anomaly.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np


@dataclass
class DerivativeSeries:
    """Paquete de arrays alineados t, f(t), f'(t), f''(t) — todos del mismo largo."""

    t: np.ndarray
    f: np.ndarray
    f_prime: np.ndarray
    f_double_prime: np.ndarray

    def __len__(self) -> int:
        return int(self.t.size)

    def last(self) -> Optional[tuple[float, float, float, float]]:
        """Devuelve (t, f, f', f'') de la muestra más reciente, o None si está vacío."""
        if self.t.size == 0:
            return None
        return (
            float(self.t[-1]),
            float(self.f[-1]),
            float(self.f_prime[-1]),
            float(self.f_double_prime[-1]),
        )


def compute_derivatives(
    t: np.ndarray,
    f: np.ndarray,
    smooth_window: int = 3,
) -> DerivativeSeries:
    """
    Calcula f'(t) y f''(t) a partir de una señal de tráfico muestreada.

    Parameters
    ----------
    t : np.ndarray
        Timestamps en segundos. Se asume (y se requiere) espaciado uniforme.
    f : np.ndarray
        f(t): paquetes por segundo en cada timestamp.
    smooth_window : int
        Ventana opcional de media móvil aplicada a f(t) ANTES de derivar.
        La derivación amplifica el ruido de alta frecuencia — una ventana
        de suavizado pequeña mantiene f'(t) y f''(t) interpretables sin
        aplanar los flancos reales del ataque (una ventana de 3 mantiene
        el retardo de respuesta ≤ 1 muestra).

    Returns
    -------
    DerivativeSeries con t, f, f', f'' alineados 1:1.
    """
    t = np.asarray(t, dtype=float)
    f = np.asarray(f, dtype=float)

    if t.size == 0 or f.size == 0:
        empty = np.array([], dtype=float)
        return DerivativeSeries(empty, empty, empty, empty)

    if t.size != f.size:
        raise ValueError(
            f"t y f deben tener el mismo largo, se obtuvo {t.size} y {f.size}"
        )

    # Δt — se asume uniforme; numpy.gradient maneja el caso no-uniforme si hace falta.
    if t.size >= 2:
        dt = float(np.median(np.diff(t)))
        if dt <= 0:
            dt = 1.0
    else:
        dt = 1.0

    f_smoothed = _moving_average(f, smooth_window) if smooth_window > 1 else f

    # f'(t) — diferencia central en el interior, unilateral en los bordes.
    f_prime = np.gradient(f_smoothed, dt)
    # f''(t) — deriva f'(t) otra vez con el mismo esquema.
    f_double_prime = np.gradient(f_prime, dt)

    return DerivativeSeries(
        t=t,
        f=f,                       # reporta el f(t) crudo, no el suavizado
        f_prime=f_prime,
        f_double_prime=f_double_prime,
    )


def _moving_average(x: np.ndarray, window: int) -> np.ndarray:
    """
    Media móvil centrada con padding de reflexión para preservar el largo.

    El padding por reflexión (en vez de padding con ceros) evita crear un
    acantilado artificial en el borde que después aparecería como un pico
    fantasma en f'(t).
    """
    if window <= 1 or x.size < window:
        return x
    pad = window // 2
    padded = np.pad(x, pad_width=pad, mode="reflect")
    kernel = np.ones(window, dtype=float) / float(window)
    smoothed = np.convolve(padded, kernel, mode="valid")
    # Re-alinear al largo original (convolve puede diferir en uno para ventana par).
    if smoothed.size > x.size:
        smoothed = smoothed[: x.size]
    elif smoothed.size < x.size:
        smoothed = np.pad(smoothed, (0, x.size - smoothed.size), mode="edge")
    return smoothed
