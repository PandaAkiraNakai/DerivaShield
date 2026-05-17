"""
dashboard/app.py
================
Capa de visualización en tiempo real (Plotly Dash).

Tres gráficos apilados, todos compartiendo el mismo eje temporal:

    Gráfico 1 — f(t)   : paquetes/s con marcadores de anomalía
    Gráfico 2 — f'(t)  : tasa de cambio + línea de umbral ámbar (μ + k·σ)
    Gráfico 3 — f''(t) : aceleración (una línea horizontal y=0 ayuda al ojo)

Paleta de colores (fijada por especificación):
    Tráfico normal    #0066CC  (azul)
    Anomalía          #CC0000  (rojo)
    Línea de umbral   #FFA500  (ámbar)

Refresco: cada 1000 ms. Ventana visible: últimos 60 segundos.

El dashboard es puro consumidor: lee del log SQLite producido por el loop
principal y del detector vivo en memoria para μ/σ actuales. NO captura
paquetes ni calcula derivadas por sí mismo.
"""

from __future__ import annotations

import time
from typing import Optional

import dash
import plotly.graph_objs as go
from dash import Dash, Input, Output, dcc, html

from detection.anomaly import AnomalyDetector
from storage.logger import TrafficLogger


COLOR_NORMAL = "#0066CC"
COLOR_ANOMALY = "#CC0000"
COLOR_THRESHOLD = "#FFA500"
WINDOW_SECONDS = 60
REFRESH_MS = 1000


def build_app(
    logger: TrafficLogger,
    detector: AnomalyDetector,
    window_seconds: int = WINDOW_SECONDS,
) -> Dash:
    """
    Construye la app Dash. `logger` y `detector` son las instancias vivas
    que está manejando main.py — el dashboard las observa, no las posee.
    """
    app = Dash(__name__, title="DerivaShield")

    app.layout = html.Div(
        style={
            "fontFamily": "Inter, system-ui, sans-serif",
            "backgroundColor": "#0E1117",
            "color": "#E6E6E6",
            "padding": "20px",
            "minHeight": "100vh",
        },
        children=[
            html.H1(
                "DerivaShield — Detección Diferencial de Anomalías de Tráfico",
                style={"marginBottom": "4px"},
            ),
            html.Div(
                id="status-line",
                style={"color": "#9aa0a6", "marginBottom": "16px"},
            ),
            dcc.Graph(id="graph-f", config={"displayModeBar": False}),
            dcc.Graph(id="graph-fp", config={"displayModeBar": False}),
            dcc.Graph(id="graph-fpp", config={"displayModeBar": False}),
            dcc.Interval(
                id="tick",
                interval=REFRESH_MS,
                n_intervals=0,
            ),
        ],
    )

    @app.callback(
        Output("graph-f", "figure"),
        Output("graph-fp", "figure"),
        Output("graph-fpp", "figure"),
        Output("status-line", "children"),
        Input("tick", "n_intervals"),
    )
    def _refresh(_n: int):
        rows = logger.fetch_recent(seconds=window_seconds)

        ts = [r.timestamp for r in rows]
        f = [r.f_t for r in rows]
        fp = [r.f_prime for r in rows]
        fpp = [r.f_double_prime for r in rows]
        anomaly_mask = [bool(r.is_anomaly) for r in rows]

        anomaly_ts = [t for t, a in zip(ts, anomaly_mask) if a]
        anomaly_f = [v for v, a in zip(f, anomaly_mask) if a]

        threshold = detector.threshold
        mu = detector.mu
        sigma = detector.sigma

        # --- Gráfico 1: f(t) ---
        fig_f = go.Figure()
        fig_f.add_trace(
            go.Scatter(
                x=ts,
                y=f,
                mode="lines",
                line=dict(color=COLOR_NORMAL, width=2),
                name="f(t) paquetes/s",
            )
        )
        if anomaly_ts:
            fig_f.add_trace(
                go.Scatter(
                    x=anomaly_ts,
                    y=anomaly_f,
                    mode="markers",
                    marker=dict(color=COLOR_ANOMALY, size=10, symbol="x"),
                    name="anomalía",
                )
            )
        _style(fig_f, title="f(t) — tráfico (paquetes/s)", yaxis_title="paquetes/s")

        # --- Gráfico 2: f'(t) con umbral ---
        fig_fp = go.Figure()
        fig_fp.add_trace(
            go.Scatter(
                x=ts,
                y=fp,
                mode="lines",
                line=dict(color=COLOR_NORMAL, width=2),
                name="f'(t)",
            )
        )
        if ts:
            fig_fp.add_trace(
                go.Scatter(
                    x=[ts[0], ts[-1]],
                    y=[threshold, threshold],
                    mode="lines",
                    line=dict(color=COLOR_THRESHOLD, width=2, dash="dash"),
                    name=f"μ + k·σ = {threshold:.2f}",
                )
            )
        anomaly_fp = [v for v, a in zip(fp, anomaly_mask) if a]
        if anomaly_ts:
            fig_fp.add_trace(
                go.Scatter(
                    x=anomaly_ts,
                    y=anomaly_fp,
                    mode="markers",
                    marker=dict(color=COLOR_ANOMALY, size=10, symbol="x"),
                    name="anomalía",
                )
            )
        _style(fig_fp, title="f'(t) — tasa de cambio", yaxis_title="d(paquetes)/dt")

        # --- Gráfico 3: f''(t) ---
        fig_fpp = go.Figure()
        fig_fpp.add_trace(
            go.Scatter(
                x=ts,
                y=fpp,
                mode="lines",
                line=dict(color=COLOR_NORMAL, width=2),
                name="f''(t)",
            )
        )
        if ts:
            fig_fpp.add_trace(
                go.Scatter(
                    x=[ts[0], ts[-1]],
                    y=[0, 0],
                    mode="lines",
                    line=dict(color=COLOR_THRESHOLD, width=1, dash="dot"),
                    name="cero",
                )
            )
        anomaly_fpp = [v for v, a in zip(fpp, anomaly_mask) if a]
        if anomaly_ts:
            fig_fpp.add_trace(
                go.Scatter(
                    x=anomaly_ts,
                    y=anomaly_fpp,
                    mode="markers",
                    marker=dict(color=COLOR_ANOMALY, size=10, symbol="x"),
                    name="anomalía",
                )
            )
        _style(fig_fpp, title="f''(t) — aceleración", yaxis_title="d²(paquetes)/dt²")

        status = (
            f"muestras mostradas: {len(rows)}  |  "
            f"μ(f'): {mu:.2f}  |  σ(f'): {sigma:.2f}  |  "
            f"umbral: {threshold:.2f}  |  "
            f"última actualización: {time.strftime('%H:%M:%S')}"
        )
        return fig_f, fig_fp, fig_fpp, status

    return app


def _style(fig: go.Figure, *, title: str, yaxis_title: str) -> None:
    fig.update_layout(
        title=dict(text=title, x=0.01, font=dict(color="#E6E6E6")),
        margin=dict(l=50, r=20, t=40, b=30),
        height=260,
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font=dict(color="#E6E6E6"),
        xaxis=dict(
            gridcolor="#22262E",
            zerolinecolor="#22262E",
            title="t (segundos epoch)",
        ),
        yaxis=dict(
            gridcolor="#22262E",
            zerolinecolor="#22262E",
            title=yaxis_title,
        ),
        legend=dict(orientation="h", y=-0.25, x=0),
        showlegend=True,
    )


def run_dashboard(
    logger: TrafficLogger,
    detector: AnomalyDetector,
    host: str = "127.0.0.1",
    port: int = 8050,
    debug: bool = False,
) -> None:
    """Llamada bloqueante — arranca el servidor HTTP de Dash."""
    app = build_app(logger, detector)
    # Dash 2.16+ usa app.run; versiones anteriores usan run_server.
    runner = getattr(app, "run", None) or app.run_server
    runner(host=host, port=port, debug=debug)
