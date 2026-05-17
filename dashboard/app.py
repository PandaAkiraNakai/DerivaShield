"""
dashboard/app.py
================
Capa de visualización (Plotly Dash) con dos páginas:

  /          — Vista en vivo: 3 gráficos (f, f', f'') + panel de alertas
               de los últimos 5 minutos, refresco cada 1 s.

  /reporte   — Reporte histórico: rango de fechas o "reporte completo",
               con resumen, gráfico de f(t) marcando las anomalías, y
               tabla con todas las anomalías del rango.

El dashboard es puro consumidor: lee del log SQLite producido por el
loop principal y del detector vivo en memoria para μ/σ actuales. NO
captura paquetes ni calcula derivadas por sí mismo.
"""

from __future__ import annotations

import time
from datetime import date, datetime, timezone
from typing import List, Optional

import dash
import plotly.graph_objs as go
from dash import Dash, Input, Output, State, dcc, html, no_update

from detection.anomaly import AnomalyDetector
from storage.logger import LogRow, TrafficLogger


COLOR_NORMAL = "#0066CC"
COLOR_ANOMALY = "#CC0000"
COLOR_THRESHOLD = "#FFA500"
WINDOW_SECONDS = 60
ALERTS_WINDOW_SECONDS = 300   # ventana del panel de alertas (5 min)
ALERTS_MAX_ROWS = 50          # tope de filas mostradas en vivo
REPORT_TABLE_LIMIT = 500      # tope de filas mostradas en el reporte
REFRESH_MS = 1000

SEVERITY_COLORS = {
    "HIGH":   "#CC0000",
    "MEDIUM": "#FFA500",
    "LOW":    "#3DB8FF",
}


# ---------------------------------------------------------------------------
# Shell + ruteo
# ---------------------------------------------------------------------------

def build_app(
    logger: TrafficLogger,
    detector: AnomalyDetector,
    window_seconds: int = WINDOW_SECONDS,
) -> Dash:
    app = Dash(__name__, title="DerivaShield", suppress_callback_exceptions=True)

    app.layout = html.Div(
        style={
            "fontFamily": "Inter, system-ui, sans-serif",
            "backgroundColor": "#0E1117",
            "color": "#E6E6E6",
            "padding": "20px",
            "minHeight": "100vh",
        },
        children=[
            dcc.Location(id="url", refresh=False),
            _navbar(),
            html.Div(id="page-content"),
        ],
    )

    @app.callback(Output("page-content", "children"),
                  Input("url", "pathname"))
    def _route(pathname: Optional[str]):
        if pathname and pathname.rstrip("/") == "/reporte":
            return _report_layout(logger)
        return _live_layout()

    _register_live_callbacks(app, logger, detector, window_seconds)
    _register_report_callbacks(app, logger)

    return app


def _navbar() -> html.Div:
    link_style = {
        "color": "#E6E6E6",
        "textDecoration": "none",
        "padding": "6px 14px",
        "borderRadius": "4px",
        "marginRight": "6px",
        "backgroundColor": "#161B22",
        "border": "1px solid #22262E",
        "fontSize": "13px",
    }
    return html.Div(
        style={
            "display": "flex",
            "alignItems": "center",
            "justifyContent": "space-between",
            "marginBottom": "16px",
        },
        children=[
            html.H1(
                "DerivaShield — Detección Diferencial de Anomalías de Tráfico",
                style={"margin": "0", "fontSize": "20px"},
            ),
            html.Nav(
                children=[
                    dcc.Link("Vivo",    href="/",        style=link_style),
                    dcc.Link("Reporte", href="/reporte", style=link_style),
                ],
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Página: Vivo
# ---------------------------------------------------------------------------

def _live_layout() -> html.Div:
    return html.Div(children=[
        html.Div(id="status-line",
                 style={"color": "#9aa0a6", "marginBottom": "16px"}),
        _alerts_panel_skeleton(),
        dcc.Graph(id="graph-f",   config={"displayModeBar": False}),
        dcc.Graph(id="graph-fp",  config={"displayModeBar": False}),
        dcc.Graph(id="graph-fpp", config={"displayModeBar": False}),
        dcc.Interval(id="tick", interval=REFRESH_MS, n_intervals=0),
    ])


def _alerts_panel_skeleton() -> html.Div:
    return html.Div(
        style={
            "backgroundColor": "#161B22",
            "border": "1px solid #22262E",
            "borderRadius": "6px",
            "padding": "14px 16px",
            "marginBottom": "20px",
        },
        children=[
            html.Div(
                style={
                    "display": "flex",
                    "alignItems": "center",
                    "justifyContent": "space-between",
                    "marginBottom": "10px",
                },
                children=[
                    html.H3(
                        f"Alertas (últimos {ALERTS_WINDOW_SECONDS // 60} min)",
                        style={"margin": "0", "fontSize": "16px"},
                    ),
                    html.Div(id="alerts-summary", style={"fontSize": "13px"}),
                ],
            ),
            html.Div(
                id="alerts-table",
                style={
                    "maxHeight": "260px",
                    "overflowY": "auto",
                    "fontFamily": "JetBrains Mono, ui-monospace, monospace",
                    "fontSize": "12.5px",
                },
            ),
        ],
    )


def _register_live_callbacks(app, logger, detector, window_seconds):
    @app.callback(
        Output("graph-f", "figure"),
        Output("graph-fp", "figure"),
        Output("graph-fpp", "figure"),
        Output("status-line", "children"),
        Output("alerts-summary", "children"),
        Output("alerts-table", "children"),
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
        fig_f.add_trace(go.Scatter(
            x=ts, y=f, mode="lines",
            line=dict(color=COLOR_NORMAL, width=2),
            name="f(t) paquetes/s",
        ))
        if anomaly_ts:
            fig_f.add_trace(go.Scatter(
                x=anomaly_ts, y=anomaly_f, mode="markers",
                marker=dict(color=COLOR_ANOMALY, size=10, symbol="x"),
                name="anomalía",
            ))
        _style(fig_f, title="f(t) — tráfico (paquetes/s)", yaxis_title="paquetes/s")

        # --- Gráfico 2: f'(t) con umbral ---
        fig_fp = go.Figure()
        fig_fp.add_trace(go.Scatter(
            x=ts, y=fp, mode="lines",
            line=dict(color=COLOR_NORMAL, width=2), name="f'(t)",
        ))
        if ts:
            fig_fp.add_trace(go.Scatter(
                x=[ts[0], ts[-1]], y=[threshold, threshold], mode="lines",
                line=dict(color=COLOR_THRESHOLD, width=2, dash="dash"),
                name=f"μ + k·σ = {threshold:.2f}",
            ))
        anomaly_fp = [v for v, a in zip(fp, anomaly_mask) if a]
        if anomaly_ts:
            fig_fp.add_trace(go.Scatter(
                x=anomaly_ts, y=anomaly_fp, mode="markers",
                marker=dict(color=COLOR_ANOMALY, size=10, symbol="x"),
                name="anomalía",
            ))
        _style(fig_fp, title="f'(t) — tasa de cambio", yaxis_title="d(paquetes)/dt")

        # --- Gráfico 3: f''(t) ---
        fig_fpp = go.Figure()
        fig_fpp.add_trace(go.Scatter(
            x=ts, y=fpp, mode="lines",
            line=dict(color=COLOR_NORMAL, width=2), name="f''(t)",
        ))
        if ts:
            fig_fpp.add_trace(go.Scatter(
                x=[ts[0], ts[-1]], y=[0, 0], mode="lines",
                line=dict(color=COLOR_THRESHOLD, width=1, dash="dot"),
                name="cero",
            ))
        anomaly_fpp = [v for v, a in zip(fpp, anomaly_mask) if a]
        if anomaly_ts:
            fig_fpp.add_trace(go.Scatter(
                x=anomaly_ts, y=anomaly_fpp, mode="markers",
                marker=dict(color=COLOR_ANOMALY, size=10, symbol="x"),
                name="anomalía",
            ))
        _style(fig_fpp, title="f''(t) — aceleración", yaxis_title="d²(paquetes)/dt²")

        status = (
            f"muestras mostradas: {len(rows)}  |  "
            f"μ(f'): {mu:.2f}  |  σ(f'): {sigma:.2f}  |  "
            f"umbral: {threshold:.2f}  |  "
            f"última actualización: {time.strftime('%H:%M:%S')}"
        )

        alerts = logger.fetch_anomalies(seconds=ALERTS_WINDOW_SECONDS)
        alerts.sort(key=lambda r: r.timestamp, reverse=True)
        alerts = alerts[:ALERTS_MAX_ROWS]
        summary = _build_alerts_summary(alerts)
        table = _build_alerts_table(alerts, time_fmt="%H:%M:%S")

        return fig_f, fig_fp, fig_fpp, status, summary, table


# ---------------------------------------------------------------------------
# Página: Reporte
# ---------------------------------------------------------------------------

def _report_layout(logger: TrafficLogger) -> html.Div:
    t_min, t_max = logger.date_bounds()
    if t_min is None:
        min_date = max_date = date.today()
        helper = "La base aún no tiene muestras."
    else:
        min_date = datetime.fromtimestamp(t_min).date()
        max_date = datetime.fromtimestamp(t_max).date()
        helper = (
            f"Datos disponibles: {min_date.isoformat()} → {max_date.isoformat()}  "
            f"({_humanize_count(t_min, t_max)})"
        )

    return html.Div(children=[
        html.Div(
            style={
                "backgroundColor": "#161B22",
                "border": "1px solid #22262E",
                "borderRadius": "6px",
                "padding": "14px 16px",
                "marginBottom": "20px",
            },
            children=[
                html.H3("Reporte histórico",
                        style={"margin": "0 0 8px 0", "fontSize": "16px"}),
                html.Div(helper, style={"color": "#9aa0a6",
                                        "fontSize": "12.5px",
                                        "marginBottom": "12px"}),
                html.Div(
                    style={"display": "flex", "gap": "12px",
                           "alignItems": "center", "flexWrap": "wrap"},
                    children=[
                        dcc.DatePickerRange(
                            id="report-range",
                            min_date_allowed=min_date,
                            max_date_allowed=max_date,
                            start_date=min_date,
                            end_date=max_date,
                            display_format="YYYY-MM-DD",
                        ),
                        dcc.Checklist(
                            id="report-full",
                            options=[{"label": "  Reporte completo (ignorar fechas)",
                                      "value": "full"}],
                            value=[],
                            style={"color": "#E6E6E6", "fontSize": "13px"},
                        ),
                        html.Button(
                            "Generar reporte",
                            id="report-generate",
                            n_clicks=0,
                            style={
                                "backgroundColor": COLOR_NORMAL,
                                "color": "#FFFFFF",
                                "border": "none",
                                "padding": "8px 14px",
                                "borderRadius": "4px",
                                "cursor": "pointer",
                                "fontWeight": 600,
                            },
                        ),
                    ],
                ),
            ],
        ),
        html.Div(id="report-output"),
    ])


def _register_report_callbacks(app, logger):
    @app.callback(
        Output("report-output", "children"),
        Input("report-generate", "n_clicks"),
        State("report-range", "start_date"),
        State("report-range", "end_date"),
        State("report-full", "value"),
        prevent_initial_call=False,
    )
    def _generate(n_clicks, start_date, end_date, full_value):
        full = bool(full_value) and "full" in full_value
        if full:
            t_from = t_to = None
            range_label = "Reporte completo"
        else:
            if not start_date or not end_date:
                return html.Div(
                    "Elegí un rango de fechas o marcá «Reporte completo».",
                    style={"color": "#9aa0a6", "padding": "8px"},
                )
            t_from = _start_of_day_local(start_date)
            t_to = _end_of_day_local(end_date)
            range_label = f"{start_date} → {end_date}"

        rows = logger.fetch_range(t_from=t_from, t_to=t_to)
        if not rows:
            return html.Div(
                f"Sin datos para «{range_label}».",
                style={"color": "#9aa0a6", "padding": "12px",
                       "backgroundColor": "#161B22",
                       "border": "1px solid #22262E", "borderRadius": "6px"},
            )

        return _build_report(rows, range_label)


def _build_report(rows: List[LogRow], range_label: str) -> html.Div:
    total = len(rows)
    anomalies = [r for r in rows if r.is_anomaly]
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in anomalies:
        if r.severity in counts:
            counts[r.severity] += 1

    first_ts = rows[0].timestamp
    last_ts = rows[-1].timestamp
    first_str = datetime.fromtimestamp(first_ts).strftime("%Y-%m-%d %H:%M:%S")
    last_str = datetime.fromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M:%S")
    span_s = max(1.0, last_ts - first_ts)
    anom_rate = (len(anomalies) / total) * 100 if total else 0.0

    # Resumen
    cards = html.Div(
        style={"display": "grid", "gap": "10px",
               "gridTemplateColumns": "repeat(auto-fit, minmax(180px, 1fr))",
               "marginBottom": "16px"},
        children=[
            _stat_card("Rango",            range_label),
            _stat_card("Desde / Hasta",    f"{first_str}  →  {last_str}"),
            _stat_card("Duración",         _humanize_seconds(span_s)),
            _stat_card("Muestras",         f"{total:,}".replace(",", ".")),
            _stat_card("Anomalías",        f"{len(anomalies):,}".replace(",", ".")
                                            + f"  ({anom_rate:.2f}%)"),
            _stat_card("HIGH / MED / LOW",
                       f"{counts['HIGH']} / {counts['MEDIUM']} / {counts['LOW']}"),
        ],
    )

    # Gráfico de f(t)
    ts = [r.timestamp for r in rows]
    f = [r.f_t for r in rows]
    anom_ts = [r.timestamp for r in anomalies]
    anom_f = [r.f_t for r in anomalies]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=[datetime.fromtimestamp(t) for t in ts], y=f, mode="lines",
        line=dict(color=COLOR_NORMAL, width=1.5), name="f(t)",
    ))
    if anom_ts:
        fig.add_trace(go.Scatter(
            x=[datetime.fromtimestamp(t) for t in anom_ts], y=anom_f,
            mode="markers",
            marker=dict(color=COLOR_ANOMALY, size=8, symbol="x"),
            name="anomalía",
        ))
    _style(fig, title="f(t) en el rango", yaxis_title="paquetes/s")
    fig.update_layout(height=320, xaxis=dict(title="tiempo",
                                             gridcolor="#22262E",
                                             zerolinecolor="#22262E"))

    # Tabla de anomalías (con paginación simple: tope REPORT_TABLE_LIMIT)
    anomalies.sort(key=lambda r: r.timestamp, reverse=True)
    truncated = len(anomalies) > REPORT_TABLE_LIMIT
    shown = anomalies[:REPORT_TABLE_LIMIT]

    header = html.Div(
        style={"display": "flex", "alignItems": "baseline",
               "justifyContent": "space-between",
               "marginTop": "12px", "marginBottom": "6px"},
        children=[
            html.H3("Anomalías en el rango",
                    style={"margin": 0, "fontSize": "16px"}),
            html.Div(
                f"mostrando {len(shown):,}".replace(",", ".") + (
                    f" de {len(anomalies):,}".replace(",", ".") + " (truncado)"
                    if truncated else ""
                ),
                style={"color": "#9aa0a6", "fontSize": "12.5px"},
            ),
        ],
    )
    table = _build_alerts_table(shown, time_fmt="%Y-%m-%d %H:%M:%S")

    return html.Div(children=[
        cards,
        dcc.Graph(figure=fig, config={"displayModeBar": False}),
        header,
        html.Div(
            table,
            style={
                "maxHeight": "420px",
                "overflowY": "auto",
                "backgroundColor": "#161B22",
                "border": "1px solid #22262E",
                "borderRadius": "6px",
                "padding": "8px 12px",
                "fontFamily": "JetBrains Mono, ui-monospace, monospace",
                "fontSize": "12.5px",
            },
        ),
    ])


def _stat_card(label: str, value: str) -> html.Div:
    return html.Div(
        style={
            "backgroundColor": "#161B22",
            "border": "1px solid #22262E",
            "borderRadius": "6px",
            "padding": "10px 12px",
        },
        children=[
            html.Div(label, style={"color": "#9aa0a6",
                                   "fontSize": "11.5px",
                                   "textTransform": "uppercase",
                                   "letterSpacing": "0.5px"}),
            html.Div(value, style={"fontSize": "15px",
                                   "marginTop": "4px",
                                   "fontWeight": 600}),
        ],
    )


# ---------------------------------------------------------------------------
# Helpers compartidos
# ---------------------------------------------------------------------------

def _style(fig: go.Figure, *, title: str, yaxis_title: str) -> None:
    fig.update_layout(
        title=dict(text=title, x=0.01, font=dict(color="#E6E6E6")),
        margin=dict(l=50, r=20, t=40, b=30),
        height=260,
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font=dict(color="#E6E6E6"),
        xaxis=dict(gridcolor="#22262E", zerolinecolor="#22262E",
                   title="t (segundos epoch)"),
        yaxis=dict(gridcolor="#22262E", zerolinecolor="#22262E",
                   title=yaxis_title),
        legend=dict(orientation="h", y=-0.25, x=0),
        showlegend=True,
    )


def _build_alerts_summary(alerts):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in alerts:
        if r.severity in counts:
            counts[r.severity] += 1
    chips = []
    for sev in ("HIGH", "MEDIUM", "LOW"):
        chips.append(html.Span(
            f"{sev}: {counts[sev]}",
            style={
                "backgroundColor": SEVERITY_COLORS[sev],
                "color": "#0E1117" if sev != "HIGH" else "#FFFFFF",
                "padding": "2px 8px",
                "borderRadius": "10px",
                "marginLeft": "6px",
                "fontWeight": 600,
            },
        ))
    chips.append(html.Span(
        f"  total: {len(alerts)}",
        style={"marginLeft": "10px", "color": "#9aa0a6"},
    ))
    return chips


def _build_alerts_table(alerts, time_fmt: str = "%H:%M:%S"):
    if not alerts:
        return html.Div(
            "sin alertas en la ventana — el detector está aprendiendo "
            "o el tráfico está limpio.",
            style={"color": "#9aa0a6", "padding": "8px 4px"},
        )
    header_style = {
        "position": "sticky", "top": "0",
        "backgroundColor": "#0E1117", "color": "#9aa0a6",
        "textAlign": "left", "padding": "6px 10px",
        "borderBottom": "1px solid #22262E", "fontWeight": 600,
    }
    cell_style = {
        "padding": "5px 10px",
        "borderBottom": "1px solid #1A1F26",
        "whiteSpace": "nowrap",
    }
    header = html.Tr(children=[
        html.Th("hora",      style=header_style),
        html.Th("severidad", style=header_style),
        html.Th("f(t)",      style={**header_style, "textAlign": "right"}),
        html.Th("f'(t)",     style={**header_style, "textAlign": "right"}),
        html.Th("f''(t)",    style={**header_style, "textAlign": "right"}),
    ])
    body_rows = []
    for r in alerts:
        when = time.strftime(time_fmt, time.localtime(r.timestamp))
        sev = r.severity or "—"
        color = SEVERITY_COLORS.get(sev, "#9aa0a6")
        body_rows.append(html.Tr(children=[
            html.Td(when, style=cell_style),
            html.Td(sev, style={**cell_style, "color": color, "fontWeight": 700}),
            html.Td(f"{r.f_t:.1f}",
                    style={**cell_style, "textAlign": "right"}),
            html.Td(f"{r.f_prime:.2f}",
                    style={**cell_style, "textAlign": "right"}),
            html.Td(f"{r.f_double_prime:.2f}",
                    style={**cell_style, "textAlign": "right"}),
        ]))
    return html.Table(
        style={"width": "100%", "borderCollapse": "collapse"},
        children=[html.Thead(header), html.Tbody(body_rows)],
    )


def _start_of_day_local(d_str: str) -> float:
    """Convierte 'YYYY-MM-DD' (zona local) a timestamp epoch en 00:00:00."""
    d = datetime.fromisoformat(d_str[:10])
    return datetime(d.year, d.month, d.day).timestamp()


def _end_of_day_local(d_str: str) -> float:
    """Convierte 'YYYY-MM-DD' (zona local) a timestamp epoch en 23:59:59.999."""
    d = datetime.fromisoformat(d_str[:10])
    return datetime(d.year, d.month, d.day, 23, 59, 59, 999_000).timestamp()


def _humanize_seconds(s: float) -> str:
    s = int(s)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60} s"
    if s < 86400:
        h, rem = divmod(s, 3600)
        return f"{h} h {rem // 60} min"
    d, rem = divmod(s, 86400)
    return f"{d} d {rem // 3600} h"


def _humanize_count(t_min: float, t_max: float) -> str:
    return _humanize_seconds(t_max - t_min) + " de cobertura"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_dashboard(
    logger: TrafficLogger,
    detector: AnomalyDetector,
    host: str = "127.0.0.1",
    port: int = 8050,
    debug: bool = False,
) -> None:
    """Llamada bloqueante — arranca el servidor HTTP de Dash."""
    app = build_app(logger, detector)
    runner = getattr(app, "run", None) or app.run_server
    runner(host=host, port=port, debug=debug)
