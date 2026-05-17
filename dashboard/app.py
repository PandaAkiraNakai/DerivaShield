"""
dashboard/app.py
================
Capa de visualización (Plotly Dash) con dos páginas:

  /          — Vista en vivo: 3 gráficos (f, f', f'') + panel de alertas
               de los últimos 5 minutos, refresco cada 1 s.

  /reporte   — Reporte histórico: rango de fechas o "reporte completo",
               con resumen, gráfico de f(t) marcando las anomalías, y
               tabla con todas las anomalías del rango. El botón
               "Generar reporte" además descarga un .xlsx con tres hojas
               (Resumen / Anomalías / Muestras).

Tema visual: morado sobrio para el chrome (paleta en dashboard/assets/
styles.css). Los gráficos conservan la paleta de la spec:
    Tráfico normal    #0066CC (azul)
    Anomalía          #CC0000 (rojo)
    Línea de umbral   #FFA500 (ámbar)
"""

from __future__ import annotations

import io
import time
from datetime import date, datetime
from typing import List, Optional

import dash
import pandas as pd
import plotly.graph_objs as go
from dash import Dash, Input, Output, State, callback_context, dcc, html, no_update

from detection.anomaly import AnomalyDetector
from storage.logger import LogRow, TrafficLogger


# --- Paleta de los plots (fijada por spec — NO tocar) ---
COLOR_NORMAL = "#0066CC"
COLOR_ANOMALY = "#CC0000"
COLOR_THRESHOLD = "#FFA500"

# --- Paleta del chrome (matched con assets/styles.css) ---
BG_MAIN     = "#1A1226"
BG_CARD     = "#251A37"
BORDER      = "#3A2D54"
TEXT_PRIM   = "#EDE5F5"
TEXT_DIM    = "#9F8FB8"
ACCENT      = "#8B5CF6"

# --- Parámetros operativos ---
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
            "backgroundColor": BG_MAIN,
            "color": TEXT_PRIM,
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
        "color": TEXT_PRIM,
        "textDecoration": "none",
        "padding": "6px 14px",
        "borderRadius": "4px",
        "marginLeft": "6px",
        "backgroundColor": BG_CARD,
        "border": f"1px solid {BORDER}",
        "fontSize": "13px",
    }
    return html.Div(
        style={
            "display": "flex",
            "alignItems": "center",
            "justifyContent": "space-between",
            "marginBottom": "20px",
            "padding": "12px 16px",
            "backgroundColor": BG_CARD,
            "border": f"1px solid {BORDER}",
            "borderRadius": "6px",
        },
        children=[
            html.Div(
                style={"display": "flex", "alignItems": "center", "gap": "14px"},
                children=[
                    html.Img(src=dash.get_asset_url("logo.png"),
                             style={"height": "40px", "width": "auto"}),
                    html.Div(
                        children=[
                            html.Div("DerivaShield",
                                     style={"fontSize": "20px",
                                            "fontWeight": 700,
                                            "letterSpacing": "0.3px"}),
                            html.Div("Detección diferencial de anomalías "
                                     "de tráfico",
                                     style={"fontSize": "12px",
                                            "color": TEXT_DIM,
                                            "marginTop": "1px"}),
                        ],
                    ),
                ],
            ),
            html.Nav(
                children=[
                    dcc.Link("Vivo",    href="/",
                             className="ds-nav-link", style=link_style),
                    dcc.Link("Reporte", href="/reporte",
                             className="ds-nav-link", style=link_style),
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
                 style={"color": TEXT_DIM, "marginBottom": "16px",
                        "fontSize": "13px"}),
        _alerts_panel_skeleton(),
        dcc.Graph(id="graph-f",   config={"displayModeBar": False}),
        dcc.Graph(id="graph-fp",  config={"displayModeBar": False}),
        dcc.Graph(id="graph-fpp", config={"displayModeBar": False}),
        dcc.Interval(id="tick", interval=REFRESH_MS, n_intervals=0),
    ])


def _alerts_panel_skeleton() -> html.Div:
    return html.Div(
        style={
            "backgroundColor": BG_CARD,
            "border": f"1px solid {BORDER}",
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
        dcc.Download(id="report-download"),
        html.Div(
            style={
                "backgroundColor": BG_CARD,
                "border": f"1px solid {BORDER}",
                "borderRadius": "6px",
                "padding": "16px 18px",
                "marginBottom": "20px",
            },
            children=[
                html.H3("Reporte histórico",
                        style={"margin": "0 0 8px 0", "fontSize": "16px"}),
                html.Div(helper, style={"color": TEXT_DIM,
                                        "fontSize": "12.5px",
                                        "marginBottom": "14px"}),
                html.Div(
                    style={"display": "flex", "gap": "16px",
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
                            options=[{"label": "  Reporte completo "
                                               "(ignorar fechas)",
                                      "value": "full"}],
                            value=[],
                            style={"color": TEXT_PRIM, "fontSize": "13px"},
                        ),
                        html.Button(
                            "Generar reporte y descargar Excel",
                            id="report-generate",
                            n_clicks=0,
                            className="ds-primary",
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
        Output("report-download", "data"),
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
                return (
                    html.Div(
                        "Elegí un rango de fechas o marcá "
                        "«Reporte completo».",
                        style={"color": TEXT_DIM, "padding": "8px"},
                    ),
                    no_update,
                )
            t_from = _start_of_day_local(start_date)
            t_to = _end_of_day_local(end_date)
            range_label = f"{start_date[:10]} → {end_date[:10]}"

        rows = logger.fetch_range(t_from=t_from, t_to=t_to)
        if not rows:
            return (
                html.Div(
                    f"Sin datos para «{range_label}».",
                    style={"color": TEXT_DIM, "padding": "12px",
                           "backgroundColor": BG_CARD,
                           "border": f"1px solid {BORDER}",
                           "borderRadius": "6px"},
                ),
                no_update,
            )

        rendered = _build_report(rows, range_label)

        # Descarga solo cuando el usuario realmente clickeó el botón
        # (evita disparar la descarga en el render inicial de la página).
        triggered = callback_context.triggered_id if callback_context.triggered else None
        if triggered == "report-generate" and (n_clicks or 0) > 0:
            xlsx_bytes = _build_excel(rows, range_label)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            slug = (range_label
                    .replace(" → ", "_to_")
                    .replace(" ", "-")
                    .replace("(", "").replace(")", ""))
            filename = f"derivashield-{slug}-{stamp}.xlsx"
            download = dcc.send_bytes(lambda buf: buf.write(xlsx_bytes),
                                      filename=filename)
            return rendered, download
        return rendered, no_update


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

    # Gráfico f(t)
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
                                             gridcolor=BORDER,
                                             zerolinecolor=BORDER))

    # Tabla de anomalías (truncada a REPORT_TABLE_LIMIT)
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
                    f" de {len(anomalies):,}".replace(",", ".") + " (truncado — "
                    "el Excel contiene todas)"
                    if truncated else ""
                ),
                style={"color": TEXT_DIM, "fontSize": "12.5px"},
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
                "backgroundColor": BG_CARD,
                "border": f"1px solid {BORDER}",
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
            "backgroundColor": BG_CARD,
            "border": f"1px solid {BORDER}",
            "borderRadius": "6px",
            "padding": "10px 12px",
        },
        children=[
            html.Div(label, style={"color": TEXT_DIM,
                                   "fontSize": "11.5px",
                                   "textTransform": "uppercase",
                                   "letterSpacing": "0.5px"}),
            html.Div(value, style={"fontSize": "15px",
                                   "marginTop": "4px",
                                   "fontWeight": 600}),
        ],
    )


# ---------------------------------------------------------------------------
# Export a Excel
# ---------------------------------------------------------------------------

def _build_excel(rows: List[LogRow], range_label: str) -> bytes:
    anomalies = [r for r in rows if r.is_anomaly]
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in anomalies:
        if r.severity in counts:
            counts[r.severity] += 1

    first_ts = rows[0].timestamp
    last_ts = rows[-1].timestamp

    df_summary = pd.DataFrame({
        "Métrica": [
            "Rango",
            "Desde",
            "Hasta",
            "Duración",
            "Total muestras",
            "Total anomalías",
            "Tasa de anomalía",
            "Severidad HIGH",
            "Severidad MEDIUM",
            "Severidad LOW",
        ],
        "Valor": [
            range_label,
            datetime.fromtimestamp(first_ts).strftime("%Y-%m-%d %H:%M:%S"),
            datetime.fromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M:%S"),
            _humanize_seconds(max(1.0, last_ts - first_ts)),
            len(rows),
            len(anomalies),
            (f"{(len(anomalies) / len(rows) * 100):.2f}%"
             if rows else "0.00%"),
            counts["HIGH"],
            counts["MEDIUM"],
            counts["LOW"],
        ],
    })

    def _to_df(rs: List[LogRow]) -> pd.DataFrame:
        return pd.DataFrame([{
            "timestamp": datetime.fromtimestamp(r.timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"),
            "epoch": r.timestamp,
            "f(t)": r.f_t,
            "f'(t)": r.f_prime,
            "f''(t)": r.f_double_prime,
            "is_anomaly": int(r.is_anomaly),
            "severity": r.severity or "",
            "tier": r.tier,
        } for r in rs])

    df_anom = _to_df(sorted(anomalies, key=lambda r: r.timestamp))
    df_all = _to_df(rows)

    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as w:
        df_summary.to_excel(w, sheet_name="Resumen", index=False)
        if not df_anom.empty:
            df_anom.to_excel(w, sheet_name="Anomalías", index=False)
        df_all.to_excel(w, sheet_name="Muestras", index=False)
        # Anchuras razonables.
        for sheet_name, df in (("Resumen", df_summary),
                               ("Anomalías", df_anom),
                               ("Muestras", df_all)):
            if df.empty:
                continue
            ws = w.sheets[sheet_name]
            for i, col in enumerate(df.columns, start=1):
                col_letter = ws.cell(row=1, column=i).column_letter
                max_len = max(
                    [len(str(col))] +
                    [len(str(v)) for v in df[col].head(200)]
                )
                ws.column_dimensions[col_letter].width = min(40, max_len + 2)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Helpers compartidos
# ---------------------------------------------------------------------------

def _style(fig: go.Figure, *, title: str, yaxis_title: str) -> None:
    fig.update_layout(
        title=dict(text=title, x=0.01, font=dict(color=TEXT_PRIM)),
        margin=dict(l=50, r=20, t=40, b=30),
        height=260,
        paper_bgcolor=BG_MAIN,
        plot_bgcolor=BG_MAIN,
        font=dict(color=TEXT_PRIM),
        xaxis=dict(gridcolor=BORDER, zerolinecolor=BORDER,
                   title="t (segundos epoch)"),
        yaxis=dict(gridcolor=BORDER, zerolinecolor=BORDER,
                   title=yaxis_title),
        legend=dict(orientation="h", y=-0.25, x=0,
                    font=dict(color=TEXT_PRIM)),
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
                "color": "#FFFFFF" if sev == "HIGH" else BG_MAIN,
                "padding": "2px 8px",
                "borderRadius": "10px",
                "marginLeft": "6px",
                "fontWeight": 600,
            },
        ))
    chips.append(html.Span(
        f"  total: {len(alerts)}",
        style={"marginLeft": "10px", "color": TEXT_DIM},
    ))
    return chips


def _build_alerts_table(alerts, time_fmt: str = "%H:%M:%S"):
    if not alerts:
        return html.Div(
            "sin alertas en la ventana — el detector está aprendiendo "
            "o el tráfico está limpio.",
            style={"color": TEXT_DIM, "padding": "8px 4px"},
        )
    header_style = {
        "position": "sticky", "top": "0",
        "backgroundColor": BG_MAIN, "color": TEXT_DIM,
        "textAlign": "left", "padding": "6px 10px",
        "borderBottom": f"1px solid {BORDER}", "fontWeight": 600,
    }
    cell_style = {
        "padding": "5px 10px",
        "borderBottom": "1px solid #2A2040",
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
        color = SEVERITY_COLORS.get(sev, TEXT_DIM)
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
    d = datetime.fromisoformat(d_str[:10])
    return datetime(d.year, d.month, d.day).timestamp()


def _end_of_day_local(d_str: str) -> float:
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
