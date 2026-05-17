#!/usr/bin/env bash
# check.sh — smoke test de DerivaShield
#
# Verifica que la app esté instalada y funcione end-to-end:
#   1. venv + dependencias importables
#   2. módulos internos importables
#   3. pipeline headless con tráfico simulado por ~50s contra una DB temporal
#   4. SQLite recibió muestras y al menos una anomalía (el dataset sintético
#      mete un spike DDoS entre 30-40s, así que con 50s sobra)
#   5. opcional: levanta el dashboard, hace HEAD, lo mata  (--with-dashboard)
#
# Uso:
#   ./check.sh                    # smoke test rápido (headless, ~55s)
#   ./check.sh --with-dashboard   # incluye chequeo HTTP del dashboard
#   ./check.sh --duration 90      # corre el headless por 90s en vez de 50
#   ./check.sh --keep             # no borra la DB temporal al terminar

set -u

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# ---------- args ----------
DURATION=50
WITH_DASHBOARD=0
KEEP_DB=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-dashboard) WITH_DASHBOARD=1; shift ;;
        --duration)       DURATION="$2"; shift 2 ;;
        --keep)           KEEP_DB=1; shift ;;
        -h|--help)
            sed -n '2,16p' "$0"; exit 0 ;;
        *)
            echo "argumento desconocido: $1" >&2; exit 2 ;;
    esac
done

# ---------- colores ----------
if [[ -t 1 ]]; then
    R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[36m'; D=$'\033[0m'
else
    R=""; G=""; Y=""; B=""; D=""
fi

pass() { printf "  %sOK%s   %s\n" "$G" "$D" "$1"; }
fail() { printf "  %sFAIL%s %s\n" "$R" "$D" "$1"; FAILS=$((FAILS+1)); }
info() { printf "%s>>%s %s\n"     "$B" "$D" "$1"; }

FAILS=0

# ---------- 1. venv ----------
info "1/5  venv y python"
if [[ ! -x .venv/bin/python ]]; then
    fail ".venv/bin/python no existe — crea el venv:"
    echo "        python -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi
PYBIN="$PROJECT_DIR/.venv/bin/python"
PYVER="$("$PYBIN" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
pass "python $PYVER en .venv"

# ---------- 2. dependencias ----------
info "2/5  dependencias (scapy, numpy, scipy, dash, plotly, pandas)"
DEP_OUT="$("$PYBIN" - <<'PY' 2>&1
import importlib, sys
mods = ["scapy", "numpy", "scipy", "dash", "plotly", "pandas"]
missing = []
for m in mods:
    try:
        importlib.import_module(m)
    except Exception as e:
        missing.append(f"{m}: {e}")
if missing:
    print("\n".join(missing))
    sys.exit(1)
PY
)"
if [[ $? -eq 0 ]]; then
    pass "todas las dependencias importables"
else
    fail "dependencias faltantes:"; echo "$DEP_OUT" | sed 's/^/        /'
    exit 1
fi

# ---------- 3. módulos internos ----------
info "3/5  módulos internos"
MOD_OUT="$("$PYBIN" - <<'PY' 2>&1
from analysis.derivatives import compute_derivatives
from capture.sniffer       import Sniffer, build_default_sniffer
from detection.anomaly     import AnomalyDetector, AnomalyEvent
from storage.logger        import TrafficLogger, LogRow
from dashboard.app         import run_dashboard
print("ok")
PY
)"
if [[ "$MOD_OUT" == "ok" ]]; then
    pass "main / capture / analysis / detection / storage / dashboard"
else
    fail "import roto:"; echo "$MOD_OUT" | sed 's/^/        /'
    exit 1
fi

# ---------- 4. pipeline headless ----------
TMP_DB="$(mktemp -t derivashield_smoke.XXXXXX.db)"
TMP_LOG="$(mktemp -t derivashield_smoke.XXXXXX.log)"
cleanup() {
    if [[ -n "${PIPE_PID:-}" ]] && kill -0 "$PIPE_PID" 2>/dev/null; then
        kill -TERM "$PIPE_PID" 2>/dev/null
        wait "$PIPE_PID" 2>/dev/null
    fi
    if [[ -n "${DASH_PID:-}" ]] && kill -0 "$DASH_PID" 2>/dev/null; then
        kill -TERM "$DASH_PID" 2>/dev/null
        wait "$DASH_PID" 2>/dev/null
    fi
    if [[ $KEEP_DB -eq 0 ]]; then
        rm -f "$TMP_DB" "${TMP_DB}-shm" "${TMP_DB}-wal" "$TMP_LOG"
    else
        echo "  (DB conservada en $TMP_DB; log en $TMP_LOG)"
    fi
}
trap cleanup EXIT

info "4/5  pipeline headless con tráfico simulado (${DURATION}s)"
"$PYBIN" main.py --no-dashboard --db "$TMP_DB" >"$TMP_LOG" 2>&1 &
PIPE_PID=$!

# muestra progreso cada 10s para que no parezca colgado
for ((s=0; s<DURATION; s+=10)); do
    sleep 10
    if ! kill -0 "$PIPE_PID" 2>/dev/null; then
        fail "el pipeline murió antes de tiempo. Últimas líneas del log:"
        tail -n 20 "$TMP_LOG" | sed 's/^/        /'
        exit 1
    fi
    printf "       %ds...\n" $((s+10))
done

kill -TERM "$PIPE_PID" 2>/dev/null
wait "$PIPE_PID" 2>/dev/null
PIPE_PID=""

if ! grep -q "\[DerivaShield\] modo=" "$TMP_LOG"; then
    fail "no apareció la línea de arranque '[DerivaShield] modo=...'"
    tail -n 20 "$TMP_LOG" | sed 's/^/        /'
else
    MODE_LINE="$(grep "\[DerivaShield\] modo=" "$TMP_LOG" | head -1)"
    pass "arrancó: $MODE_LINE"
fi

# ---------- chequeo SQLite ----------
read -r N_ROWS N_ANOM SEVERITIES <<<"$("$PYBIN" - "$TMP_DB" <<'PY'
import sqlite3, sys
db = sys.argv[1]
con = sqlite3.connect(db)
cur = con.cursor()
n_rows = cur.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
n_anom = cur.execute("SELECT COUNT(*) FROM traffic_logs WHERE is_anomaly=1").fetchone()[0]
sev = cur.execute(
    "SELECT severity, COUNT(*) FROM traffic_logs WHERE is_anomaly=1 GROUP BY severity"
).fetchall()
sev_str = ",".join(f"{s or 'NULL'}:{c}" for s, c in sev) or "-"
print(n_rows, n_anom, sev_str)
PY
)"

if [[ -z "${N_ROWS:-}" ]]; then
    fail "no se pudo leer la DB $TMP_DB"
else
    if [[ "$N_ROWS" -gt 20 ]]; then
        pass "muestras persistidas en SQLite: $N_ROWS filas en traffic_logs"
    else
        fail "solo $N_ROWS filas en traffic_logs (esperaba >20)"
    fi
    if [[ "$N_ANOM" -gt 0 ]]; then
        pass "anomalías detectadas: $N_ANOM ($SEVERITIES)"
    else
        fail "0 anomalías detectadas — el dataset sintético debería disparar al menos el DDoS"
        tail -n 30 "$TMP_LOG" | sed 's/^/        /'
    fi
fi

# ---------- 5. dashboard opcional ----------
if [[ $WITH_DASHBOARD -eq 1 ]]; then
    info "5/5  dashboard HTTP (puerto 18050, ~6s)"
    "$PYBIN" main.py --port 18050 --db "$TMP_DB" >>"$TMP_LOG" 2>&1 &
    DASH_PID=$!
    sleep 6
    if ! kill -0 "$DASH_PID" 2>/dev/null; then
        fail "el proceso del dashboard murió. Últimas líneas:"
        tail -n 20 "$TMP_LOG" | sed 's/^/        /'
    else
        HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:18050/ || echo 000)"
        if [[ "$HTTP_CODE" =~ ^2 ]]; then
            pass "dashboard respondió HTTP $HTTP_CODE en /"
        else
            fail "dashboard respondió HTTP $HTTP_CODE (esperaba 2xx)"
        fi
        kill -TERM "$DASH_PID" 2>/dev/null
        wait "$DASH_PID" 2>/dev/null
        DASH_PID=""
    fi
else
    info "5/5  dashboard — saltado (usá --with-dashboard para incluirlo)"
fi

echo
if [[ $FAILS -eq 0 ]]; then
    printf "%sTODO OK%s — DerivaShield funciona.\n" "$G" "$D"
    exit 0
else
    printf "%s%d chequeo(s) fallaron%s\n" "$R" "$FAILS" "$D"
    exit 1
fi
