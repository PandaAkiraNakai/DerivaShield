# DerivaShield

Detector de anomalías de red basado en cálculo diferencial. Trata el
conteo de paquetes por segundo como una señal discreta `f(t)`, la
deriva numéricamente dos veces y marca los momentos en los que el
tráfico **a la vez** sube rápido y acelera:

```
ANOMALÍA  ⇔  f'(t) > μ + k·σ   AND   f''(t) > 0
```

- `f(t)`  — paquetes por segundo
- `f'(t)` — tasa de cambio (velocidad)
- `f''(t)` — aceleración (concavidad)
- `μ`, `σ` — media y desviación estándar corrientes de `f'(t)` sobre un
  baseline limpio
- `k` — factor de sensibilidad (default `2.0`)

Un DDoS o un port-scan reales se ven como un punto de inflexión en la
curva de tráfico, no solo como un valor alto. Exigir las dos condiciones
juntas reduce los falsos positivos del tráfico naturalmente bursty.

## Estructura del proyecto

```
derivashield/
├── main.py                 # punto de entrada CLI — cablea todo
├── capture/
│   └── sniffer.py          # captura live (Scapy), replay PCAP, fallback simulado
├── analysis/
│   └── derivatives.py      # f'(t), f''(t) con numpy.gradient
├── detection/
│   └── anomaly.py          # regla μ + k·σ + concavidad, niveles de severidad
├── storage/
│   └── logger.py           # SQLite + retención HOT/WARM/COLD
├── dashboard/
│   └── app.py              # vista en vivo de 3 gráficos en Plotly Dash
└── requirements.txt
```

## Instalación

Requiere Python 3.11.

```bash
cd DerivaShield
python -m venv .venv
source .venv/bin/activate           # fish: source .venv/bin/activate.fish
pip install -r requirements.txt
```

### Privilegios para captura en vivo

Scapy necesita acceso a raw sockets para capturar en vivo. Dos opciones:

```bash
# Opción A — correr como root (lo más simple, sirve para laboratorio)
sudo .venv/bin/python main.py --live

# Opción B — darle capabilities al python del venv una sola vez (sin sudo después)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)
.venv/bin/python main.py --live
```

Si ninguna funciona, DerivaShield cae automáticamente a su dataset
sintético — útil para demos y para desarrollar en máquinas donde no
puedes darle raw-socket caps a Python.

## Uso

```bash
# Tráfico simulado (default — no necesita privilegios)
python main.py

# Captura en vivo en la interfaz por defecto
sudo python main.py --live

# Captura en vivo en una interfaz específica
sudo python main.py --live --iface wlan0

# Reproducir un archivo PCAP
python main.py --file traffic.pcap

# Detección más / menos sensible
python main.py --k 1.5         # más sensible (más alertas)
python main.py --k 3.0         # menos sensible (solo excursiones grandes)

# Puerto del dashboard personalizado
python main.py --port 9000

# Headless (sin dashboard) — solo análisis + logging
python main.py --no-dashboard
```

Una vez que el dashboard está corriendo, abre <http://127.0.0.1:8050>
en un navegador.

## Dataset simulado

Cuando no hay fuente en vivo disponible (o `--live` es denegado), el
sniffer emite un stream sintético:

| Ventana de tiempo | Comportamiento |
|-------------------|----------------|
| 0 – 30 s          | Baseline ~100 pkts/s + ruido gaussiano |
| 30 – 40 s         | Spike DDoS (ráfaga gaussiana hasta ~800 pkts/s) |
| 60 – 90 s         | Rampa de port-scan (lineal, 100 → 400 pkts/s) |

Los dos ataques deberían disparar alertas por el umbral de `f'(t)`; el
DDoS sale como severidad HIGH, el port-scan típicamente LOW–MEDIUM.

## Dashboard

Tres gráficos en vivo, todos compartiendo el mismo eje temporal:

1. **f(t)** — tráfico en paquetes/s. Marcadores `x` rojos = anomalías.
2. **f'(t)** — tasa de cambio, con línea ámbar punteada de `μ + k·σ`.
3. **f''(t)** — aceleración, con referencia punteada en cero.

Intervalo de refresco: 1 segundo. Ventana: últimos 60 segundos.

La paleta de colores está fijada por especificación:

| Elemento            | Color |
|---------------------|-------|
| Traza normal        | `#0066CC` (azul) |
| Marcador de anomalía| `#CC0000` (rojo) |
| Línea de umbral     | `#FFA500` (ámbar) |

## Logging y retención

Cada muestra por segundo se escribe en `derivashield.db` (puede sobrescribirse
con `--db`). La política de retención corre una vez por hora:

| Nivel | Ventana de edad | Resolución |
|-------|-----------------|-----------|
| HOT   | ≤ 24 h          | 1 fila / segundo (crudo) |
| WARM  | 1 – 7 días      | 1 fila / minuto (promedio) |
| COLD  | 7 – 30 d        | 1 fila / hora (promedio) |
| —     | > 30 días       | borrado |

La agregación preserva la peor severidad observada en cada bucket y
hace OR del flag `is_anomaly`.

## Alertas por consola

Cada anomalía detectada también imprime una línea coloreada en stdout:

```
[HIGH] 2026-05-17 12:42:18 f(t)=812.0  f'(t)=412.55  f''(t)=58.10  (umbral=44.20, μ=2.1, σ=21.0)
```

Niveles de severidad:

- `LOW`    — `f'(t)` entre `μ + k·σ` y `μ + 2k·σ`
- `MEDIUM` — entre `μ + 2k·σ` y `μ + 4k·σ`
- `HIGH`   — por encima de `μ + 4k·σ`

## La matemática, en breve

Se usa `numpy.gradient` para las dos derivadas. Aplica un esquema de
diferencia central en los puntos interiores (precisión `O(Δt²)`) y una
diferencia unilateral en los extremos — coincide con las formas
clásicas del libro:

```
f'(t)  ≈  ( f(t + Δt) - f(t - Δt) ) / (2Δt)     (interior)
f'(t)  ≈  ( f(t + Δt) - f(t)      ) / Δt        (extremo izquierdo)
f''(t) =  d/dt [ f'(t) ]                         (aplicado recursivamente)
```

`f(t)` se suaviza ligeramente (media móvil de 3 muestras, con padding
por reflexión) antes de derivar, así el jitter por segundo no domina
sobre `f'(t)`.

## Solución de problemas

- **`PermissionError` / `Operation not permitted` con `--live`** — dale
  `cap_net_raw` a tu Python (ver Instalación) o corre con `sudo`.
- **No se detectan anomalías** — la ventana de bootstrap (los primeros
  ~10 s) no marca nada mientras μ/σ se aprenden. Espera o vuelve a
  arrancar.
- **El dashboard no muestra nada** — verifica que el thread de análisis
  esté escribiendo a la misma base de datos que lee el dashboard (`--db`).
- **Puerto 8050 ocupado** — elige otro con `--port`.
