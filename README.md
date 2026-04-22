# ZKTeco Sync

A self-hosted LAN appliance that replaces ZKTeco BioCloud. It collects attendance from ZKTeco biometric devices over your local network and exposes a clean web UI and REST API — no cloud dependency, no per-device license.

## How it works

ZKTeco devices speak two protocols simultaneously:

| Protocol | Direction | Port | Used for |
|----------|-----------|------|----------|
| **ADMS** (HTTP push) | Device → Server | 80/443 | Real-time attendance push |
| **SDK** (TCP pull) | Server → Device | 4370 | Employee sync, template pull, device control |

This app runs both listeners. Devices push attendance events the moment they happen; the SDK poller lets you pull historical records, employees, and fingerprint templates on demand.

## Features

- **Real-time attendance** via ADMS push from devices
- **On-demand sync** — pull employees, attendance, and fingerprint templates from any device
- **Employee management** — view all employees, push to specific devices, remove from devices
- **Fingerprint templates** — pull from one device, push to others (one master copy per finger)
- **Live enrollment** — trigger fingerprint enrollment on a device from the UI
- **Device control** — unlock door, set clock, write LCD message, restart, queue raw commands
- **HRM integration** — push attendance records to a third-party HRM on a configurable interval, with last-synced-ID tracking and a manual trigger
- **Multi-database** — MariaDB, MySQL, PostgreSQL, or MSSQL (including Windows Authentication)
- **JWT-secured API** — all endpoints require a bearer token; credentials set via `.env`

## Requirements

- Python 3.11+
- Node 18+ (for frontend build)
- One of: MariaDB/MySQL, PostgreSQL, or MSSQL

## Setup

### Prerequisites

- Python 3.11+
- Node 18+ with npm
- `uv` — `pip install uv`
- One of: MariaDB/MySQL, PostgreSQL, or MSSQL

### Guided installer (recommended)

The installer handles everything interactively — configuration, dependencies, frontend build, and optional service registration.

```bash
git clone <repo-url>
cd zkteco-sync
python install.py
```

The installer will:
1. Prompt for database credentials, bind address, port, and admin credentials
2. Write `.env` with an auto-generated secret key
3. Install Python and Node dependencies
4. Test the database connection
5. Build the frontend
6. Optionally register a **systemd** service (Linux) or **NSSM Windows service** (Windows) so the app starts on boot and restarts on crash

If a `.env` already exists it will ask before overwriting.

### Manual setup

If you prefer to set things up yourself:

```bash
git clone <repo-url>
cd zkteco-sync
cp .env.example .env
```

Edit `.env`:

```env
API_USERNAME=admin
API_PASSWORD=your-password
SECRET_KEY=<python -c "import secrets; print(secrets.token_hex(32))">

DB_ENGINE=mariadb        # mariadb | mysql | postgresql | mssql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=zkteco_sync
DB_USER=root
DB_PASSWORD=
```

```bash
uv sync
npm install --prefix frontend
npm run build --prefix frontend
python run.py
```

The web UI is served at `http://<server-ip>:8000`. Database tables are created automatically on first run.

## Pointing devices at this server

On each ZKTeco device, set the ADMS / Cloud Server address to:

```
http://<server-ip>:8000
```

The device will begin pushing attendance records immediately. No further configuration is needed on the device side.

## HRM Integration

Go to **Settings → HRM Sync** in the UI to configure:

- **Endpoint** — the URL your HRM accepts attendance pushes at
- **Secret** — the API key sent with each push
- **Location ID** — identifier passed with every record
- **Interval** — how often to push (in seconds)
- **Timezone** — used to denote the timestamps pushed are in this timezone. The machine does not inform this
- **Last Synced ID** — editable; lower it to re-push records, raise it to skip

Records are batched in groups of 10,000. On failure, state is preserved so the next run resumes from where it left off.

## Development

Run backend and frontend separately with hot reload:

```bash
# Backend
uv run uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
npm run dev --prefix frontend
```

The Vite dev server proxies `/api` to `http://localhost:8000` automatically.

## Acknowledgements

SDK device communication is powered by [pyzk](https://github.com/fananimi/pyzk), an open-source Python library for ZKTeco/ZKSoftware attendance machines. Many thanks to the pyzk community for making the SDK layer possible.

## Compatible devices

The following devices have been confirmed working by the pyzk community:

| Device | Platform | Firmware |
|--------|----------|----------|
| U580 | ZEM500 | Ver 6.21 |
| T4-C | ZEM510_TFT | Ver 6.60 |
| iClock260 | ZEM600_TFT | Ver 6.60 |
| iFace402/ID | ZEM800_TFT | Ver 6.60 |
| MA300 | ZEM560 | Ver 6.60 |
| iFace800/ID | ZEM600_TFT | Ver 6.60 |
| K20 | JZ4725_TFT | Ver 6.60 |
| VF680 | ZEM600_TFT | Ver 6.60 |
| RSP10k1 | ZLM30_TFT | Ver 6.70 |
| K14 | JZ4725_TFT | Ver 6.60 |
| iFace702 | ZMM220_TFT | Ver 6.60 |
| F18/ID | ZMM210_TFT | Ver 6.60 |
| K40/ID | JZ4725_TFT | Ver 6.60 |
| iClock3000/ID | ZMM200_TFT | Ver 6.60 |
| iClock880-H/ID | ZEM600_TFT | Ver 6.70 |

Any device running firmware Ver 6.x on a compatible platform should work. If you test a device not listed here, please open an issue so it can be added.

## Project structure

```
app/
  main.py           # FastAPI app, lifespan, HRM scheduler
  models.py         # SQLAlchemy models
  database.py       # DB engine, UTCDateTime type decorator
  schemas.py        # Pydantic request/response schemas
  deps.py           # Auth dependency (require_auth)
  routers/
    auth.py         # Login, password verify
    devices.py      # Device CRUD and all SDK actions
    employees.py    # Employee read, device/template queries
    attendance.py   # Attendance list with filters
    adms.py         # ADMS push endpoints (device-initiated)
    hrm_sync.py     # HRM config, status, manual trigger
  services/
    poller.py       # SDK pull logic (employees, attendance, templates)
    hrm_sync.py     # HRM push logic and batch loop
frontend/
  src/
    pages/          # Devices, Employees, Attendance, Settings
    api.js          # All API calls in one place
```
