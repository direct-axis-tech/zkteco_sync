#!/usr/bin/env python3
"""ZKTeco Sync — installation script."""

import getpass
import os
import platform
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

# ── Platform ──────────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

if IS_WINDOWS:
    os.system("")  # enable ANSI escape codes in Windows Terminal / modern cmd

# ── Colors ────────────────────────────────────────────────────────────────────
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE   = "\033[0;34m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
NC     = "\033[0m"

# ── UI helpers ────────────────────────────────────────────────────────────────
def header(msg):  print(f"\n{BOLD}{BLUE}▶  {msg}{NC}")
def success(msg): print(f"   {GREEN}✓{NC}  {msg}")
def warn(msg):    print(f"   {YELLOW}!{NC}  {msg}")
def info(msg):    print(f"   {DIM}    {msg}{NC}")

def die(msg):
    print(f"\n   {RED}✗  {msg}{NC}\n")
    sys.exit(1)

def ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    val = input(f"   {prompt}{suffix}: ").strip()
    return val if val else default

def ask_secret(prompt):
    return getpass.getpass(f"   {prompt}: ")

def ask_yn(prompt, default="y"):
    suffix = "[Y/n]" if default == "y" else "[y/N]"
    val = input(f"   {prompt} {suffix}: ").strip().lower()
    return val in ("", "y", "yes") if default == "y" else val in ("y", "yes")

def run(args, cwd=None):
    """Stream command output to terminal. Dies on failure."""
    cmd = " ".join(str(a) for a in args) if IS_WINDOWS else args
    result = subprocess.run(cmd, shell=IS_WINDOWS, cwd=cwd)
    if result.returncode != 0:
        die(f"Command failed: {' '.join(str(a) for a in args)}")

def run_capture(args, cwd=None):
    """Run command, return (stdout, stderr, success)."""
    cmd = " ".join(str(a) for a in args) if IS_WINDOWS else args
    result = subprocess.run(
        cmd, shell=IS_WINDOWS, cwd=cwd, capture_output=True, text=True
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode == 0

# ── Project root ──────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.resolve()
if not (ROOT / "pyproject.toml").exists() or not (ROOT / "frontend").exists():
    die("Run this script from the project root directory.")

# ─────────────────────────────────────────────────────────────────────────────
print()
print(f"{BOLD}  ZKTeco Sync — Installation{NC}")
print(f"  {DIM}Self-hosted ZKTeco attendance sync appliance{NC}")
print()

# ── Prerequisites ─────────────────────────────────────────────────────────────
header("Checking prerequisites")

if sys.version_info < (3, 11):
    die(f"Python 3.11+ required. Found {sys.version_info.major}.{sys.version_info.minor}")
success(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

def check_tool(cmd, label=None):
    label = label or cmd
    if not shutil.which(cmd):
        die(f"{label} is required but not installed.")
    out, _, _ = run_capture([cmd, "--version"])
    success(f"{label}  {out.splitlines()[0]}")

check_tool("uv",   "uv")
check_tool("node", "Node.js")
check_tool("npm",  "npm")

# ── Configuration ─────────────────────────────────────────────────────────────
env_file  = ROOT / ".env"
configure = True

if env_file.exists():
    header("Existing configuration found")
    warn(".env already exists.")
    if not ask_yn("Reconfigure?", default="n"):
        configure = False
        success("Keeping existing .env")

if configure:
    header("App settings")
    app_host = ask("Bind address", "0.0.0.0")
    app_port = ask("Port",         "8000")

    header("Database")
    print()
    info("Supported engines:  mariadb   mysql   postgresql   mssql")
    print()

    default_ports = {
        "mariadb": "3306", "mysql": "3306",
        "postgresql": "5432", "mssql": "1433",
    }
    while True:
        db_engine = ask("Engine", "mariadb")
        if db_engine in default_ports:
            break
        warn(f"Invalid engine '{db_engine}'. Choose: mariadb, mysql, postgresql, mssql")

    db_host = ask("Host",     "127.0.0.1")
    db_port = ask("Port",     default_ports[db_engine])
    db_name = ask("Database", "zkteco_sync")

    if db_engine == "mssql":
        print()
        info("Leave username and password empty to use Windows Authentication.")
        print()
        db_user     = ask("Username (empty = Windows Auth)", "")
        db_password = ask_secret("Password (empty = Windows Auth)")
        print()
        db_odbc = ask("ODBC Driver", "ODBC Driver 17 for SQL Server")
    else:
        db_user     = ask("Username", "root")
        db_password = ask_secret("Password")
        db_odbc     = "ODBC Driver 17 for SQL Server"

    header("Admin credentials")
    api_username = ask("Username", "admin")

    while True:
        api_password = ask_secret("Password")
        if not api_password:
            warn("Password cannot be empty.")
            continue
        if api_password == ask_secret("Confirm password"):
            break
        warn("Passwords do not match. Try again.")

    secret_key = secrets.token_hex(32)

    header("Writing .env")
    env_file.write_text(
        f"APP_HOST={app_host}\n"
        f"APP_PORT={app_port}\n"
        f"APP_ENV=production\n"
        f"\n"
        f"API_USERNAME={api_username}\n"
        f"API_PASSWORD={api_password}\n"
        f"SECRET_KEY={secret_key}\n"
        f"\n"
        f"DB_ENGINE={db_engine}\n"
        f"DB_HOST={db_host}\n"
        f"DB_PORT={db_port}\n"
        f"DB_NAME={db_name}\n"
        f"DB_USER={db_user}\n"
        f"DB_PASSWORD={db_password}\n"
        f"DB_ODBC_DRIVER={db_odbc}\n"
    )
    success(".env written")
    info("SECRET_KEY was auto-generated.")

# ── Python dependencies ───────────────────────────────────────────────────────
header("Installing Python dependencies")
run(["uv", "sync"], cwd=ROOT)
success("Python dependencies installed")

# ── Test database connection ──────────────────────────────────────────────────
header("Testing database connection")

db_test = "from app.database import engine; engine.connect().close(); print('ok')"
_, err, ok = run_capture(["uv", "run", "python", "-c", db_test], cwd=ROOT)

if ok:
    success("Database connection successful")
else:
    last_err = next(
        (l for l in reversed(err.splitlines()) if l.strip()), err
    )
    warn(f"Connection failed: {last_err}")
    warn(f"Check credentials in .env and ensure the '{db_name if configure else '?'}' database exists.")
    if not ask_yn("Continue anyway?", default="n"):
        die("Aborted. Fix the database connection and re-run.")

# ── Frontend ──────────────────────────────────────────────────────────────────
header("Installing frontend dependencies")
run(["npm", "install", "--prefix", "frontend", "--silent"], cwd=ROOT)
success("Node modules installed")

header("Building frontend")
run(["npm", "run", "build", "--prefix", "frontend"], cwd=ROOT)
success("Frontend built  →  frontend/dist/")

# ── Service setup ─────────────────────────────────────────────────────────────
header("Background service")

if IS_WINDOWS:
    nssm = shutil.which("nssm")
    if not nssm:
        warn("NSSM not found in PATH.")
        info("Download NSSM from nssm.cc, add nssm.exe to your PATH,")
        info("then re-run this installer to set up the background service.")
    else:
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False

        if not is_admin:
            warn("Administrator privileges required to install a Windows service.")
            info("Re-run this script as Administrator to set up the service.")
        elif ask_yn("Install as a Windows service (runs on boot, restarts on crash)?", "y"):
            uv_path = shutil.which("uv")
            log_dir = ROOT / "logs"
            log_dir.mkdir(exist_ok=True)
            svc = "zkteco-sync"

            for args in [
                [nssm, "install",  svc, uv_path, "run", "python", "run.py"],
                [nssm, "set", svc, "AppDirectory",   str(ROOT)],
                [nssm, "set", svc, "AppStdout",      str(log_dir / "stdout.log")],
                [nssm, "set", svc, "AppStderr",      str(log_dir / "stderr.log")],
                [nssm, "set", svc, "AppRotateFiles",  "1"],
                [nssm, "set", svc, "AppRotateBytes",  "10485760"],  # rotate at 10 MB
                [nssm, "set", svc, "AppRotateOnline", "1"],         # rotate while running
                [nssm, "set", svc, "Start",           "SERVICE_AUTO_START"],
                [nssm, "start", svc],
            ]:
                run(args)

            success(f"Service '{svc}' installed and started")
            info(f"Logs  →  {log_dir}")
            info(f"nssm start   {svc}")
            info(f"nssm stop    {svc}")
            info(f"nssm restart {svc}")
            info(f"nssm status  {svc}")

elif IS_LINUX and shutil.which("systemctl"):
    if ask_yn("Install as a systemd service (runs on boot, restarts on crash)?", "y"):
        uv_path  = shutil.which("uv")
        svc_name = "zkteco-sync"
        svc_file = Path(f"/etc/systemd/system/{svc_name}.service")
        svc_body = (
            f"[Unit]\n"
            f"Description=ZKTeco Sync\n"
            f"After=network.target\n\n"
            f"[Service]\n"
            f"Type=simple\n"
            f"User={os.getenv('USER', 'root')}\n"
            f"WorkingDirectory={ROOT}\n"
            f"ExecStart={uv_path} run python run.py\n"
            f"Restart=always\n"
            f"RestartSec=5\n"
            f"SyslogIdentifier={svc_name}\n\n"
            f"[Install]\n"
            f"WantedBy=multi-user.target\n"
        )
        subprocess.run(
            ["sudo", "tee", str(svc_file)],
            input=svc_body, text=True, check=True, capture_output=True,
        )
        run(["sudo", "systemctl", "daemon-reload"])
        run(["sudo", "systemctl", "enable",  svc_name])
        run(["sudo", "systemctl", "restart", svc_name])

        success(f"Service '{svc_name}' installed and started")
        info(f"sudo systemctl status  {svc_name}")
        info(f"sudo systemctl stop    {svc_name}")
        info(f"sudo systemctl restart {svc_name}")
        info(f"journalctl -u {svc_name} -f   (live logs)")

else:
    info("Automatic service setup not supported on this platform.")
    info("Start manually with:  python run.py")

# ── Done ──────────────────────────────────────────────────────────────────────
port = next(
    (l.split("=", 1)[1].strip() for l in env_file.read_text().splitlines()
     if l.startswith("APP_PORT=")),
    "8000",
)

print()
print(f"{BOLD}{GREEN}  Installation complete.{NC}")
print()
print(f"  Start manually:  {BOLD}python run.py{NC}")
print()
print(f"  Open:  {BOLD}http://localhost:{port}{NC}")
print()
