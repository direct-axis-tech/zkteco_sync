#!/usr/bin/env python3
"""ZKTeco Sync — installation script.

Modes:
  install.py            Production install: interactive configuration, prebuilt
                        frontend from GitHub Releases, optional service setup.
  install.py --dev      Development machine: frontend built from the checkout,
                        APP_ENV=development (uvicorn auto-reload), no service.
  install.py --upgrade  Non-interactive upgrade after a git pull: re-syncs
                        dependencies, refreshes the frontend, restarts the
                        registered service. Never touches .env. Dev boxes are
                        detected from .env so the same command works everywhere.
"""

import argparse
import getpass
import os
import platform
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

# ── Constants ─────────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

ROOT     = Path(__file__).parent.resolve()
SVC_NAME = "zkteco-sync"

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

# ── Subprocess helpers ────────────────────────────────────────────────────────
def _winify(args):
    # On Windows we need shell=True to find .cmd/.bat shims (npm, uv via shim).
    # list2cmdline applies proper argv quoting so args with spaces/semicolons
    # survive cmd.exe parsing.
    return subprocess.list2cmdline([str(a) for a in args])

def run(args, cwd=None):
    """Stream command output to terminal. Dies on failure."""
    cmd = _winify(args) if IS_WINDOWS else args
    result = subprocess.run(cmd, shell=IS_WINDOWS, cwd=cwd)
    if result.returncode != 0:
        die(f"Command failed: {' '.join(str(a) for a in args)}")

def run_capture(args, cwd=None, input=None):
    """Run command, return (stdout, stderr, success)."""
    cmd = _winify(args) if IS_WINDOWS else args
    result = subprocess.run(
        cmd, shell=IS_WINDOWS, cwd=cwd, input=input,
        capture_output=True, text=True,
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode == 0

def last_error_line(stderr):
    """Best one-line summary of a failed command's stderr: the exception line
    of a Python traceback if present, otherwise the last non-blank line."""
    lines = [l for l in stderr.splitlines() if l.strip()]
    exc = next(
        (l for l in reversed(lines) if "Error" in l or "Exception" in l),
        lines[-1] if lines else stderr,
    )
    return exc.strip()

# ── .env access ───────────────────────────────────────────────────────────────
class EnvFile:
    """Read and patch a KEY=VALUE .env file without disturbing other lines."""

    def __init__(self, path):
        self.path = path

    def exists(self):
        return self.path.exists()

    def get(self, key, default=""):
        if not self.exists():
            return default
        for line in self.path.read_text().splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
        return default

    def set(self, **updates):
        """Replace (or append) the given KEY=VALUE lines in place."""
        lines = self.path.read_text().splitlines() if self.exists() else []
        pending = dict(updates)
        out = []
        for line in lines:
            key = line.split("=", 1)[0]
            if "=" in line and key in pending:
                out.append(f"{key}={pending.pop(key)}")
            else:
                out.append(line)
        out += [f"{k}={v}" for k, v in pending.items()]
        self.path.write_text("\n".join(out) + "\n")

    def write(self, content):
        self.path.write_text(content)

# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="ZKTeco Sync installer — see the module docstring for modes.",
    )
    parser.add_argument("--dev", action="store_true",
                        help="development machine: build frontend from source, "
                             "APP_ENV=development, no background service")
    parser.add_argument("--upgrade", action="store_true",
                        help="non-interactive upgrade: pull, re-sync, restart")
    parser.add_argument("--skip-pull", action="store_true",
                        help="with --upgrade: don't git pull first")
    return parser.parse_args()

# ── Phases ────────────────────────────────────────────────────────────────────
def print_banner(upgrade, dev_mode):
    label = "Upgrade" if upgrade else "Development setup" if dev_mode else "Installation"
    print()
    print(f"{BOLD}  ZKTeco Sync — {label}{NC}")
    print(f"  {DIM}Self-hosted ZKTeco attendance sync appliance{NC}")
    print()

def pull_latest():
    """git pull --ff-only. The pull may update install.py itself, so if HEAD
    moved we re-exec the freshly pulled installer (with --skip-pull to avoid
    looping) and let it finish the upgrade."""
    header("Pulling latest code")
    if not shutil.which("git") or not (ROOT / ".git").exists():
        warn("Not a git checkout (or git not installed) — skipping pull.")
        return

    old_head, _, _ = run_capture(["git", "rev-parse", "HEAD"], cwd=ROOT)
    _, pull_err, pulled = run_capture(["git", "pull", "--ff-only"], cwd=ROOT)
    if not pulled:
        warn(f"git pull failed: {last_error_line(pull_err)}")
        die("Resolve manually (local changes? no network?) "
            "or re-run with --skip-pull to upgrade without pulling.")

    new_head, _, _ = run_capture(["git", "rev-parse", "HEAD"], cwd=ROOT)
    if new_head == old_head:
        success("Already up to date")
        return

    success(f"Updated  {old_head[:7]} → {new_head[:7]}")
    info("Re-running the installer from the updated code…")
    result = subprocess.run(
        [sys.executable, str(ROOT / "install.py"), *sys.argv[1:], "--skip-pull"],
        cwd=ROOT,
    )
    sys.exit(result.returncode)

def check_prerequisites(dev_mode):
    header("Checking prerequisites")

    if sys.version_info < (3, 11):
        die(f"Python 3.11+ required. Found {sys.version_info.major}.{sys.version_info.minor}")
    success(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

    def check_tool(cmd, label):
        if not shutil.which(cmd):
            die(f"{label} is required but not installed.")
        out, _, _ = run_capture([cmd, "--version"])
        success(f"{label}  {out.splitlines()[0]}")

    check_tool("uv", "uv")
    if dev_mode:
        # Dev boxes build the frontend from source, so the Node toolchain is
        # required. Production servers download the released build instead.
        check_tool("node", "Node.js")
        check_tool("npm",  "npm")

def prompt_database():
    """Interactive database prompts. Returns a dict of DB_* values."""
    header("Database")
    print()
    info("Supported engines:  mariadb   mysql   postgresql   mssql")
    print()

    default_ports = {
        "mariadb": "3306", "mysql": "3306",
        "postgresql": "5432", "mssql": "1433",
    }
    while True:
        engine = ask("Engine", "mariadb")
        if engine in default_ports:
            break
        warn(f"Invalid engine '{engine}'. Choose: mariadb, mysql, postgresql, mssql")

    if engine == "mssql":
        print()
        info("For SQL Server Express / named instances, enter Host as")
        info(r"  HOSTNAME\INSTANCE   (e.g. DESKTOP-ABC\SQLEXPRESS)")
        info("Port will then be discovered automatically via SQL Browser.")
        print()

    host = ask("Host", "127.0.0.1")
    if engine == "mssql" and "\\" in host:
        port = ""
        info("Named instance detected — skipping port (SQL Browser will resolve it).")
    else:
        port = ask("Port", default_ports[engine])
    name = ask("Database", "zkteco_sync")

    if engine == "mssql":
        print()
        info("Leave username and password empty to use Windows Authentication.")
        print()
        user     = ask("Username (empty = Windows Auth)", "")
        password = ask_secret("Password (empty = Windows Auth)")
        print()
        odbc = ask("ODBC Driver", "ODBC Driver 17 for SQL Server")
    else:
        user     = ask("Username", "root")
        password = ask_secret("Password")
        odbc     = "ODBC Driver 17 for SQL Server"

    return {
        "DB_ENGINE": engine, "DB_HOST": host, "DB_PORT": port,
        "DB_NAME": name, "DB_USER": user, "DB_PASSWORD": password,
        "DB_ODBC_DRIVER": odbc,
    }

def configure(env, dev_mode):
    """Interactive configuration → fresh .env. Returns False if the user kept
    an existing .env instead."""
    if env.exists():
        header("Existing configuration found")
        warn(".env already exists.")
        if not ask_yn("Reconfigure?", default="n"):
            success("Keeping existing .env")
            return False

    header("App settings")
    app_host = ask("Bind address", "0.0.0.0")
    app_port = ask("Port",         "8000")

    db = prompt_database()

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

    header("Writing .env")
    env.write(
        f"APP_HOST={app_host}\n"
        f"APP_PORT={app_port}\n"
        f"APP_ENV={'development' if dev_mode else 'production'}\n"
        f"\n"
        f"API_USERNAME={api_username}\n"
        f"API_PASSWORD={api_password}\n"
        f"SECRET_KEY={secrets.token_hex(32)}\n"
        f"\n"
        f"DB_ENGINE={db['DB_ENGINE']}\n"
        f"DB_HOST={db['DB_HOST']}\n"
        f"DB_PORT={db['DB_PORT']}\n"
        f"DB_NAME={db['DB_NAME']}\n"
        f"DB_USER={db['DB_USER']}\n"
        f"DB_PASSWORD={db['DB_PASSWORD']}\n"
        f"DB_ODBC_DRIVER={db['DB_ODBC_DRIVER']}\n"
    )
    success(".env written")
    info("SECRET_KEY was auto-generated.")
    return True

def enforce_app_env(env, dev_mode):
    """The --dev flag is authoritative even when keeping an existing .env, so
    re-running the installer flips a box between dev and production."""
    target = "development" if dev_mode else "production"
    if env.get("APP_ENV") != target:
        env.set(APP_ENV=target)
        success(f"APP_ENV set to {target}")

def sync_python_deps():
    header("Installing Python dependencies")
    run(["uv", "sync"], cwd=ROOT)
    success("Python dependencies installed")

def test_database(env, upgrade):
    header("Testing database connection")

    probe = "from app.database import engine; engine.connect().close(); print('ok')"
    _, err, ok = run_capture(["uv", "run", "python", "-c", probe], cwd=ROOT)
    if ok:
        success("Database connection successful")
        return

    warn(f"Connection failed: {last_error_line(err)}")
    warn(f"Check credentials in .env and ensure the '{env.get('DB_NAME', '?')}' database exists.")
    if upgrade:
        warn("Continuing anyway (upgrade mode is non-interactive).")
    elif not ask_yn("Continue anyway?", default="n"):
        die("Aborted. Fix the database connection and re-run.")

def bootstrap_mssql_login(env):
    """If MSSQL is configured with Windows Auth (empty user and password), use
    the current session to create a dedicated SQL Auth login for the app. This
    decouples DB access from whichever Windows account runs the service."""
    if env.get("DB_ENGINE") != "mssql" or env.get("DB_USER") or env.get("DB_PASSWORD"):
        return

    header("Bootstrapping dedicated SQL login")
    new_user = "zkteco_sync_app"
    new_pw   = secrets.token_urlsafe(24)

    _, err, ok = run_capture(
        ["uv", "run", "python", "scripts/bootstrap_sql_user.py", new_user],
        cwd=ROOT, input=new_pw,
    )
    if not ok:
        warn(f"Bootstrap failed: {last_error_line(err)}")
        info("Your Windows user likely lacks CREATE LOGIN permission")
        info("(needs sysadmin or securityadmin on the SQL Server instance).")
        info("Re-run install.py from a SQL Server sysadmin Windows session,")
        info("or have a DBA create the login manually and provide it instead")
        info("of leaving the Username blank.")
        die("Aborted. Cannot proceed without a SQL Auth login for the service.")

    env.set(DB_USER=new_user, DB_PASSWORD=new_pw)
    success(f"Created SQL login '{new_user}' with db_owner on '{env.get('DB_NAME')}'")
    info(".env updated to SQL Auth — service identity no longer matters.")

def build_frontend_from_source():
    run(["npm", "install"], cwd=ROOT / "frontend")
    run(["npm", "run", "build"], cwd=ROOT / "frontend")
    success("Frontend built  →  frontend/dist/")

def install_frontend(dev_mode, upgrade):
    """Production servers download the CI-built, checksummed frontend bundle
    (zkteco-sync-frontend-v*.zip) from GitHub Releases, so they need neither
    Node nor npm. The download runs inside the
    venv (uv sync already succeeded) because httpx ships CA certs that a bare
    system Python often lacks. Dev boxes build from the checkout instead — a
    released build would shadow local frontend changes."""
    if dev_mode:
        header("Building frontend from source")
        build_frontend_from_source()
        info("While editing, use `npm run dev` for hot reload instead.")
        return

    header("Installing frontend")
    tag, err, fetched = run_capture(
        ["uv", "run", "python", "scripts/fetch_frontend.py"], cwd=ROOT
    )
    if fetched:
        success(f"Prebuilt frontend {tag} downloaded  →  frontend/dist/")
        return

    warn(f"Prebuilt frontend download failed: {last_error_line(err)}")
    if not upgrade and shutil.which("npm") and ask_yn(
        "Build the frontend locally with npm (slow on small servers)?", "y"
    ):
        build_frontend_from_source()
    elif (ROOT / "frontend" / "dist" / "index.html").exists():
        warn("Using the existing frontend/dist/ from a previous install.")
    else:
        die(
            "No frontend available. Either allow network access to github.com, "
            "install Node/npm for a local build, or copy a built frontend/dist/ "
            "onto this machine and re-run."
        )

def restart_service():
    """Upgrade path: never (re-)register — nssm install dies on an existing
    service. Just restart whatever is already registered."""
    if IS_WINDOWS and shutil.which("nssm"):
        _, _, registered = run_capture(["nssm", "status", SVC_NAME])
        if registered:
            run(["nssm", "restart", SVC_NAME])
            success(f"Service '{SVC_NAME}' restarted")
        else:
            info("No Windows service registered — restart the app manually.")
    elif IS_LINUX and shutil.which("systemctl"):
        _, _, registered = run_capture(["systemctl", "cat", SVC_NAME])
        if registered:
            run(["sudo", "systemctl", "restart", SVC_NAME])
            success(f"Service '{SVC_NAME}' restarted")
        else:
            info("No systemd service registered — restart the app manually.")
    else:
        info("Restart the app manually to load the new version.")

def is_windows_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def install_windows_service():
    nssm = shutil.which("nssm")
    if not nssm:
        warn("NSSM not found in PATH.")
        info("Download NSSM from nssm.cc, add nssm.exe to your PATH,")
        info("then re-run this installer to set up the background service.")
        return
    if not is_windows_admin():
        warn("Administrator privileges required to install a Windows service.")
        info("Re-run this script as Administrator to set up the service.")
        return
    if not ask_yn("Install as a Windows service (runs on boot, restarts on crash)?", "y"):
        return

    uv_path = shutil.which("uv")
    log_dir = ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    svc = SVC_NAME

    # Run as LocalSystem (NSSM default). DB access uses SQL Auth from .env,
    # so the service identity doesn't need any DB grants.
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

def install_linux_service():
    if not ask_yn("Install as a systemd service (runs on boot, restarts on crash)?", "y"):
        return

    svc_body = dedent(f"""\
        [Unit]
        Description=ZKTeco Sync
        After=network.target

        [Service]
        Type=simple
        User={os.getenv('USER', 'root')}
        WorkingDirectory={ROOT}
        ExecStart={shutil.which('uv')} run python run.py
        Restart=always
        RestartSec=5
        SyslogIdentifier={SVC_NAME}

        [Install]
        WantedBy=multi-user.target
        """)
    subprocess.run(
        ["sudo", "tee", f"/etc/systemd/system/{SVC_NAME}.service"],
        input=svc_body, text=True, check=True, capture_output=True,
    )
    run(["sudo", "systemctl", "daemon-reload"])
    run(["sudo", "systemctl", "enable",  SVC_NAME])
    run(["sudo", "systemctl", "restart", SVC_NAME])

    success(f"Service '{SVC_NAME}' installed and started")
    info(f"sudo systemctl status  {SVC_NAME}")
    info(f"sudo systemctl stop    {SVC_NAME}")
    info(f"sudo systemctl restart {SVC_NAME}")
    info(f"journalctl -u {SVC_NAME} -f   (live logs)")

def setup_service(dev_mode, upgrade):
    header("Background service")
    if upgrade:
        restart_service()
    elif dev_mode:
        info("Dev mode — skipping service registration.")
    elif IS_WINDOWS:
        install_windows_service()
    elif IS_LINUX and shutil.which("systemctl"):
        install_linux_service()
    else:
        info("Automatic service setup not supported on this platform.")
        info("Start manually with:  python run.py")

def print_summary(env, dev_mode, upgrade):
    port = env.get("APP_PORT", "8000")

    print()
    if upgrade:
        print(f"{BOLD}{GREEN}  Upgrade complete.{NC}")
    elif dev_mode:
        print(f"{BOLD}{GREEN}  Development setup complete.{NC}")
        print()
        print(f"  Backend (auto-reload):   {BOLD}uv run python run.py{NC}")
        print(f"  Frontend hot reload:     {BOLD}cd frontend && npm run dev{NC}")
        print()
        print(f"  App (built frontend):    {BOLD}http://localhost:{port}{NC}")
        print(f"  App (vite dev server):   {BOLD}http://localhost:5173{NC}  (proxies /api → :8000)")
        if port != "8000":
            warn(f"APP_PORT={port} but frontend/vite.config.js proxies to :8000 — "
                 f"keep port 8000 on dev boxes or update the proxy target.")
    else:
        print(f"{BOLD}{GREEN}  Installation complete.{NC}")
        print()
        print(f"  Start manually:  {BOLD}python run.py{NC}")
        print()
        print(f"  Open:  {BOLD}http://localhost:{port}{NC}")
    print()

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    if IS_WINDOWS:
        os.system("")  # enable ANSI escape codes in Windows Terminal / modern cmd
    # Keep our output ordered with subprocess output (uv, npm, git, re-exec)
    # when stdout is a pipe or log file rather than a terminal.
    sys.stdout.reconfigure(line_buffering=True)

    if not (ROOT / "pyproject.toml").exists() or not (ROOT / "frontend").exists():
        die("Run this script from the project root directory.")

    env = EnvFile(ROOT / ".env")
    if args.upgrade:
        if not env.exists():
            die("No .env found — run install.py (without --upgrade) first.")
        if env.get("APP_ENV") == "development":
            args.dev = True

    print_banner(args.upgrade, args.dev)

    if args.upgrade and not args.skip_pull:
        pull_latest()  # re-execs the fresh installer if HEAD moved

    check_prerequisites(args.dev)

    if not args.upgrade:
        if not configure(env, args.dev):
            enforce_app_env(env, args.dev)

    sync_python_deps()
    test_database(env, args.upgrade)

    if not args.upgrade:
        bootstrap_mssql_login(env)

    install_frontend(args.dev, args.upgrade)
    setup_service(args.dev, args.upgrade)
    print_summary(env, args.dev, args.upgrade)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n   {YELLOW}Interrupted.{NC}\n")
        sys.exit(130)
