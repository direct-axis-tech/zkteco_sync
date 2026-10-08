#!/usr/bin/env bash
#
# Turn the checkout this script sits in into a ZKTeco Sync instance on a
# Bitnami server, served at https://<hostname>. A server can hold any number
# of instances - one checkout each - and each one is named <instance>:
#
#   code, .venv, .env   this checkout
#   database            zkteco_sync_<instance>   (non [A-Za-z0-9_] becomes '_')
#   systemd service     zkteco-sync-<instance>
#   Apache vhost        conf/vhosts/zkteco-sync-<instance>-vhost.conf
#   port                first free one from 8000 up
#
# Shared by all instances on the server:
#
#   uv's Python         UV_PYTHON_INSTALL_DIR from /etc/environment; if unset,
#                       /opt/uv/python, written to /etc/environment and
#                       /etc/profile.d/uv-python.sh
#
# Usage, as the bitnami user, from a fresh clone outside /home:
#
#   git clone https://github.com/direct-axis-tech/zkteco_sync.git /opt/zkteco-sync-acme
#   cd /opt/zkteco-sync-acme
#   sudo ./deploy/bitnami/provision.sh [-c|--cert-name NAME] <instance> <hostname>
#
#   -c, --cert-name  serve /opt/bitnami/apache/conf/NAME.crt/.key instead of
#                    <hostname>.crt/.key
#
# Prerequisite: DNS for <hostname> points here, and a certificate lists
# <hostname> among its domains. Get one, or add <hostname> to the server's
# existing one, with:
#
#   sudo /opt/bitnami/bncert-tool
#
# If the certificate it writes is named after another domain (e.g.
# system.axispro.xyz.crt), pass --cert-name system.axispro.xyz. Either way
# the script checks that the certificate covers <hostname> before it changes
# anything.
#
# Re-running for the same instance is safe: finished steps are skipped.
# Anything that already belongs to another instance makes it stop before
# changing a thing.

set -euo pipefail

readonly INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ENV_FILE="$INSTALL_DIR/.env"
readonly BITNAMI=/opt/bitnami
readonly APACHE_CONF="$BITNAMI/apache/conf"
readonly HTTPD="$BITNAMI/apache/bin/httpd"
readonly FIRST_PORT=8000
readonly DEFAULT_UV_PYTHON_DIR=/opt/uv/python

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[0;32mok\033[0m  %s\n' "$*"; }
die()  { printf '\n\033[0;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# set -e exits on any failing command without a word; say where instead, as
# the chain of steps (e.g. as_user < install_uv < main) and the command.
# -E carries the trap into functions, where nearly everything here runs.
on_error() {
    local steps="${FUNCNAME[*]:1:${#FUNCNAME[@]}-2}"   # minus on_error and bash's own "main"
    die "unexpected failure in ${steps// / < }, line $1: $2"
}
set -E
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

# Run a command as the user who invoked sudo: they own the instance's files
# and install.py names them as the service's User=.
as_user() {
    runuser -u "$OWNER" -- env \
        USER="$OWNER" HOME="$OWNER_HOME" \
        PATH="$OWNER_HOME/.local/bin:$PATH" \
        UV_PYTHON_INSTALL_DIR="$UV_PYTHON_INSTALL_DIR" \
        "$@"
}

# Empty when the key, or the whole .env, is missing - as on a first run.
env_get() {
    [ -f "$ENV_FILE" ] || return 0
    sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1
}

# A MySQL name from $1: anything outside A-Z a-z 0-9 _ becomes '_', cut to
# $2 characters (64 for a database, 32 for a user).
sql_name() { local name="${1//[^A-Za-z0-9_]/_}"; printf '%s' "${name:0:$2}"; }

sql() { mysql --defaults-extra-file="$MYCNF" -N -B -e "$1"; }

# ── Inputs ────────────────────────────────────────────────────────────────────

# The header comment, down to the first blank line.
usage() { sed -n '2,/^$/p' "$0"; }

parse_args() {
    local opts cert_name=""
    opts="$(getopt -o c:h -l cert-name:,help -n "$(basename "$0")" -- "$@")" || exit 1
    eval set -- "$opts"
    while true; do
        case "$1" in
            -c|--cert-name) cert_name="$2"; shift 2 ;;
            -h|--help)      usage; exit 0 ;;
            --)             shift; break ;;
        esac
    done
    [ $# -eq 2 ] || die "usage: sudo $0 [-c|--cert-name NAME] <instance> <hostname>"

    INSTANCE="$1"
    HOST="$2"
    [[ "$INSTANCE" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] \
        || die "instance must be 1-32 of a-z, 0-9 and '-', not starting or ending in '-': $INSTANCE"

    SERVICE="zkteco-sync-$INSTANCE"
    DB_NAME="$(sql_name "zkteco_sync_$INSTANCE" 64)"
    VHOST="$APACHE_CONF/vhosts/zkteco-sync-$INSTANCE-vhost.conf"
    CERT_FILE="$APACHE_CONF/${cert_name:-$HOST}.crt"
    KEY_FILE="$APACHE_CONF/${cert_name:-$HOST}.key"
}

# ── Preflight: everything that could stop us halfway, checked up front ──────

require_sudo() {
    [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] \
        || die "run with sudo from the bitnami user: sudo $0 $*"
    OWNER="$SUDO_USER"
    OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
    ROOT_PASSWORD_FILE="$OWNER_HOME/bitnami_application_password"
}

check_server() {
    [ -x "$HTTPD" ]       || die "$HTTPD not found - this script targets Bitnami stacks"
    [ -r "$CERT_FILE" ]   || die "no $CERT_FILE - run bncert-tool for $HOST first, or pass --cert-name"
    [ -r "$KEY_FILE" ]    || die "no $KEY_FILE - run bncert-tool for $HOST first, or pass --cert-name"
    openssl x509 -in "$CERT_FILE" -noout -checkhost "$HOST" | grep -q "does match" \
        || die "$CERT_FILE does not cover $HOST - add $HOST with bncert-tool (see the prerequisite in --help)"
    openssl x509 -in "$CERT_FILE" -noout -checkend 0 >/dev/null \
        || die "$CERT_FILE has expired - renew it with bncert-tool"
    command -v ss >/dev/null    || die "ss (iproute2) is required"
    command -v mysql >/dev/null || PATH="$PATH:$BITNAMI/mariadb/bin:$BITNAMI/mysql/bin"
    command -v mysql >/dev/null || die "mysql client not found"

    if [ -d "$BITNAMI/mariadb" ]; then DB_ENGINE=mariadb; else DB_ENGINE=mysql; fi
}

# install.py runs as the owner and writes .venv and .env here, and the
# service runs with ProtectHome=true, which hides /home from it.
check_checkout() {
    case "$INSTALL_DIR" in
        /home/*|/root/*) die "$INSTALL_DIR is under /home, which the service cannot see - clone under /opt instead" ;;
    esac
    runuser -u "$OWNER" -- test -w "$INSTALL_DIR" \
        || die "$INSTALL_DIR is not writable by $OWNER - sudo chown -R $OWNER: $INSTALL_DIR"
}

# The service runs with ProtectHome=true, so it cannot see uv's default
# Python under ~/.local/share/uv. Every login must agree on a location
# outside /home, or a later `install.py --upgrade` puts Python back there.
# Empty here means unset; install_uv sets it up.
read_uv_python_dir() {
    UV_PYTHON_INSTALL_DIR="$(cat /etc/environment /etc/profile.d/uv-python.sh 2>/dev/null \
        | sed -nE 's/^(export )?UV_PYTHON_INSTALL_DIR="?([^"]*)"?$/\2/p' | head -n1 || true)"

    case "$UV_PYTHON_INSTALL_DIR" in
        "")              return ;;
        /home/*|/root/*) die "UV_PYTHON_INSTALL_DIR=$UV_PYTHON_INSTALL_DIR is under /home, which the service cannot see" ;;
        /*)              ;;
        *)               die "UV_PYTHON_INSTALL_DIR must be absolute: $UV_PYTHON_INSTALL_DIR" ;;
    esac
    if [ -d "$UV_PYTHON_INSTALL_DIR" ]; then
        runuser -u "$OWNER" -- test -w "$UV_PYTHON_INSTALL_DIR" \
            || die "$UV_PYTHON_INSTALL_DIR is not writable by $OWNER"
    fi
}

# The root password goes through a 0600 options file, never argv.
open_database() {
    [ -r "$ROOT_PASSWORD_FILE" ] || die "$ROOT_PASSWORD_FILE not found"

    MYCNF="$(mktemp)"
    trap 'rm -f "$MYCNF"' EXIT
    printf '[client]\nuser=root\npassword="%s"\n' "$(cat "$ROOT_PASSWORD_FILE")" > "$MYCNF"
    sql "SELECT 1" >/dev/null || die "cannot log in to $DB_ENGINE as root"
}

# Whichever user the app logs in as can reach every database that user can.
# Asked on a first run only; a re-run keeps what .env already says.
choose_db_user() {
    DB_USER="$(env_get DB_USER)"
    DB_PASSWORD="$(env_get DB_PASSWORD)"
    [ -n "$DB_USER" ] && return

    local suggested
    suggested="$(sql_name "zkteco_sync_$INSTANCE" 32)"
    read -rp "    Database user for this instance [$suggested]: " DB_USER
    DB_USER="${DB_USER:-$suggested}"
    [[ "$DB_USER" =~ ^[A-Za-z0-9_]{1,32}$ ]] \
        || die "database user must be 1-32 of A-Z, a-z, 0-9 and '_': $DB_USER"

    if [ "$DB_USER" = root ]; then
        DB_PASSWORD="$(cat "$ROOT_PASSWORD_FILE")"
    elif [ "$(sql "SELECT COUNT(*) FROM mysql.user WHERE User='$DB_USER' AND Host='127.0.0.1'")" != 0 ]; then
        read -rsp "    Password of existing user $DB_USER: " DB_PASSWORD; echo
        can_log_in "$DB_USER" "$DB_PASSWORD" || die "cannot log in as $DB_USER with that password"
    else
        DB_PASSWORD="$(openssl rand -hex 24)"
    fi
}

# Over TCP to 127.0.0.1, exactly as the app connects.
can_log_in() {
    local cnf ok=1
    cnf="$(mktemp)"
    printf '[client]\nuser=%s\npassword="%s"\n' "$1" "$2" > "$cnf"
    mysql --defaults-extra-file="$cnf" --protocol=TCP -h 127.0.0.1 -e "SELECT 1" >/dev/null 2>&1 && ok=0
    rm -f "$cnf"
    return $ok
}

# Without a .env this is a first run, so anything already carrying this
# instance's names belongs to someone else.
check_no_collision() {
    if [ ! -f "$ENV_FILE" ]; then
        # An empty database is what an interrupted earlier run leaves behind.
        local tables
        tables="$(sql "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='$DB_NAME'")"
        [ "$tables" = 0 ] || die "database $DB_NAME already holds data - pick another instance name"
    fi

    if systemctl cat "$SERVICE" >/dev/null 2>&1 \
       && ! systemctl cat "$SERVICE" | grep -qx "WorkingDirectory=$INSTALL_DIR"; then
        die "service $SERVICE already runs from somewhere other than $INSTALL_DIR"
    fi

    # Apache silently serves a hostname from the first vhost naming it, so a
    # duplicate would route one client's devices to another instance.
    local others
    others="$(grep -rlE "^\s*Server(Name|Alias)\s+(.*\s)?${HOST//./\\.}(\s|:|$)" \
                "$APACHE_CONF/vhosts" "$APACHE_CONF/bitnami" 2>/dev/null \
              | grep -vxF "$VHOST" || true)"
    [ -z "$others" ] || die "$HOST is already served by: $others"
}

# Keep the instance's existing port; otherwise take the first one nothing
# listens on and no other instance has claimed (a stopped one still owns it).
choose_port() {
    APP_PORT="$(env_get APP_PORT)"
    [ -n "$APP_PORT" ] && return

    CLAIMED_PORTS="$(claimed_ports)"
    APP_PORT=$FIRST_PORT
    while port_taken "$APP_PORT"; do APP_PORT=$((APP_PORT + 1)); done
}

port_taken() {
    ss -Hltn | awk '{print $4}' | grep -qE "[:.]$1\$" \
        || grep -qx "$1" <<< "$CLAIMED_PORTS"
}

# APP_PORT of every other instance, found through its zkteco-sync* service:
# instances live wherever they were cloned.
claimed_ports() {
    local unit dir
    for unit in $(systemctl list-unit-files 'zkteco-sync*' --no-legend 2>/dev/null | awk '{print $1}' || true); do
        dir="$(systemctl show -p WorkingDirectory --value "$unit")"
        [ "$dir" != "$INSTALL_DIR" ] || continue
        sed -n 's/^APP_PORT=//p' "$dir/.env" 2>/dev/null || true
    done
}

# ── Install ───────────────────────────────────────────────────────────────────

# /etc/environment covers every session; profile.d covers login shells.
set_up_uv_python_dir() {
    if [ -z "$UV_PYTHON_INSTALL_DIR" ]; then
        UV_PYTHON_INSTALL_DIR="$DEFAULT_UV_PYTHON_DIR"
        # Don't glue the new line onto a last line that lacks its newline.
        [ -z "$(tail -c1 /etc/environment 2>/dev/null)" ] || echo >> /etc/environment
        echo "UV_PYTHON_INSTALL_DIR=$UV_PYTHON_INSTALL_DIR" >> /etc/environment
        echo "export UV_PYTHON_INSTALL_DIR=$UV_PYTHON_INSTALL_DIR" > /etc/profile.d/uv-python.sh
        UV_PYTHON_DIR_ADDED=true
        ok "UV_PYTHON_INSTALL_DIR=$UV_PYTHON_INSTALL_DIR set system-wide"
    fi
    [ -d "$UV_PYTHON_INSTALL_DIR" ] \
        || install -d -o "$OWNER" -g "$(id -gn "$OWNER")" "$UV_PYTHON_INSTALL_DIR"
}

install_uv() {
    set_up_uv_python_dir
    as_user sh -c 'command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh'
    as_user sh -c 'uv python find 3.11 >/dev/null 2>&1 || uv python install 3.11'
    ok "$(as_user uv --version), Python $(as_user uv python find 3.11)"
}

create_database() {
    sql "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
    ok "$DB_NAME"

    [ "$DB_USER" = root ] && return
    sql "CREATE USER IF NOT EXISTS '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD'"
    sql "GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'127.0.0.1'"
    can_log_in "$DB_USER" "$DB_PASSWORD" || die "created $DB_USER but cannot log in as it"
    ok "$DB_USER granted $DB_NAME"
}

# install.py asks its own questions; tell the operator the answers that
# differ per instance, then check they were typed in.
run_installer() {
    local password_hint="$DB_PASSWORD"
    [ "$DB_USER" = root ] && password_hint="contents of $ROOT_PASSWORD_FILE"
    cat <<EOF

    Answer install.py with the defaults, except:

      Service name ...... $SERVICE
      Port .............. $APP_PORT
      Public hostname ... $HOST
      Engine ............ $DB_ENGINE
      Database .......... $DB_NAME
      Username .......... $DB_USER
      Password .......... $password_hint

EOF
    (cd "$INSTALL_DIR" && as_user uv run --python 3.11 python install.py)

    [ -f "$ENV_FILE" ]                          || die "install.py wrote no $ENV_FILE"
    [ "$(env_get SERVICE_NAME)" = "$SERVICE" ]  || die "SERVICE_NAME in $ENV_FILE is not $SERVICE - re-run and reconfigure"
    [ "$(env_get DB_NAME)" = "$DB_NAME" ]       || die "DB_NAME in $ENV_FILE is not $DB_NAME - fix it and re-run"
    [ "$(env_get DB_USER)" = "$DB_USER" ]       || die "DB_USER in $ENV_FILE is not $DB_USER - fix it and re-run"
    [ "$(env_get APP_PORT)" = "$APP_PORT" ]     || die "APP_PORT in $ENV_FILE is not $APP_PORT - fix it and re-run"
    [[ ",$(env_get ALLOWED_HOSTS)," == *",$HOST,"* ]] \
        || die "ALLOWED_HOSTS in $ENV_FILE does not include $HOST - fix it and re-run"
}

# Other sites share this Apache: a config that fails the test never gets
# as far as the restart.
publish_vhost() {
    if [ -e "$VHOST" ]; then
        ok "$VHOST already exists - left as is"
    else
        sed -e "s|@INSTANCE@|$INSTANCE|g" \
            -e "s|@HOSTNAME@|$HOST|g" \
            -e "s|@CERT_FILE@|$CERT_FILE|g" \
            -e "s|@KEY_FILE@|$KEY_FILE|g" \
            -e "s|@APP_PORT@|$APP_PORT|g" \
            "$INSTALL_DIR/deploy/bitnami/zkteco-sync-vhost.conf.template" > "$VHOST"
        ok "wrote $VHOST"
    fi

    "$HTTPD" -t -f "$APACHE_CONF/httpd.conf" \
        || die "Apache config test failed - fix $VHOST and re-run (Apache untouched)"
    "$BITNAMI/ctlscript.sh" restart apache
    ok "Apache restarted"
}

# Through Apache on this box, so unpropagated DNS cannot fail it. 502-504
# means the app is not answering yet; give it a few seconds to boot.
check_live() {
    systemctl is-active --quiet "$SERVICE" \
        || die "$SERVICE is not running - journalctl -u $SERVICE -n 50"

    local code
    for _ in $(seq 15); do
        code="$(curl -sk -o /dev/null -w '%{http_code}' \
                  --resolve "$HOST:443:127.0.0.1" "https://$HOST/" || true)"
        case "$code" in 000|50[234]) sleep 2 ;; *) ok "HTTP $code"; return ;; esac
    done
    die "https://$HOST answered $code - journalctl -u $SERVICE -n 50, $BITNAMI/apache/logs/zkteco-sync-$INSTANCE-error.log"
}

print_next_steps() {
    cat <<EOF

Instance '$INSTANCE' is live at https://$HOST

  1. Log in as the admin you created and change its password.
  2. Delete API_USERNAME and API_PASSWORD from $ENV_FILE.
  3. Point devices at $HOST, port 443, HTTPS, and open pairing under Devices.

  Logs     journalctl -u $SERVICE -f
  Upgrade  cd $INSTALL_DIR && uv run python install.py --upgrade
EOF
    if [ "${UV_PYTHON_DIR_ADDED:-}" = true ]; then
        echo
        echo "  UV_PYTHON_INSTALL_DIR was just set system-wide: log out and back in"
        echo "  before running --upgrade, or uv will not see it."
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"
    require_sudo "$@"

    step "Checking the server for instance '$INSTANCE'"
    check_server
    check_checkout
    read_uv_python_dir
    open_database
    check_no_collision
    choose_port
    choose_db_user
    ok "$INSTALL_DIR, database $DB_NAME as $DB_USER, service $SERVICE, port $APP_PORT"

    step "uv and Python 3.11";        install_uv
    step "Database";                  create_database
    step "install.py";                run_installer
    step "Apache vhost";              publish_vhost
    step "Checking https://$HOST";    check_live
    print_next_steps
}

main "$@"
