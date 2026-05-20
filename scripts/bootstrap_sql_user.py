"""Bootstrap a dedicated SQL Auth login + db user with db_owner.

Connects using whatever credentials are currently in .env (typically Windows
Auth during install) and creates a new SQL Server login the app can use
permanently. Decouples DB access from the OS identity that runs the service.

Reads the new username from argv[1] and the new password from stdin so the
password never appears in process lists or shell history. Idempotent — if
the login already exists, its password is reset and db_owner is reaffirmed.

Usage:
    echo <password> | uv run python scripts/bootstrap_sql_user.py <username>
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import text  # noqa: E402

from app.database import engine  # noqa: E402


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: bootstrap_sql_user.py <username>  (password on stdin)",
            file=sys.stderr,
        )
        sys.exit(1)

    username = sys.argv[1]
    password = sys.stdin.read().strip()
    if not password:
        print("Password missing on stdin", file=sys.stderr)
        sys.exit(1)

    # Escape single quotes for the SQL literal. Identifiers use [] brackets,
    # which only need handling if the username contains ']' — we control the
    # name from the installer so that's not a concern.
    pw_lit = password.replace("'", "''")

    sqls = [
        f"IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'{username}') "
        f"CREATE LOGIN [{username}] WITH PASSWORD = N'{pw_lit}', CHECK_POLICY = OFF",

        # Reset password if the login already existed (idempotent re-run).
        f"IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'{username}') "
        f"ALTER LOGIN [{username}] WITH PASSWORD = N'{pw_lit}'",

        f"IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'{username}') "
        f"CREATE USER [{username}] FOR LOGIN [{username}]",

        f"ALTER ROLE db_owner ADD MEMBER [{username}]",
    ]

    print(f"Bootstrapping SQL login [{username}]")
    conn = engine.connect().execution_options(isolation_level="AUTOCOMMIT")
    try:
        for sql in sqls:
            try:
                conn.execute(text(sql))
            except Exception as e:
                # ALTER ROLE ADD MEMBER raises if already a member — fine.
                if "already" in str(e).lower():
                    continue
                raise
    finally:
        conn.close()
    print("ok")


if __name__ == "__main__":
    main()
