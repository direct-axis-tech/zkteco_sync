"""Idempotent, additive schema migrations run on every boot.

``create_all()`` creates missing *tables* but never touches a table that
already exists, so an upgraded install would silently run without the new
columns. This module closes that gap: it compares the mapped metadata with
what the database actually has and issues ``ALTER TABLE ... ADD`` for
anything missing.

Rules this module holds to, because it runs unattended on operator databases:

* additive only — never drops, never retypes, never renames;
* safe to repeat — a second run is a no-op;
* never adds NOT NULL without a default, since existing rows must get a value;
* dialect-portable across MariaDB, MySQL, PostgreSQL and MSSQL by asking the
  dialect's own type compiler rather than hard-coding SQL types.

Later units extend this file by adding columns to ``app/models.py`` (nothing
to do here — they are picked up automatically) and, if a new column needs
existing rows backfilled, by adding a statement to ``_run_data_fixups``,
which is handed the set of columns this run actually created.
"""

import logging

from sqlalchemy import Enum as SAEnum
from sqlalchemy import inspect, text
from sqlalchemy.schema import CreateIndex

from app.database import Base

# Importing the models is what populates Base.metadata — without it every
# table would look absent and run_migrations would silently do nothing.
import app.models  # noqa: F401,E402

log = logging.getLogger(__name__)


def run_migrations(engine) -> None:
    """Single entry point, called from the app lifespan right after create_all."""
    added = _add_missing_columns(engine)
    _add_missing_indexes(engine)
    _run_data_fixups(engine, added)


# ---------------------------------------------------------------------------
# Columns
# ---------------------------------------------------------------------------

def _add_missing_columns(engine) -> set:
    """Add every mapped column the database lacks; return what was added.

    The returned ``{(table, column)}`` set is what tells a data fixup that a
    column has just appeared on a table that already held rows — the only
    moment a backfill is meaningful."""
    inspector = inspect(engine)
    known_tables = set(inspector.get_table_names())
    added = set()

    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in known_tables:
                continue  # create_all just built it with every column present
            present = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present:
                    continue
                _add_column(conn, engine.dialect, table, column)
                added.add((table.name, column.name))

    return added


def add_column_sql(dialect, table, column) -> str:
    """The ALTER TABLE statement that adds one column, in the given dialect."""
    preparer = dialect.identifier_preparer
    default = _default_literal(column, dialect)

    parts = [preparer.quote(column.name), column.type.compile(dialect)]
    # NOT NULL is only safe when the database itself can fill existing rows.
    parts.append("NOT NULL" if (not column.nullable and default is not None) else "NULL")
    if default is not None:
        parts.append(f"DEFAULT {default}")

    # MSSQL's ALTER TABLE ADD takes the column list directly — no COLUMN keyword.
    keyword = "ADD" if dialect.name == "mssql" else "ADD COLUMN"
    return f"ALTER TABLE {preparer.format_table(table)} {keyword} {' '.join(parts)}"


def _add_column(conn, dialect, table, column) -> None:
    # PostgreSQL stores Enum as a named type that must exist before a column
    # can reference it. On MySQL/MSSQL this is a no-op.
    if isinstance(column.type, SAEnum):
        column.type.create(conn, checkfirst=True)

    ddl = add_column_sql(dialect, table, column)
    log.info("migration: %s", ddl)
    conn.execute(text(ddl))

    if not column.nullable and _default_literal(column, dialect) is None:
        log.warning(
            "migration: %s.%s is declared NOT NULL but has no server default — "
            "added as NULL so existing rows stay valid",
            table.name,
            column.name,
        )


def _default_literal(column, dialect):
    """SQL literal for a column's default, or None when the DB cannot supply one.

    Python-side callables (timestamps, sequences) are applied by the ORM on
    insert, so they give the database nothing to backfill with."""
    server_default = getattr(column, "server_default", None)
    if server_default is not None and getattr(server_default, "arg", None) is not None:
        return str(server_default.arg)

    default = column.default
    if default is None or not getattr(default, "is_scalar", False):
        return None
    return _literal(default.arg, dialect)


def _literal(value, dialect):
    if isinstance(value, bool):
        # PostgreSQL will not accept 1/0 for a boolean column.
        if dialect.name == "postgresql":
            return "TRUE" if value else "FALSE"
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return None


# ---------------------------------------------------------------------------
# Indexes
# ---------------------------------------------------------------------------

def _add_missing_indexes(engine) -> None:
    """Create indexes declared in the metadata that the database lacks.

    A column added by _add_missing_columns arrives without the index its
    model declares, so this pass follows it."""
    inspector = inspect(engine)
    known_tables = set(inspector.get_table_names())

    for table in Base.metadata.sorted_tables:
        if table.name not in known_tables:
            continue
        present = {idx.get("name") for idx in inspector.get_indexes(table.name)}
        columns = {col["name"] for col in inspector.get_columns(table.name)}
        for index in table.indexes:
            if index.name in present:
                continue
            if not {col.name for col in index.columns}.issubset(columns):
                continue
            try:
                with engine.begin() as conn:
                    log.info("migration: creating index %s on %s", index.name, table.name)
                    conn.execute(CreateIndex(index))
            except Exception as exc:  # an index is an optimisation, never a blocker
                log.warning("migration: could not create index %s: %s", index.name, exc)


# ---------------------------------------------------------------------------
# Data fixups
# ---------------------------------------------------------------------------

def _run_data_fixups(engine, added: set) -> None:
    """Backfills for columns whose default is wrong for pre-existing rows.

    ``added`` holds the ``(table, column)`` pairs this run created. Keying a
    backfill on it is what makes the backfill idempotent: it fires on the one
    boot that introduced the column and never again, so it cannot later undo a
    value an operator has since chosen.
    """
    _approve_pre_existing_devices(engine, added)


def _approve_pre_existing_devices(engine, added: set) -> None:
    """Devices already in the database were trusted before D3 existed.

    ``Device.status`` defaults to 'pending', which is right for a serial seen
    for the first time and badly wrong for an install that has been collecting
    attendance for months: those devices would go quiet the moment this
    version boots. Anything present at the instant the column appears is
    therefore grandfathered in as approved."""
    if ("devices", "status") not in added:
        return

    with engine.begin() as conn:
        result = conn.execute(
            text(
                "UPDATE devices SET status = 'approved', approved_by = 'migration' "
                "WHERE status IS NULL OR status = 'pending'"
            )
        )
    log.warning(
        "migration: grandfathered %s pre-existing device(s) to status='approved' — "
        "newly seen serials from now on require explicit approval",
        result.rowcount,
    )
