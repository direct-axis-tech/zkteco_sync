from datetime import timezone
from sqlalchemy import create_engine, DateTime, TypeDecorator
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
from urllib.parse import quote_plus
import os


class UTCDateTime(TypeDecorator):
    """DateTime column that always returns timezone-aware UTC datetimes."""
    impl = DateTime
    cache_ok = True

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

load_dotenv()

_DRIVERS = {
    "mariadb":     "mysql+pymysql",
    "mysql":       "mysql+pymysql",
    "postgresql":  "postgresql+psycopg2",
    "mssql":       "mssql+pyodbc",
}

_db_engine = os.getenv("DB_ENGINE", "mariadb").lower()
_driver = _DRIVERS.get(_db_engine)

if not _driver:
    raise ValueError(
        f"Unsupported DB_ENGINE '{_db_engine}'. "
        f"Supported values: {', '.join(_DRIVERS.keys())}"
    )

DB_URL = "{driver}://{user}:{password}@{host}:{port}/{name}".format(
    driver=_driver,
    user=os.getenv("DB_USER", "root"),
    password=quote_plus(os.getenv("DB_PASSWORD", "")),
    host=os.getenv("DB_HOST", "127.0.0.1"),
    port=os.getenv("DB_PORT", "3306"),
    name=os.getenv("DB_NAME", "zkteco_sync"),
)

if _db_engine == "mssql":
    odbc_driver = os.getenv("DB_ODBC_DRIVER", "ODBC Driver 17 for SQL Server")
    _host = os.getenv("DB_HOST", "127.0.0.1")
    _port = os.getenv("DB_PORT", "").strip()
    _name = os.getenv("DB_NAME", "zkteco_sync")
    _user = os.getenv("DB_USER", "").strip()
    _password = os.getenv("DB_PASSWORD", "")

    # Named instances (HOST\INSTANCE) use dynamic ports — let SQL Browser
    # resolve them. Adding ,PORT only works for default instances or
    # instances explicitly bound to a static port.
    if "\\" in _host:
        _server = _host
    elif _port:
        _server = f"{_host},{_port}"
    else:
        _server = _host

    parts = [
        f"DRIVER={{{odbc_driver}}}",
        f"SERVER={_server}",
        f"DATABASE={_name}",
    ]
    if _user or _password:
        parts.append(f"UID={_user}")
        parts.append(f"PWD={_password}")
    else:
        parts.append("Trusted_Connection=yes")

    DB_URL = f"mssql+pyodbc:///?odbc_connect={quote_plus(';'.join(parts))}"

engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
