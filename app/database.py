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
    _user = os.getenv("DB_USER", "")
    _password = os.getenv("DB_PASSWORD", "")
    if not _user and not _password:
        DB_URL = "{driver}://@{host}:{port}/{name}?driver={odbc}&trusted_connection=yes".format(
            driver=_driver,
            host=os.getenv("DB_HOST", "127.0.0.1"),
            port=os.getenv("DB_PORT", "1433"),
            name=os.getenv("DB_NAME", "zkteco_sync"),
            odbc=quote_plus(odbc_driver),
        )
    else:
        DB_URL += f"?driver={quote_plus(odbc_driver)}"

engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
