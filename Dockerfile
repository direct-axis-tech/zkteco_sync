# syntax=docker/dockerfile:1.7
#
# ZKTeco Sync — one image holding the FastAPI backend and the built React UI.
#
#   docker build -t zkteco-sync .                                  # Alpine, default
#   docker build --target runtime-mssql -t zkteco-sync:mssql .     # Debian + MS ODBC
#
# Layout. `frontend` and `deps` are throwaway build environments; only their
# outputs (frontend/dist and the /opt/venv virtualenv) are copied into a
# runtime stage that has nothing else installed — no node, no uv, no package
# manager state, no compiler. Every Python dependency is a prebuilt wheel
# (musl and glibc, amd64 and arm64 — see uv.lock), so no stage compiles
# anything and the default build never runs a package manager at all.
#
# Two runtime stages, because they want different bases:
#
#   runtime        python:3.11-alpine. The image people should run. Roughly
#                  half the size of the Debian one. Supports MariaDB, MySQL
#                  and PostgreSQL.
#   runtime-mssql  python:3.11-slim plus Microsoft's ODBC Driver 18, for
#                  DB_ENGINE=mssql (set DB_ODBC_DRIVER="ODBC Driver 18 for
#                  SQL Server"). glibc because that is where Microsoft's apt
#                  package just works; it also accepts Microsoft's EULA on
#                  your behalf, which is a second reason it is opt-in.
#
# Both bases ship tzdata (app/config.py needs a tz database) and
# ca-certificates (outbound HTTPS to the HRM).

# --- frontend ---------------------------------------------------------------
# Pinned to the build host's own platform: the output is static files, so in
# a multi-arch build there is no reason to run node under QEMU emulation.
FROM --platform=$BUILDPLATFORM node:20-alpine AS frontend

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- Python dependencies, one venv per libc --------------------------------
# --frozen: the lock is the source of truth; a pyproject that has drifted
# from it fails the build instead of resolving something new silently.
# Bytecode is compiled here, once, so the container starts fast and the
# read-only runtime never wants to write .pyc files.
FROM python:3.11-alpine AS deps
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

FROM python:3.11-slim AS deps-glibc
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# --- runtime-mssql ----------------------------------------------------------
FROM python:3.11-slim AS runtime-mssql

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH" \
    APP_HOST=0.0.0.0 APP_PORT=8000

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && . /etc/os-release \
 && curl -fsSL "https://packages.microsoft.com/config/debian/${VERSION_ID}/packages-microsoft-prod.deb" \
      -o /tmp/packages-microsoft-prod.deb \
 && dpkg -i /tmp/packages-microsoft-prod.deb \
 && rm /tmp/packages-microsoft-prod.deb \
 && apt-get update \
 && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 unixodbc \
 && apt-get purge -y --auto-remove curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=deps-glibc /opt/venv /opt/venv
COPY app/ ./app/
COPY tests/ ./tests/
COPY run.py docker/healthcheck.py ./
COPY --from=frontend /build/dist ./frontend/dist

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "healthcheck.py"]
CMD ["python", "run.py"]

# --- runtime (default: last stage wins) -------------------------------------
FROM python:3.11-alpine AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH" \
    # A container has no loopback-only Apache in front of it; the socket
    # must be reachable from outside the network namespace. Compose narrows
    # what the *host* exposes via the ports: mapping (127.0.0.1 by default).
    APP_HOST=0.0.0.0 APP_PORT=8000

# Unprivileged user. Nothing here needs to write to the image, so the files
# stay root-owned and world-readable — no chown layer.
RUN adduser -S -D -H -s /sbin/nologin app

WORKDIR /app
COPY --from=deps /opt/venv /opt/venv
COPY app/ ./app/
COPY tests/ ./tests/
COPY run.py docker/healthcheck.py ./
COPY --from=frontend /build/dist ./frontend/dist

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "healthcheck.py"]
CMD ["python", "run.py"]
