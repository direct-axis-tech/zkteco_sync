# Deploying with Docker

One image holds the backend and the built UI; `docker-compose.yml` adds a
MariaDB next to it. Everything is driven by the same `.env` a native install
uses, so [README → Setup](README.md#setup) and [SECURITY.md](SECURITY.md)
still apply — this document only covers what is different inside a
container.

## Quick start

```bash
git clone <repo-url>
cd zkteco-sync
cp .env.example .env
chmod 600 .env
```

Edit `.env`. At minimum:

| Key | Notes |
|-----|-------|
| `SECRET_KEY` | `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ALLOWED_HOSTS` | The hostname(s) the app is reached as. Required when `APP_ENV=production`. |
| `API_USERNAME` / `API_PASSWORD` | First-boot admin. Forced password change at first login; delete afterwards. |
| `DB_HOST=db`, `DB_PORT=3306` | The bundled MariaDB, as the app sees it on the compose network. (Or your own server — see [below](#using-a-database-you-already-have).) |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD` | Create the database and account inside the bundled MariaDB **and** tell the app how to connect. `DB_USER` must **not** be `root` — the MariaDB image refuses to create a regular user by that name (`.env.example` says `root` because that is a common native default). |
| `TRUSTED_PROXIES` | `172.30.0.1` if Apache on the host fronts the container — see [below](#trusted_proxies-is-different-under-docker). |

Then:

```bash
docker compose up -d --build
docker compose logs -f app
```

The first boot creates the database, schema and admin account exactly as a
native first run does. The UI answers on `http://127.0.0.1:8000`; the app
rejects any `Host` header not in `ALLOWED_HOSTS`, so either send that
hostname (`curl -H 'Host: zk.example.com' http://127.0.0.1:8000/healthz`) or
add the machine's own address to `ALLOWED_HOSTS` while testing.

Upgrade:

```bash
git pull
docker compose up -d --build
```

The database lives in the `dbdata` volume and survives rebuilds; schema
migrations run automatically on boot, as natively.

## What compose changes, and what it does not

Compose pins exactly one key under `environment:`: `APP_HOST=0.0.0.0`,
because inside a container the socket has to be reachable from outside the
network namespace (what the *host* exposes is narrowed separately by
`APP_BIND`). Everything else — `APP_ENV`, `ALLOWED_HOSTS`, the database
settings, all the hardening keys — is read from `.env` unchanged.

Two keys are Docker-only, read by compose and never by the app:

| Key | Default | Meaning |
|-----|---------|---------|
| `APP_BIND` | `127.0.0.1` | Host interface the published port binds to. Keep loopback when Apache on the host terminates TLS; `0.0.0.0` for a plain LAN deployment where devices push straight to the container. |
| `ZK_SUBNET` | `172.30.0.0/24` | The compose network. Fixed so the gateway address is predictable (next section). Change only if it collides with a network you route to. |

## `TRUSTED_PROXIES` is different under Docker

Natively, Apache connects to the app over loopback, so `TRUSTED_PROXIES=
127.0.0.1` is what makes `X-Forwarded-For` believable. Under the default
compose file the app sees that same connection arriving from the **Docker
bridge gateway** — `172.30.0.1` with the default subnet — because the host's
port mapping is what opened the socket, not Apache directly.

Set `TRUSTED_PROXIES=172.30.0.1` in `.env`. Leave it at `127.0.0.1` and the
app treats Apache as an untrusted peer, ignores `X-Forwarded-For`, and every
device sits behind "172.30.0.1" — so per-device IP allowlisting fails closed
and refuses all of them. The reasoning is in
[README → Deploying behind Apache](README.md#deploying-behind-apache-public-internet)
and [SECURITY.md](SECURITY.md).

The Apache vhost itself
([`deploy/apache/zkteco-sync.conf.example`](deploy/apache/zkteco-sync.conf.example))
needs no change: it still proxies to `127.0.0.1:8000`, which is where compose
publishes the container.

## Using a database you already have

The same compose file works without the bundled MariaDB. In `.env`, point
`DB_ENGINE`/`DB_HOST`/`DB_PORT` at your server as you would natively — from
inside the container this machine is reachable as `host.docker.internal`
(compose maps that name to the host), so a MariaDB or PostgreSQL on the
Docker host is `DB_HOST=host.docker.internal`. It has to listen on an
interface the container can reach: a server bound only to `127.0.0.1` will
not be. Then start only the app:

```bash
docker compose up -d --build --no-deps app
```

Connections from the container arrive at your database from the compose
subnet (`172.30.0.0/24`), so the account needs to be allowed from there
(`'zkteco'@'172.30.0.%'` in MariaDB terms).

### SQL Server

The default image is Alpine-based and does not carry Microsoft's ODBC
driver. Build the `runtime-mssql` target instead (Debian + ODBC Driver 18;
installing it accepts Microsoft's EULA), and set the driver name in `.env`:

```bash
# .env
DB_ENGINE=mssql
DB_ODBC_DRIVER=ODBC Driver 18 for SQL Server

ZK_TARGET=runtime-mssql docker compose up -d --build --no-deps app
```

Windows Authentication (`Trusted_Connection`) is not available from a Linux
container; use a SQL login.

## Prebuilt images

[`.github/workflows/docker.yml`](.github/workflows/docker.yml) publishes to
GitHub Container Registry on every `v*` tag (and `:edge` from `main`), for
`linux/amd64` and `linux/arm64`:

```
ghcr.io/<owner>/zkteco_sync:<version>          Alpine (default)
ghcr.io/<owner>/zkteco_sync:<version>-mssql    Debian + ODBC Driver 18
```

To run one instead of building, edit the `image:` line in
`docker-compose.yml` to point at it and drop `--build`.

## The image

```
docker build -t zkteco-sync .                                # ~210 MB
docker build --target runtime-mssql -t zkteco-sync:mssql .   # ~335 MB
```

- Three-stage build. `frontend` (Node) and `deps` (uv) are throwaway; only
  `frontend/dist` and the `/opt/venv` virtualenv are copied into a runtime
  stage that contains nothing else — no Node, no uv, no package-manager
  state, no compiler.
- Every Python dependency installs from a prebuilt wheel (musl and glibc,
  amd64 and arm64, all pinned in `uv.lock`), so no stage compiles anything
  and the default build never runs `apk`/`apt` at all. A rebuild with only
  application code changed takes seconds: the dependency layer is cached
  until `uv.lock` changes, and `npm`/`uv` caches persist across builds via
  BuildKit cache mounts.
- Bytecode is precompiled at build time (`UV_COMPILE_BYTECODE=1`), so
  startup is fast and the running container never needs to write to the
  image.
- Runs as an unprivileged user. Nothing is written to disk; logs go to
  stdout (`docker compose logs`).
- `HEALTHCHECK` calls `GET /healthz` through
  [`docker/healthcheck.py`](docker/healthcheck.py), which sends the first
  `ALLOWED_HOSTS` entry as the `Host` header — a plain `curl localhost` would
  be rejected by the host check and report the container unhealthy forever.
  `/healthz` says nothing but `{"status":"ok"}` and is hidden from OpenAPI.
- `.env` is never baked into the image (`.dockerignore`); compose hands it to
  the container at run time.

## Useful commands

```bash
docker compose run --rm --no-deps app python -m unittest discover -s tests   # test suite (in-memory SQLite)
docker compose exec db mariadb -u"$DB_USER" -p "$DB_NAME"                    # SQL shell on the bundled DB
docker compose logs -f app                                                   # application log
docker compose down                                                          # stop; keeps the database volume
docker compose down -v                                                       # stop AND delete the database
```
