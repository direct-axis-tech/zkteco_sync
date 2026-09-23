"""Container liveness probe for the HEALTHCHECK instruction.

Sends a Host header the app will accept: TrustedHostMiddleware rejects any
request whose Host is not in ALLOWED_HOSTS, and in production that list is
required, so a plain `curl localhost` would report the container unhealthy
forever. The first configured hostname is used; with none configured the app
itself falls back to accepting localhost.
"""

import os
import sys
import urllib.request

port = os.getenv("APP_PORT", "8000")
hosts = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()]
host = hosts[0] if hosts else "localhost"

req = urllib.request.Request(
    f"http://127.0.0.1:{port}/healthz", headers={"Host": host}
)
try:
    with urllib.request.urlopen(req, timeout=4) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except Exception as exc:  # noqa: BLE001 — any failure means "unhealthy"
    print(f"unhealthy: {exc}", file=sys.stderr)
    sys.exit(1)
