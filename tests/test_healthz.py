"""The container liveness probe: GET /healthz on the fully assembled app.

Run alongside the rest of the suite:

    python -m unittest discover -s tests -v

This is the one test that imports app.main, because what it guards is the
wiring, not a router: /healthz must sit *inside* TrustedHostMiddleware (a
probe is not a licence to skip the Host check) and must answer with nothing
an anonymous caller could use. docker/healthcheck.py relies on exactly the
contract pinned here — a 200 with a valid Host, a 400 without one.

Importing app.main builds the SQLAlchemy engine from .env but never connects
(schema creation lives in the lifespan, which TestClient only runs inside a
`with` block, and this test deliberately never enters one).
"""

import os
import unittest

# Same guard as the other suites: keep the import off the production
# fail-fast path regardless of what .env says. load_dotenv() does not
# override variables that are already set.
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "x" * 48)
os.environ.setdefault("DEFAULT_DEVICE_TIMEZONE", "Asia/Dubai")

from fastapi.testclient import TestClient  # noqa: E402

from app import config                      # noqa: E402
from app.main import app                    # noqa: E402


class HealthzTests(unittest.TestCase):
    def setUp(self):
        # The same Host selection docker/healthcheck.py makes: the first
        # configured hostname, or localhost when none is (app/main.py falls
        # back to the loopback names in that case).
        host = (config.ALLOWED_HOSTS or ["localhost"])[0]
        self.client = TestClient(app, base_url=f"http://{host}")

    def tearDown(self):
        self.client.close()

    def test_ok_with_valid_host(self):
        resp = self.client.get("/healthz")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})

    def test_says_nothing_else(self):
        # No version, no database state, no hostnames: an unauthenticated
        # endpoint on a public-internet deployment must not describe itself.
        self.assertEqual(set(self.client.get("/healthz").json()), {"status"})

    def test_rejected_with_unknown_host(self):
        # Why healthcheck.py bothers with a Host header at all.
        resp = self.client.get("/healthz", headers={"Host": "not-in-allowed-hosts.invalid"})
        self.assertEqual(resp.status_code, 400)

    def test_not_in_openapi(self):
        self.assertNotIn("/healthz", app.openapi()["paths"])


if __name__ == "__main__":
    unittest.main()
