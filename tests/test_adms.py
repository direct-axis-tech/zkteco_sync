"""Wire-protocol fixture tests for the ADMS (`/iclock/*`) endpoints.

Run with the standard library only — no pytest, no new dependency:

    python -m unittest discover -s tests -v

Why these exist at all. Two production attendance devices depend on the exact
bytes of one handshake reply, and the change these tests guard adds a *second*
protocol alongside it. The failure mode that matters is not a crash: it is a
device that registers, reports healthy, shows green, and silently discards
every punch — which is precisely what the previous

    if table != "ATTLOG":
        return PlainTextResponse(content="OK")

did to a Security-protocol `rtlog` push. So the assertions here are about
exact bytes and about data actually landing in the database, not about status
codes alone.

The suite runs entirely against a throwaway in-memory SQLite database. It
never touches MariaDB, and it never reads or writes a live device, user or
configuration row.
"""

import hashlib
import os
import unittest
from datetime import datetime

# Set before importing anything from `app`: app.config and app.database both
# call load_dotenv(), which does NOT override variables that are already set,
# so this keeps the suite off the operator's real database and out of the
# production fail-fast path regardless of what .env happens to say.
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "x" * 48)
# Pinned so the timezone assertions below do not depend on what the
# operator happens to have in .env.
os.environ.setdefault("DEFAULT_DEVICE_TIMEZONE", "Asia/Dubai")

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402
from sqlalchemy import create_engine, inspect, text            # noqa: E402
from sqlalchemy.orm import sessionmaker                        # noqa: E402
from sqlalchemy.pool import StaticPool                         # noqa: E402

from app import config                                         # noqa: E402
from app.database import Base, get_db                          # noqa: E402
from app.models import (                                       # noqa: E402
    AdmsPairing, AttendanceLog, BiometricTemplate, Device, DeviceEmployee, Employee,
)
from app.routers import adms                                   # noqa: E402
from app.services import employee_sync                         # noqa: E402


# The legacy Attendance PUSH handshake reply, recovered from
# `git show HEAD:app/routers/adms.py` rather than retyped, and pinned here by
# both its literal text and its digest. Two live devices
# (ESY4241100079, CQZ7230961348) parse this string. If a change to adms.py
# makes this test fail, the change is wrong — not the test.
LEGACY_BLOCK_TEMPLATE = (
    "GET OPTION FROM: {sn}\n"
    "ATTLOGStamp=9999\n"
    "OPERLOGStamp=9999\n"
    "ATTPHOTOStamp=None\n"
    "ErrorDelay=30\n"
    "Delay=10\n"
    "TransTimes=00:00;14:05\n"
    "TransInterval=1\n"
    "TransFlag=1111000000\n"
    "TimeZone=0\n"
    "Realtime=1\n"
    "Encrypt=None"
)

# SHA-256 of the block as served to ESY4241100079. This same digest was
# recorded independently by an earlier unit (D8) after verifying the wire
# format was unchanged, so it is a cross-check against two separate readings
# of the original code.
LEGACY_BLOCK_SHA256 = "d412946d1b53bdf811b9d72af25075651232f62d4deec76e73a872c69adb8f7b"

LEGACY_SN = "ESY4241100079"
LEGACY_SN_2 = "CQZ7230961348"
ACC_SN = "VGU6254600603"


class AdmsTestCase(unittest.TestCase):
    """A fresh in-memory database and a client per test."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,   # one shared connection, so ":memory:" persists
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        # Only the ADMS router, so route-ordering behaviour (in particular the
        # catch-all) is exercised exactly as it is registered in app/main.py.
        app = FastAPI()
        app.include_router(adms.router)

        def _override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        # A real routable source address: client_ip() falls back to the peer,
        # and TestClient's default peer ("testclient") is not an IP at all.
        self.client = TestClient(app, client=("203.0.113.10", 40000))

    def tearDown(self):
        self.client.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    # -- helpers ---------------------------------------------------------

    def add_device(self, serial, **kwargs):
        fields = dict(
            serial_number=serial,
            ip_address="203.0.113.10",
            port=4370,
            name="Test Device",
            status="approved",
        )
        fields.update(kwargs)
        db = self.Session()
        try:
            device = Device(**fields)
            db.add(device)
            db.commit()
        finally:
            db.close()

    def get_device(self, serial):
        db = self.Session()
        try:
            return db.query(Device).filter_by(serial_number=serial).first()
        finally:
            db.close()

    def attendance_rows(self):
        db = self.Session()
        try:
            return db.query(AttendanceLog).order_by(AttendanceLog.id).all()
        finally:
            db.close()

    def employees(self):
        db = self.Session()
        try:
            return {e.user_id: e for e in db.query(Employee).all()}
        finally:
            db.close()

    def templates(self):
        """All BiometricTemplate rows, keyed the same way the table is."""
        db = self.Session()
        try:
            return {
                (t.user_id, t.type, t.no): t
                for t in db.query(BiometricTemplate).all()
            }
        finally:
            db.close()

    def device_links(self, serial):
        db = self.Session()
        try:
            return {
                d.user_id: d
                for d in db.query(DeviceEmployee).filter_by(device_sn=serial).all()
            }
        finally:
            db.close()

    def add_employee(self, user_id, **kwargs):
        """A pre-existing employee row — an operator-entered one, typically."""
        fields = dict(user_id=user_id, name="", privilege=0, card="0")
        fields.update(kwargs)
        db = self.Session()
        try:
            db.add(Employee(**fields))
            db.commit()
        finally:
            db.close()


# ---------------------------------------------------------------------------
# 1. The legacy block, byte for byte
# ---------------------------------------------------------------------------

class LegacyHandshakeRegressionTests(AdmsTestCase):
    """The regression guard for the two live production devices."""

    def test_legacy_handshake_is_byte_for_byte_unchanged(self):
        self.add_device(LEGACY_SN)
        response = self.client.get(f"/iclock/cdata?SN={LEGACY_SN}&options=all")

        self.assertEqual(response.status_code, 200)
        expected = LEGACY_BLOCK_TEMPLATE.format(sn=LEGACY_SN)
        self.assertEqual(response.text, expected)
        self.assertEqual(
            hashlib.sha256(response.content).hexdigest(), LEGACY_BLOCK_SHA256
        )
        # No trailing newline, and the length the original code produced.
        self.assertEqual(len(response.content), 202)
        self.assertFalse(response.text.endswith("\n"))

    def test_second_production_serial_gets_the_same_block(self):
        self.add_device(LEGACY_SN_2)
        response = self.client.get(f"/iclock/cdata?SN={LEGACY_SN_2}&options=all")
        self.assertEqual(response.text, LEGACY_BLOCK_TEMPLATE.format(sn=LEGACY_SN_2))

    def test_pushver_3_alone_does_not_flip_a_device_to_acc(self):
        """The discriminator must not misfire on a legacy serial.

        `pushver` is optional and attendance devices send it too — the
        Attendance protocol's own example is pushver=2.2.14 — so a 3.x value
        on its own is not evidence of anything. This is the single most
        dangerous way the change could break the two production devices.
        """
        self.add_device(LEGACY_SN)
        for pushver in ("2.2.14", "3.1.2", "3.2.0"):
            with self.subTest(pushver=pushver):
                response = self.client.get(
                    f"/iclock/cdata?SN={LEGACY_SN}&options=all&pushver={pushver}"
                )
                self.assertEqual(
                    response.text, LEGACY_BLOCK_TEMPLATE.format(sn=LEGACY_SN)
                )
                self.assertEqual(self.get_device(LEGACY_SN).protocol, "att")

    def test_pushoptionsflag_alone_does_not_flip_a_device_to_acc(self):
        self.add_device(LEGACY_SN)
        response = self.client.get(
            f"/iclock/cdata?SN={LEGACY_SN}&options=all&PushOptionsFlag=1&language=83"
        )
        self.assertEqual(response.text, LEGACY_BLOCK_TEMPLATE.format(sn=LEGACY_SN))
        self.assertEqual(self.get_device(LEGACY_SN).protocol, "att")

    def test_new_devices_default_to_att(self):
        self.add_device(LEGACY_SN)
        self.assertEqual(self.get_device(LEGACY_SN).protocol, "att")

    def test_attlog_push_is_unchanged(self):
        """The legacy punch path must keep parsing and keep answering OK."""
        self.add_device(LEGACY_SN)
        body = "1001\t2026-08-20 09:15:00\t0\t1\n1002\t2026-08-20 09:16:30\t1\t15\n"
        response = self.client.post(
            f"/iclock/cdata?SN={LEGACY_SN}&table=ATTLOG", content=body
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "OK")

        rows = self.attendance_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].user_id, "1001")
        self.assertEqual(rows[0].timestamp.replace(tzinfo=None),
                         datetime(2026, 8, 20, 9, 15, 0))
        self.assertEqual(rows[0].status, 0)
        self.assertEqual(rows[0].punch, 1)
        self.assertEqual(rows[0].source, "adms_push")
        # The Security-protocol provenance columns stay empty on legacy rows.
        self.assertIsNone(rows[0].event_code)
        self.assertIsNone(rows[0].verify_type)
        self.assertIsNone(rows[0].record_index)

    def test_operlog_still_returns_bare_ok_without_parsing(self):
        self.add_device(LEGACY_SN)
        response = self.client.post(
            f"/iclock/cdata?SN={LEGACY_SN}&table=OPERLOG", content="OPLOG 1\t2\t3\n"
        )
        self.assertEqual(response.text, "OK")
        self.assertEqual(self.attendance_rows(), [])

    def test_attlog_push_demotes_a_stale_acc_classification(self):
        """A terminal converted back to T&A mode recovers on its own."""
        self.add_device(LEGACY_SN, protocol="acc")
        self.client.post(
            f"/iclock/cdata?SN={LEGACY_SN}&table=ATTLOG",
            content="1001\t2026-08-20 09:15:00\t0\t1\n",
        )
        self.assertEqual(self.get_device(LEGACY_SN).protocol, "att")


# ---------------------------------------------------------------------------
# 2. The new `acc` replies, against the spec's literals
# ---------------------------------------------------------------------------

class AccHandshakeTests(AdmsTestCase):

    def test_devicetype_acc_returns_the_registry_block(self):
        """The exact shape from the protocol document's §2 literal."""
        self.add_device(ACC_SN)
        response = self.client.get(
            f"/iclock/cdata?SN={ACC_SN}&options=all&pushver=3.1.2"
            f"&DeviceType=acc&PushOptionsFlag=1"
        )
        self.assertEqual(response.status_code, 200)

        lines = response.text.split("\n")
        device = self.get_device(ACC_SN)

        self.assertEqual(lines[0], "registry=ok")
        self.assertEqual(lines[1], f"RegistryCode={device.registry_code}")
        self.assertEqual(lines[2], "ServerVersion=3.1.2")
        self.assertEqual(lines[3], "ServerName=ADMS")
        # Both spellings are emitted deliberately: they are the same field
        # under two names and ZKTeco's own server picks between them by the
        # device's MachineType, which is not known until after the device has
        # already had to read this block.
        self.assertEqual(lines[4], "PushProtVer=3.1.2")
        self.assertEqual(lines[5], "PushVersion=3.1.2")
        self.assertEqual(lines[6], "ErrorDelay=30")
        self.assertEqual(lines[7], "RequestDelay=10")
        self.assertEqual(lines[8], "TransTimes=00:00;14:05")
        self.assertEqual(lines[9], "TransInterval=1")
        self.assertEqual(lines[10], "TransTables=User Transaction")
        self.assertEqual(lines[11], "Realtime=1")
        self.assertEqual(lines[12], f"SessionID={device.session_id}")
        self.assertEqual(lines[13], "TimeoutSec=10")
        self.assertEqual(len(lines), 14)
        self.assertFalse(response.text.endswith("\n"))

        # A RegistryCode is what stops the registration loop; a device that
        # does not find one here goes back round.
        self.assertIn("RegistryCode=", response.text)
        self.assertTrue(device.registry_code)
        self.assertLessEqual(len(device.registry_code), 32)
        self.assertEqual(len(device.session_id), 32)

    def test_acc_handshake_carries_none_of_the_legacy_keys(self):
        """Keys the Security protocol does not define must not leak across."""
        self.add_device(ACC_SN)
        body = self.client.get(
            f"/iclock/cdata?SN={ACC_SN}&options=all&DeviceType=acc"
        ).text
        for key in ("ATTLOGStamp", "OPERLOGStamp", "ATTPHOTOStamp",
                    "TransFlag", "Encrypt", "TimeZone", "GET OPTION FROM"):
            self.assertNotIn(key, body)

    def test_registry_code_and_session_id_are_stable_across_requests(self):
        """The device derives its token from these; they must not churn."""
        self.add_device(ACC_SN)
        first = self.client.get(f"/iclock/cdata?SN={ACC_SN}&options=all&DeviceType=acc").text
        second = self.client.get(f"/iclock/cdata?SN={ACC_SN}&options=all&DeviceType=acc").text
        self.assertEqual(first, second)

    def test_classification_is_sticky_when_devicetype_is_omitted(self):
        self.add_device(ACC_SN)
        self.client.get(f"/iclock/cdata?SN={ACC_SN}&options=all&DeviceType=acc")
        self.assertEqual(self.get_device(ACC_SN).protocol, "acc")

        # Same device, no DeviceType this time — must not fall back to legacy.
        response = self.client.get(f"/iclock/cdata?SN={ACC_SN}&options=all")
        self.assertTrue(response.text.startswith("registry=ok"))

    def test_explicit_devicetype_att_outranks_a_sticky_acc_column(self):
        """Converting a terminal to T&A mode must be recoverable."""
        self.add_device(ACC_SN, protocol="acc")
        response = self.client.get(
            f"/iclock/cdata?SN={ACC_SN}&options=all&DeviceType=att"
        )
        self.assertEqual(response.text, LEGACY_BLOCK_TEMPLATE.format(sn=ACC_SN))

    def test_devicetype_matching_is_case_insensitive(self):
        self.add_device(ACC_SN)
        response = self.client.get(f"/iclock/cdata?SN={ACC_SN}&options=all&devicetype=ACC")
        self.assertTrue(response.text.startswith("registry=ok"))


class RegistryEndpointTests(AdmsTestCase):

    # A real registration body, trimmed: one line of comma-separated pairs.
    REGISTRY_BODY = (
        "DeviceType=acc,~DeviceName=BioFace A1,FirmVer=Ver 8.0.1.3-20151229,"
        "PushVersion=Ver 2.0.22-20161201,CommType=ethernet,MaxPackageSize=2048000,"
        "LockCount=1,MachineType=101,FaceFunOn=1,FingerFunOn=1,"
        "MultiBioDataSupport=0:0:0:0:0:0:0:0:1:1,authKey=dassas"
    )

    def test_registry_returns_only_the_registry_code(self):
        self.add_device(ACC_SN)
        response = self.client.post(
            f"/iclock/registry?SN={ACC_SN}", content=self.REGISTRY_BODY
        )
        self.assertEqual(response.status_code, 200)

        code = self.get_device(ACC_SN).registry_code
        self.assertEqual(response.text, f"RegistryCode={code}")
        # The protocol's own example is Content-Length: 23 against the body
        # "RegistryCode=Uy47fxftP3" — i.e. no trailing newline at all.
        self.assertEqual(len(response.content), len(f"RegistryCode={code}"))
        self.assertNotIn("\n", response.text)
        # Returning a bare OK here is the documented way to reproduce the
        # registration loop this unit exists to fix.
        self.assertNotEqual(response.text, "OK")

    def test_registry_is_reachable_at_all(self):
        """The original defect: no route, so POST fell through to the SPA's
        StaticFiles mount, which serves GET/HEAD only and answers 405."""
        self.add_device(ACC_SN)
        response = self.client.post(f"/iclock/registry?SN={ACC_SN}", content="")
        self.assertNotEqual(response.status_code, 405)
        self.assertEqual(response.status_code, 200)

    def test_registry_marks_the_device_acc_and_stores_capabilities(self):
        self.add_device(ACC_SN)
        self.client.post(f"/iclock/registry?SN={ACC_SN}", content=self.REGISTRY_BODY)

        device = self.get_device(ACC_SN)
        self.assertEqual(device.protocol, "acc")
        self.assertEqual(device.capabilities, self.REGISTRY_BODY)
        self.assertTrue(device.registry_code)

    def test_registry_also_answers_get(self):
        self.add_device(ACC_SN)
        response = self.client.get(f"/iclock/registry?SN={ACC_SN}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.text.startswith("RegistryCode="))

    def test_registry_refuses_an_unapproved_serial_with_406(self):
        """Device trust still applies: a new protocol is not a way around it."""
        self.add_device(ACC_SN, status="pending")
        response = self.client.post(f"/iclock/registry?SN={ACC_SN}", content="")
        self.assertEqual(response.status_code, 406)
        self.assertEqual(response.text, "")
        self.assertFalse(self.get_device(ACC_SN).registry_code)

    def test_registry_refuses_an_unknown_serial_with_406(self):
        response = self.client.post("/iclock/registry?SN=NOSUCHSERIAL", content="")
        self.assertEqual(response.status_code, 406)

    def test_registry_refuses_a_source_outside_the_device_allowlist(self):
        self.add_device(
            ACC_SN, ip_check_enabled=True, allowed_cidrs="198.51.100.0/24"
        )
        response = self.client.post(f"/iclock/registry?SN={ACC_SN}", content="")
        self.assertEqual(response.status_code, 406)
        self.assertFalse(self.get_device(ACC_SN).protocol == "acc")

    def test_registry_accepts_a_source_inside_the_device_allowlist(self):
        self.add_device(
            ACC_SN, ip_check_enabled=True, allowed_cidrs="203.0.113.0/24"
        )
        response = self.client.post(f"/iclock/registry?SN={ACC_SN}", content="")
        self.assertEqual(response.status_code, 200)

    def test_registry_refusal_is_audited(self):
        self.add_device(ACC_SN, status="rejected")
        self.client.post(f"/iclock/registry?SN={ACC_SN}", content="")

        db = self.Session()
        try:
            rows = db.execute(
                text("SELECT actor, action, target FROM audit_logs")
            ).fetchall()
        finally:
            db.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "device")
        self.assertEqual(rows[0][1], "adms_refused")
        self.assertEqual(rows[0][2], ACC_SN)


class PushEndpointTests(AdmsTestCase):

    def test_push_returns_the_configuration_block(self):
        self.add_device(ACC_SN)
        response = self.client.post(f"/iclock/push?SN={ACC_SN}", content="")
        self.assertEqual(response.status_code, 200)

        device = self.get_device(ACC_SN)
        lines = response.text.split("\n")
        self.assertEqual(lines, [
            "ServerVersion=3.1.2",
            "ServerName=ADMS",
            "PushVersion=3.1.2",
            "PushProtVer=3.1.2",
            "ErrorDelay=30",
            "RequestDelay=10",
            "TransTimes=00:00;14:05",
            "TransInterval=1",
            "TransTables=User Transaction",
            "Realtime=1",
            f"SessionID={device.session_id}",
            "TimeoutSec=10",
        ])

    def test_push_always_carries_a_session_id(self):
        """The device derives its request token from this value."""
        self.add_device(ACC_SN)
        response = self.client.post(f"/iclock/push?SN={ACC_SN}", content="")
        self.assertIn("SessionID=", response.text)
        session_id = self.get_device(ACC_SN).session_id
        self.assertEqual(len(session_id), 32)
        self.assertIn(f"SessionID={session_id}", response.text)

    def test_push_answers_both_methods(self):
        """The protocol document's prose says GET, its own example shows POST."""
        self.add_device(ACC_SN)
        post = self.client.post(f"/iclock/push?SN={ACC_SN}", content="")
        get = self.client.get(f"/iclock/push?SN={ACC_SN}")
        self.assertEqual(post.status_code, 200)
        self.assertEqual(get.status_code, 200)
        self.assertEqual(post.text, get.text)

    def test_push_marks_the_device_acc(self):
        self.add_device(ACC_SN)
        self.client.post(f"/iclock/push?SN={ACC_SN}", content="")
        self.assertEqual(self.get_device(ACC_SN).protocol, "acc")

    def test_push_refuses_an_unapproved_serial(self):
        self.add_device(ACC_SN, status="pending")
        response = self.client.post(f"/iclock/push?SN={ACC_SN}", content="")
        self.assertEqual(response.status_code, 401)


# ---------------------------------------------------------------------------
# 3. rtlog parsing
# ---------------------------------------------------------------------------

class RtlogTests(AdmsTestCase):

    def post_rtlog(self, body, sn=ACC_SN):
        return self.client.post(f"/iclock/cdata?SN={sn}&table=rtlog", content=body)

    def setUp(self):
        super().setUp()
        self.add_device(ACC_SN, protocol="acc")

    def test_a_punch_becomes_an_attendance_row(self):
        body = (
            "time=2026-08-20 09:15:32\tpin=1001\tcardno=0\tsitecode=0\tlinkid=0\t"
            "eventaddr=1\tevent=0\tinoutstatus=0\tverifytype=1\tindex=21\n"
        )
        response = self.post_rtlog(body)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "OK")

        rows = self.attendance_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.device_sn, ACC_SN)
        self.assertEqual(row.user_id, "1001")
        self.assertEqual(row.timestamp.replace(tzinfo=None),
                         datetime(2026, 8, 20, 9, 15, 32))
        # inoutstatus (0=In, 1=Out) is the direction, which is what `status`
        # means in this schema and what the HRM push sends as its direction
        # field. verifytype is the verification mode, which is `punch`.
        self.assertEqual(row.status, 0)
        self.assertEqual(row.punch, 1)
        self.assertEqual(row.source, "adms_push")
        # Opaque provenance, stored rather than interpreted.
        self.assertEqual(row.event_code, "0")
        self.assertEqual(row.verify_type, "1")
        self.assertEqual(row.record_index, "21")

    def test_inoutstatus_out_maps_to_status_1(self):
        self.post_rtlog(
            "time=2026-08-20 17:02:00\tpin=1001\tevent=0\tinoutstatus=1\t"
            "verifytype=1\tindex=99\n"
        )
        self.assertEqual(self.attendance_rows()[0].status, 1)

    def test_multiple_records_in_one_push(self):
        body = (
            "time=2026-08-20 09:15:32\tpin=1001\tevent=0\tinoutstatus=0\tindex=21\n"
            "time=2026-08-20 09:16:02\tpin=1002\tevent=0\tinoutstatus=0\tindex=22\n"
            "time=2026-08-20 09:17:44\tpin=1003\tevent=0\tinoutstatus=0\tindex=23\n"
        )
        self.post_rtlog(body)
        rows = self.attendance_rows()
        self.assertEqual([r.user_id for r in rows], ["1001", "1002", "1003"])
        self.assertEqual([r.record_index for r in rows], ["21", "22", "23"])

    def test_fields_are_parsed_by_key_not_by_position(self):
        """Field count and order vary by firmware revision, so position is
        never safe: sitecode/linkid arrived in one revision and
        maskflag/temperature/convtemperature in another."""
        body = (
            "index=77\tverifytype=15\tpin=2002\tmaskflag=1\ttemperature=36.6\t"
            "convtemperature=0\tevent=0\tinoutstatus=1\ttime=2026-08-20 10:00:00\t"
            "cardno=12345\tsitecode=2\tlinkid=0\teventaddr=1\n"
        )
        self.post_rtlog(body)
        row = self.attendance_rows()[0]
        self.assertEqual(row.user_id, "2002")
        self.assertEqual(row.timestamp.replace(tzinfo=None),
                         datetime(2026, 8, 20, 10, 0, 0))
        self.assertEqual(row.status, 1)
        self.assertEqual(row.punch, 15)
        self.assertEqual(row.record_index, "77")

    def test_dedup_on_device_sn_and_index_across_pushes(self):
        """`index` is the device's own unique record ID — a replayed batch
        must not duplicate rows."""
        body = (
            "time=2026-08-20 09:15:32\tpin=1001\tevent=0\tinoutstatus=0\tindex=21\n"
        )
        self.post_rtlog(body)
        self.post_rtlog(body)
        self.post_rtlog(body)
        self.assertEqual(len(self.attendance_rows()), 1)

    def test_dedup_on_index_within_a_single_push(self):
        body = (
            "time=2026-08-20 09:15:32\tpin=1001\tevent=0\tinoutstatus=0\tindex=21\n"
            "time=2026-08-20 09:15:32\tpin=1001\tevent=0\tinoutstatus=0\tindex=21\n"
        )
        self.post_rtlog(body)
        self.assertEqual(len(self.attendance_rows()), 1)

    def test_the_same_index_from_a_different_device_is_a_different_record(self):
        """The dedup key is (device_sn, index), not index alone — every device
        numbers its own records from 1."""
        self.add_device("OTHERDEVICE01", protocol="acc")
        record = "time=2026-08-20 09:15:32\tpin=1001\tevent=0\tinoutstatus=0\tindex=21\n"
        self.post_rtlog(record)
        # Same index, same pin, different serial and a distinct timestamp so
        # the (device, user, timestamp) constraint is not what separates them.
        self.post_rtlog(
            "time=2026-08-20 09:15:40\tpin=1001\tevent=0\tinoutstatus=0\tindex=21\n",
            sn="OTHERDEVICE01",
        )
        rows = self.attendance_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual({r.device_sn for r in rows}, {ACC_SN, "OTHERDEVICE01"})

    def test_pin_zero_is_a_device_event_not_a_punch(self):
        """Start-up, door sensor, auxiliary input and remote operations all
        carry pin=0 because no person is involved."""
        body = (
            "time=2026-08-20 08:00:00\tpin=0\tcardno=0\teventaddr=1\tevent=27\t"
            "inoutstatus=1\tverifytype=0\tindex=1\n"
        )
        response = self.post_rtlog(body)
        self.assertEqual(response.text, "OK")
        self.assertEqual(self.attendance_rows(), [])

    def test_device_events_do_not_suppress_real_punches_in_the_same_push(self):
        body = (
            "time=2026-08-20 08:00:00\tpin=0\tevent=27\tinoutstatus=1\tindex=1\n"
            "time=2026-08-20 09:15:32\tpin=1001\tevent=0\tinoutstatus=0\tindex=2\n"
            "time=2026-08-20 08:00:05\tpin=0\tevent=28\tinoutstatus=1\tindex=3\n"
        )
        self.post_rtlog(body)
        rows = self.attendance_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].user_id, "1001")

    def test_an_unknown_event_code_is_stored_not_filtered(self):
        """Which event codes mean 'valid punch' is unverified, so the filter
        is `pin != 0` and the code is recorded. An abnormal event counted as a
        punch is visible and correctable; a real punch dropped by a wrong
        allow-list is silent and unrecoverable."""
        body = (
            "time=2026-08-20 09:15:32\tpin=1001\tevent=203\tinoutstatus=0\t"
            "verifytype=1\tindex=44\n"
        )
        self.post_rtlog(body)
        rows = self.attendance_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].event_code, "203")

    def test_a_bitmask_verifytype_is_not_coerced_into_a_wrong_verify_mode(self):
        """3.1.2 may report face verification as `0000000000000010`.
        int() would turn that into 10 — a different, real legacy verify mode —
        so the raw string is kept and `punch` is left at 0."""
        body = (
            "time=2026-08-20 09:15:32\tpin=1001\tevent=0\tinoutstatus=0\t"
            "verifytype=0000000000000010\tindex=55\n"
        )
        self.post_rtlog(body)
        row = self.attendance_rows()[0]
        self.assertEqual(row.verify_type, "0000000000000010")
        self.assertEqual(row.punch, 0)
        self.assertNotEqual(row.punch, 10)

    def test_an_unreadable_timestamp_drops_only_that_record_and_logs_an_error(self):
        body = (
            "time=not-a-timestamp\tpin=1001\tevent=0\tinoutstatus=0\tindex=60\n"
            "time=2026-08-20 09:15:32\tpin=1002\tevent=0\tinoutstatus=0\tindex=61\n"
        )
        with self.assertLogs("app.routers.adms", level="ERROR") as captured:
            response = self.post_rtlog(body)
        self.assertEqual(response.text, "OK")
        self.assertTrue(any("unreadable time" in line for line in captured.output))
        rows = self.attendance_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].user_id, "1002")

    def test_the_raw_body_is_logged_verbatim(self):
        """This log is the evidence that closes the event-code question."""
        body = (
            "time=2026-08-20 09:15:32\tpin=1001\tevent=0\tinoutstatus=0\tindex=21\n"
        )
        with self.assertLogs("app.routers.adms", level="INFO") as captured:
            self.post_rtlog(body)
        self.assertTrue(any("rtlog from" in line and "pin=1001" in line
                            for line in captured.output))

    def test_rtlog_from_an_unapproved_serial_is_refused_and_stores_nothing(self):
        self.add_device("PENDING00001", status="pending")
        response = self.client.post(
            "/iclock/cdata?SN=PENDING00001&table=rtlog",
            content="time=2026-08-20 09:15:32\tpin=1001\tevent=0\tindex=21\n",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.attendance_rows(), [])

    def test_an_empty_rtlog_body_is_acknowledged(self):
        response = self.post_rtlog("")
        self.assertEqual(response.text, "OK")
        self.assertEqual(self.attendance_rows(), [])


# ---------------------------------------------------------------------------
# 4. The unknown-table trap
# ---------------------------------------------------------------------------

class TableDispatchTests(AdmsTestCase):

    def setUp(self):
        super().setUp()
        self.add_device(ACC_SN, protocol="acc")

    def test_an_unknown_table_is_acknowledged_and_logged_not_discarded(self):
        """The exact trap this unit exists to avoid.

        The old handler answered OK to anything that was not ATTLOG and never
        read the body, so a device could push data forever and leave no trace
        of it anywhere. Acknowledging is right — a non-2xx would put the
        device into a retry loop — but the body must survive into the log.
        """
        body = "somefield=1\tanother=2\tpayload=important\n"
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.client.post(
                f"/iclock/cdata?SN={ACC_SN}&table=somethingnew", content=body
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "OK")

        joined = "\n".join(captured.output)
        self.assertIn("unhandled table", joined)
        self.assertIn("somethingnew", joined)
        self.assertIn(ACC_SN, joined)
        # The body itself — not just the fact that there was one.
        self.assertIn("payload=important", joined)

    def test_an_absent_table_parameter_still_answers_ok(self):
        response = self.client.post(f"/iclock/cdata?SN={ACC_SN}", content="junk")
        self.assertEqual(response.text, "OK")

    def test_rtstate_is_acknowledged(self):
        response = self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=rtstate",
            content="time=2026-08-20 09:00:00\tsensor=AABB\trelay=CC\talarm=00\n",
        )
        self.assertEqual(response.text, "OK")

    def test_options_is_acknowledged_and_stores_the_capability_line(self):
        line = "DeviceType=acc,MachineType=101,FaceFunOn=1,~MaxUserCount=3000"
        response = self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=options", content=line
        )
        self.assertEqual(response.text, "OK")
        self.assertEqual(self.get_device(ACC_SN).capabilities, line)

    def test_tabledata_is_acknowledged_with_tablename_equals_count(self):
        """Not OK — the device wants its own table name echoed back, and a
        device that does not see it is documented to retry forever."""
        response = self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=user&count=3",
            content="pin=1\tname=A\npin=2\tname=B\npin=3\tname=C\n",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "user=3")

    def test_tabledata_counts_records_when_the_count_parameter_is_missing(self):
        response = self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=biodata",
            content="pin=1\ttmp=xx\npin=2\ttmp=yy\n",
        )
        self.assertEqual(response.text, "biodata=2")

    def test_tabledata_errorlog_is_acknowledged(self):
        """Advertising PushProtVer=3.1.2 invites this table specifically."""
        response = self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=errorlog&count=1",
            content="errcode=5\terrmsg=whatever\n",
        )
        self.assertEqual(response.text, "errorlog=1")


# ---------------------------------------------------------------------------
# 4b. `tabledata&tablename=user` — employees arriving from the terminal
# ---------------------------------------------------------------------------

# The three records the operator's BioFace A1 actually sent, recovered from
# /Users/mufeedbinismail/Documents/zkteco-sync.log around 2026-08-20 10:39:50.
# The log had expanded every TAB to eight spaces and syslog had split the body
# on its LFs; both are undone here, so this constant is the wire bytes.
#
# Note what is in it: every `name=` is empty and every `cardno=` is empty. This
# is the normal shape of a user upload, not a degenerate one, and it is the
# case the merge rule exists for.
CAPTURED_USER_UPLOAD = (
    "user uid=1\tcardno=\tpin=1\tpassword=\tgroup=1\tstarttime=0\tendtime=0\t"
    "name=\tprivilege=14\tdisable=0\tverify=0\n"
    "user uid=2\tcardno=\tpin=2\tpassword=\tgroup=1\tstarttime=0\tendtime=0\t"
    "name=\tprivilege=14\tdisable=0\tverify=0\n"
    "user uid=3\tcardno=\tpin=3\tpassword=\tgroup=1\tstarttime=0\tendtime=0\t"
    "name=\tprivilege=0\tdisable=0\tverify=0\n"
)


class UserTableUploadTests(AdmsTestCase):
    """The ingest that makes an employee list appear from a NATted device."""

    def setUp(self):
        super().setUp()
        self.add_device(ACC_SN, protocol="acc")

    def post_users(self, body, count=None, serial=ACC_SN):
        url = f"/iclock/cdata?SN={serial}&table=tabledata&tablename=user"
        if count is not None:
            url += f"&count={count}"
        return self.client.post(url, content=body)

    # -- the captured payload -------------------------------------------

    def test_the_captured_upload_creates_every_record_it_declared(self):
        """count=3 means three employees, not one. The log kept one because
        _clip cut the body; the parser must not repeat that mistake."""
        response = self.post_users(CAPTURED_USER_UPLOAD, count=3)
        self.assertEqual(response.status_code, 200)

        employees = self.employees()
        self.assertEqual(sorted(employees), ["1", "2", "3"])
        self.assertEqual(
            [employees[p].privilege for p in ("1", "2", "3")], [14, 14, 0]
        )

    def test_the_acknowledgement_is_still_byte_exact(self):
        """The device retries the upload forever without this exact string,
        so ingesting must not have changed a byte of it."""
        response = self.post_users(CAPTURED_USER_UPLOAD, count=3)
        self.assertEqual(response.content, b"user=3")
        self.assertTrue(
            response.headers["content-type"].startswith("text/plain")
        )

    def test_the_acknowledgement_echoes_the_declared_count_not_the_stored_one(self):
        """`count` is the device's claim about its own upload. Echoing back
        what we managed to store instead would make a device that sent one
        unparseable record retry the whole batch indefinitely."""
        body = CAPTURED_USER_UPLOAD + "this is not a record\n"
        response = self.post_users(body, count=4)
        self.assertEqual(response.text, "user=4")
        self.assertEqual(len(self.employees()), 3)

    def test_a_device_link_is_recorded_with_the_device_local_uid(self):
        """Same shape the SDK pull writes: keyed on (device_sn, user_id),
        carrying the terminal's own slot number."""
        self.post_users(CAPTURED_USER_UPLOAD, count=3)
        links = self.device_links(ACC_SN)
        self.assertEqual(sorted(links), ["1", "2", "3"])
        self.assertEqual([links[p].uid for p in ("1", "2", "3")], [1, 2, 3])

    def test_an_unnamed_enrolment_is_stored_blank_not_invented(self):
        """The UI falls back to the PIN for an empty name. A placeholder that
        looked like a name would be a fact the device never reported."""
        self.post_users(CAPTURED_USER_UPLOAD, count=3)
        self.assertEqual(self.employees()["1"].name, "")

    # -- the merge rule ---------------------------------------------------

    def test_an_empty_incoming_name_does_not_clobber_an_existing_one(self):
        """The whole reason this ingest needs a merge rule rather than an
        overwrite: the operator types the names, and every upload the device
        sends carries `name=`."""
        self.add_employee("1", name="Aisha Rahman", card="0012345678", privilege=0)
        self.post_users(CAPTURED_USER_UPLOAD, count=3)

        emp = self.employees()["1"]
        self.assertEqual(emp.name, "Aisha Rahman")
        self.assertEqual(emp.card, "0012345678")
        # ...but a field the device *did* report still lands.
        self.assertEqual(emp.privilege, 14)

    def test_a_name_the_device_does_send_is_written(self):
        """The rule is fill-in-never-empty-out, not never-write."""
        self.add_employee("1", name="")
        self.post_users("user uid=1\tpin=1\tname=Yusuf Haddad\tprivilege=0\n", count=1)
        self.assertEqual(self.employees()["1"].name, "Yusuf Haddad")

    def test_a_card_number_reaches_the_row_for_the_hrm(self):
        self.post_users("user uid=4\tpin=4\tcardno=0012345678\tname=Lina\n", count=1)
        self.assertEqual(self.employees()["4"].card, "0012345678")

    def test_a_zero_card_does_not_erase_a_real_one(self):
        """`cardno=0` and `cardno=` are both "no card", and Employee.card
        defaults to "0" — none of the three may overwrite a card number."""
        self.add_employee("4", name="Lina", card="0012345678")
        self.post_users("user uid=4\tpin=4\tcardno=0\tname=\n", count=1)
        self.assertEqual(self.employees()["4"].card, "0012345678")

    def test_a_repeat_upload_is_idempotent(self):
        """Devices re-send their whole user list on reconnect. A replay must
        not duplicate rows, and must not even touch a row it cannot change."""
        self.post_users(CAPTURED_USER_UPLOAD, count=3)
        first = self.employees()
        stamps = {p: first[p].updated_at for p in first}

        response = self.post_users(CAPTURED_USER_UPLOAD, count=3)

        self.assertEqual(response.text, "user=3")
        again = self.employees()
        self.assertEqual(sorted(again), ["1", "2", "3"])
        self.assertEqual(len(self.device_links(ACC_SN)), 3)
        for pin, stamp in stamps.items():
            self.assertEqual(again[pin].updated_at, stamp, f"pin {pin} was rewritten")

    def test_the_same_pin_twice_in_one_batch_merges_rather_than_duplicating(self):
        body = (
            "user uid=9\tpin=9\tname=\tcardno=555\n"
            "user uid=9\tpin=9\tname=Omar Said\tcardno=\n"
        )
        self.post_users(body, count=2)
        employees = self.employees()
        self.assertEqual(sorted(employees), ["9"])
        self.assertEqual(employees["9"].name, "Omar Said")
        self.assertEqual(employees["9"].card, "555")

    # -- parsing ----------------------------------------------------------

    def test_fields_are_read_by_key_and_never_by_position(self):
        """Field order and field count vary across firmware revisions. A
        positional parse would put a card number in the name column."""
        body = (
            "user name=Sara Nasser\tprivilege=14\tpin=11\tcardno=778899\t"
            "uid=11\tsomethingnew=42\n"
        )
        self.post_users(body, count=1)
        emp = self.employees()["11"]
        self.assertEqual(emp.name, "Sara Nasser")
        self.assertEqual(emp.card, "778899")
        self.assertEqual(emp.privilege, 14)

    def test_the_table_name_prefix_is_optional(self):
        """Present on every captured record, but stripping it must not be the
        only way a record parses."""
        self.post_users("pin=12\tuid=12\tname=Noor\n", count=1)
        self.assertEqual(self.employees()["12"].name, "Noor")

    def test_a_malformed_record_is_skipped_and_logged_without_dropping_the_batch(self):
        body = (
            "user uid=1\tpin=1\tname=Aisha\n"
            "total garbage with no equals sign at all\n"
            "user uid=2\tname=Nobody\tprivilege=0\n"          # no pin
            "user uid=3\tpin=3\tname=Yusuf\n"
        )
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.post_users(body, count=4)

        self.assertEqual(response.text, "user=4")
        employees = self.employees()
        self.assertEqual(sorted(employees), ["1", "3"])
        self.assertEqual(employees["3"].name, "Yusuf")
        joined = "\n".join(captured.output)
        self.assertIn("total garbage", joined)

    def test_a_record_for_pin_zero_is_not_made_an_employee(self):
        """pin=0 is the device talking about itself, the same convention
        rtlog uses for door and tamper events."""
        with self.assertLogs("app.routers.adms", level="WARNING"):
            self.post_users("user uid=0\tpin=0\tname=\n", count=1)
        self.assertEqual(self.employees(), {})

    def test_an_empty_upload_is_acknowledged_and_stores_nothing(self):
        response = self.post_users("", count=0)
        self.assertEqual(response.text, "user=0")
        self.assertEqual(self.employees(), {})

    def test_two_devices_holding_the_same_person_share_one_employee_row(self):
        """user_id is the key, uid is per-device. Two terminals that both hold
        PIN 1 are two links to one person, not two people."""
        self.add_device("SECONDACC00001", protocol="acc")
        self.post_users("user uid=1\tpin=1\tname=Aisha\n", count=1)
        self.post_users("user uid=57\tpin=1\tname=\n", count=1, serial="SECONDACC00001")

        self.assertEqual(sorted(self.employees()), ["1"])
        self.assertEqual(self.employees()["1"].name, "Aisha")
        self.assertEqual(self.device_links(ACC_SN)["1"].uid, 1)
        self.assertEqual(self.device_links("SECONDACC00001")["1"].uid, 57)

    # -- what must NOT be ingested ---------------------------------------

    def test_biodata_does_not_create_an_employee_or_a_device_link(self):
        """`biodata` is E2's table (BiometricTemplate, see BiodataTableUploadTests
        below) — it must not become a second, implicit writer of `employees`
        or `device_employees`."""
        response = self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=biodata&count=2",
            content="biodata pin=1\tno=5\ttype=1\ttmp=apUBEBgEfAQBAA0AAVH4AAg\n",
        )
        self.assertEqual(response.text, "biodata=2")
        self.assertEqual(self.employees(), {})
        self.assertEqual(self.device_links(ACC_SN), {})

    def test_a_base64_table_is_summarised_in_the_log_rather_than_dumped(self):
        """A biophoto push is ~100 KB per record. The journal is not a blob
        store, and the operator still needs to see that it arrived."""
        blob = "A" * 40000
        with self.assertLogs("app.routers.adms", level="INFO") as captured:
            self.client.post(
                f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=biophoto&count=1",
                content=f"biophoto pin=1\tfilename=1.jpg\tcontent={blob}\n",
            )
        joined = "\n".join(captured.output)
        self.assertIn("not logged", joined)
        self.assertNotIn(blob, joined)

    def test_a_small_keyed_table_is_kept_whole_in_the_log(self):
        """The opposite failure: the captured `user` push was truncated to its
        first record, which is why nobody could tell whether names ever
        arrive. All three records must now reach the log."""
        with self.assertLogs("app.routers.adms", level="INFO") as captured:
            self.post_users(CAPTURED_USER_UPLOAD, count=3)
        joined = "\n".join(captured.output)
        self.assertIn("uid=1", joined)
        self.assertIn("uid=2", joined)
        self.assertIn("uid=3", joined)

    # -- failure containment ---------------------------------------------

    def test_a_storage_failure_still_acknowledges_so_the_device_stops_retrying(self):
        """An ingest bug must not turn into a device stuck in an upload loop."""
        def boom(*args, **kwargs):
            raise RuntimeError("simulated storage failure")

        original = adms._store_user_table
        adms._store_user_table = boom
        try:
            with self.assertLogs("app.routers.adms", level="ERROR"):
                response = self.post_users(CAPTURED_USER_UPLOAD, count=3)
        finally:
            adms._store_user_table = original

        self.assertEqual(response.content, b"user=3")

    def test_an_unapproved_serial_cannot_inject_employees(self):
        """The ingest sits behind _authorise like every other table."""
        response = self.post_users(CAPTURED_USER_UPLOAD, count=3, serial="NOTAPPROVED01")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.employees(), {})


# ---------------------------------------------------------------------------
# 4c. `tabledata&tablename=biodata` — biometric templates arriving verbatim
# ---------------------------------------------------------------------------

# The two records the operator's BioFace A1 actually sent for pin=1, recovered
# from /Users/mufeedbinismail/Documents/zkteco-sync.log around 2026-08-20
# 10:39:50 (`tmp` truncated here — the real one runs to a few KB of base64;
# only its exact survival across storage is being tested, not its content).
CAPTURED_BIODATA_UPLOAD = (
    "biodata pin=1\tno=5\tindex=0\tvalid=1\tduress=0\ttype=1\tmajorver=13\t"
    "minorver=0\tformat=0\ttmp=apUBEBgEfAQBAA0AAVH4AAgJCgs42CmiExIxE2A4o0xKdg==\n"
    "biodata pin=1\tno=0\tindex=0\tvalid=1\tduress=0\ttype=9\tmajorver=40\t"
    "minorver=1\tformat=0\ttmp=apUBFjYCAABuuOlOCQAoAQFM+ZoWAGJobX4kJSYnGSkqKw==\n"
)


class BiodataTableUploadTests(AdmsTestCase):
    """Biometric templates stored verbatim so E4 can later replay them."""

    def setUp(self):
        super().setUp()
        self.add_device(ACC_SN, protocol="acc")

    def post_biodata(self, body, count=None, serial=ACC_SN):
        url = f"/iclock/cdata?SN={serial}&table=tabledata&tablename=biodata"
        if count is not None:
            url += f"&count={count}"
        return self.client.post(url, content=body)

    # -- the captured payload ---------------------------------------------

    def test_the_captured_upload_stores_every_record(self):
        response = self.post_biodata(CAPTURED_BIODATA_UPLOAD, count=6)
        self.assertEqual(response.status_code, 200)

        templates = self.templates()
        self.assertEqual(sorted(templates), [("1", 1, 5), ("1", 9, 0)])

    def test_the_acknowledgement_is_byte_exact(self):
        """The device retries a multi-KB template upload forever without this
        exact string."""
        response = self.post_biodata(CAPTURED_BIODATA_UPLOAD, count=6)
        self.assertEqual(response.content, b"biodata=6")
        self.assertTrue(response.headers["content-type"].startswith("text/plain"))

    def test_the_acknowledgement_echoes_the_declared_count_not_the_stored_one(self):
        """count=6 was declared by the real device though only 2 records
        survived the log — the ack must reflect what was declared, not what
        this batch happened to contain."""
        response = self.post_biodata(CAPTURED_BIODATA_UPLOAD, count=6)
        self.assertEqual(response.text, "biodata=6")
        self.assertEqual(len(self.templates()), 2)

    # -- verbatim round-trip ------------------------------------------------

    def test_every_field_survives_verbatim_including_the_unused_ones(self):
        """duress, index, majorver, minorver and format have no use today —
        they still must reach the row exactly as sent, because E4 rebuilds
        `DATA UPDATE BIODATA` from these columns and nothing else."""
        body = (
            "biodata pin=7\tno=3\tindex=9\tvalid=1\tduress=1\ttype=1\t"
            "majorver=13\tminorver=2\tformat=1\ttmp=QUJDREVGRw==\n"
        )
        self.post_biodata(body, count=1)

        row = self.templates()[("7", 1, 3)]
        self.assertEqual(row.record_index, 9)
        self.assertEqual(row.valid, 1)
        self.assertEqual(row.duress, 1)
        self.assertEqual(row.majorver, 13)
        self.assertEqual(row.minorver, 2)
        self.assertEqual(row.format, 1)
        self.assertEqual(row.tmp, "QUJDREVGRw==")
        self.assertEqual(row.source_device_sn, ACC_SN)

        # Enough to reconstruct §3.8's DATA UPDATE BIODATA command, field for
        # field, from what is on the row.
        reconstructed = (
            f"Pin={row.user_id}\tNo={row.no}\tIndex={row.record_index}\t"
            f"Valid={row.valid}\tDuress={row.duress}\tType={row.type}\t"
            f"MajorVer={row.majorver}\tMinorVer={row.minorver}\t"
            f"Format={row.format}\tTmp={row.tmp}"
        )
        self.assertEqual(
            reconstructed,
            "Pin=7\tNo=3\tIndex=9\tValid=1\tDuress=1\tType=1\t"
            "MajorVer=13\tMinorVer=2\tFormat=1\tTmp=QUJDREVGRw==",
        )

    def test_fields_are_read_by_key_and_never_by_position(self):
        body = (
            "biodata tmp=WFla\tformat=0\tpin=21\tminorver=1\tno=2\ttype=9\t"
            "majorver=40\tvalid=1\tduress=0\tindex=0\n"
        )
        self.post_biodata(body, count=1)
        row = self.templates()[("21", 9, 2)]
        self.assertEqual(row.tmp, "WFla")
        self.assertEqual(row.majorver, 40)

    # -- upsert semantics -----------------------------------------------

    def test_a_repeat_upload_is_idempotent(self):
        """Devices resend their whole template set on reconnect. A replay
        must converge on the same rows, not accumulate duplicates."""
        self.post_biodata(CAPTURED_BIODATA_UPLOAD, count=6)
        first = self.templates()

        response = self.post_biodata(CAPTURED_BIODATA_UPLOAD, count=6)

        self.assertEqual(response.text, "biodata=6")
        again = self.templates()
        self.assertEqual(sorted(again), sorted(first))
        self.assertEqual(len(again), 2)

    def test_a_changed_tmp_on_reupload_updates_the_row_not_a_new_one(self):
        """Re-enrolling the same finger changes the template content but not
        its identity — the row must update in place."""
        self.post_biodata(
            "biodata pin=1\tno=5\ttype=1\ttmp=AAAA\n", count=1,
        )
        self.post_biodata(
            "biodata pin=1\tno=5\ttype=1\ttmp=BBBB\n", count=1,
        )
        templates = self.templates()
        self.assertEqual(len(templates), 1)
        self.assertEqual(templates[("1", 1, 5)].tmp, "BBBB")

    def test_the_same_record_twice_in_one_batch_merges_rather_than_duplicating(self):
        body = (
            "biodata pin=3\tno=1\ttype=1\ttmp=AAAA\n"
            "biodata pin=3\tno=1\ttype=1\ttmp=BBBB\n"
        )
        self.post_biodata(body, count=2)
        templates = self.templates()
        self.assertEqual(len(templates), 1)
        self.assertEqual(templates[("3", 1, 1)].tmp, "BBBB")

    # -- two modalities coexist -------------------------------------------

    def test_two_modalities_for_one_pin_coexist(self):
        """pin=1 in the real capture carries both a fingerprint (type=1,
        no=5) and a face (type=9, no=0) record — confirming (user_id, type,
        no) does not collide across modalities."""
        self.post_biodata(CAPTURED_BIODATA_UPLOAD, count=6)
        templates = self.templates()

        fingerprint = templates[("1", 1, 5)]
        face = templates[("1", 9, 0)]
        self.assertNotEqual(fingerprint.tmp, face.tmp)
        self.assertEqual(fingerprint.majorver, 13)
        self.assertEqual(face.majorver, 40)

    # -- malformed records ---------------------------------------------

    def test_a_malformed_record_is_skipped_and_logged_without_dropping_the_batch(self):
        body = (
            "biodata pin=1\tno=5\ttype=1\ttmp=AAAA\n"
            "total garbage with no equals sign at all\n"
            "biodata pin=2\tno=0\ttmp=BBBB\n"          # no type
            "biodata pin=\tno=0\ttype=1\ttmp=CCCC\n"    # no pin
            "biodata pin=4\tno=1\ttype=1\ttmp=\n"       # no tmp
            "biodata pin=5\tno=2\ttype=9\ttmp=DDDD\n"
        )
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.post_biodata(body, count=6)

        self.assertEqual(response.text, "biodata=6")
        templates = self.templates()
        self.assertEqual(sorted(templates), [("1", 1, 5), ("5", 9, 2)])
        joined = "\n".join(captured.output)
        self.assertIn("total garbage", joined)

    def test_an_unapproved_serial_cannot_inject_templates(self):
        response = self.post_biodata(
            CAPTURED_BIODATA_UPLOAD, count=6, serial="NOTAPPROVED01",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.templates(), {})

    def test_a_storage_failure_still_acknowledges_so_the_device_stops_retrying(self):
        def boom(*args, **kwargs):
            raise RuntimeError("simulated storage failure")

        original = adms._store_biodata_table
        adms._store_biodata_table = boom
        try:
            with self.assertLogs("app.routers.adms", level="ERROR"):
                response = self.post_biodata(CAPTURED_BIODATA_UPLOAD, count=6)
        finally:
            adms._store_biodata_table = original

        self.assertEqual(response.content, b"biodata=6")

    def test_biodata_upload_does_not_touch_employees_or_device_links(self):
        """Collision guard: this table must not become a second writer of
        `employees` or `device_employees`."""
        self.post_biodata(CAPTURED_BIODATA_UPLOAD, count=6)
        self.assertEqual(self.employees(), {})
        self.assertEqual(self.device_links(ACC_SN), {})


class SdkAndPushAgreeTests(AdmsTestCase):
    """The two transports write the same tables. They must converge.

    The SDK pull reaches a device over TCP 4370; the ADMS upload arrives over
    HTTP. A LAN device can be reachable both ways, and before this unit the
    poller wrote `employees` inline with its own overwrite-everything rule. If
    that had been left alone, a name would appear on one path and be erased on
    the other on the next poll, forever.
    """

    def setUp(self):
        super().setUp()
        self.add_device(ACC_SN, protocol="acc")

    def sdk_pull(self, serial, user_id, uid, name, privilege, card):
        """What poller.pull_employees now does per user from conn.get_users().

        pyzk hands back name="" and card=0 for an unnamed, card-less user —
        the same "nothing to say" the wire expresses as `name=` / `cardno=`.
        """
        db = self.Session()
        try:
            employee_sync.record_device_user(
                db, serial, user_id, uid=uid, name=name, privilege=privilege, card=card
            )
            db.commit()
        finally:
            db.close()

    def test_the_poller_calls_the_same_writer_as_the_push_ingest(self):
        """Not a behavioural assertion — a structural one. If someone adds a
        second writer to poller.py, this fails."""
        import inspect as _inspect
        from app.services import poller
        source = _inspect.getsource(poller.pull_employees)
        self.assertIn("employee_sync.record_device_user", source)
        self.assertNotIn("db.add(Employee(", source)
        self.assertNotIn("db.add(DeviceEmployee(", source)

    def test_an_sdk_pull_does_not_erase_a_name_the_push_ingest_stored(self):
        self.post = None
        self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=user&count=1",
            content="user uid=1\tpin=1\tname=Aisha Rahman\tcardno=778899\n",
        )
        self.sdk_pull(ACC_SN, "1", uid=1, name="", privilege=14, card=0)

        emp = self.employees()["1"]
        self.assertEqual(emp.name, "Aisha Rahman")
        self.assertEqual(emp.card, "778899")
        self.assertEqual(emp.privilege, 14)

    def test_a_push_ingest_does_not_erase_a_name_the_sdk_pull_stored(self):
        self.sdk_pull(ACC_SN, "1", uid=1, name="Aisha Rahman", privilege=14, card=778899)
        self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=user&count=1",
            content="user uid=1\tpin=1\tname=\tcardno=\tprivilege=14\n",
        )
        emp = self.employees()["1"]
        self.assertEqual(emp.name, "Aisha Rahman")
        self.assertEqual(emp.card, "778899")

    def test_alternating_transports_reach_a_fixed_point(self):
        """The flip-flop test. Ten alternations, one final state."""
        for _ in range(5):
            self.client.post(
                f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=user&count=1",
                content="user uid=1\tpin=1\tname=\tcardno=\tprivilege=14\n",
            )
            self.sdk_pull(ACC_SN, "1", uid=1, name="", privilege=14, card=0)

        employees = self.employees()
        self.assertEqual(sorted(employees), ["1"])
        self.assertEqual(len(self.device_links(ACC_SN)), 1)
        self.assertEqual(employees["1"].privilege, 14)

    def test_neither_transport_creates_a_second_device_link(self):
        self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=tabledata&tablename=user&count=1",
            content="user uid=1\tpin=1\tname=Aisha\n",
        )
        self.sdk_pull(ACC_SN, "1", uid=1, name="Aisha", privilege=0, card=0)

        db = self.Session()
        try:
            self.assertEqual(db.query(DeviceEmployee).count(), 1)
            self.assertEqual(db.query(Employee).count(), 1)
        finally:
            db.close()


# ---------------------------------------------------------------------------
# 5. The catch-all
# ---------------------------------------------------------------------------

class CatchAllTests(AdmsTestCase):

    def test_an_unknown_iclock_path_is_named_in_the_log(self):
        """The incident that produced this unit was a 405 with no diagnostic.
        The same event must now identify itself."""
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.client.post(
                "/iclock/service/control?SN=VGU6254600603", content="hello=world"
            )
        self.assertEqual(response.status_code, 404)
        joined = "\n".join(captured.output)
        self.assertIn("/iclock/service/control", joined)
        self.assertIn("POST", joined)
        self.assertIn("hello=world", joined)

    def test_the_catch_all_does_not_shadow_the_real_routes(self):
        """It is declared last, so every concrete route still wins."""
        self.add_device(LEGACY_SN)
        self.assertEqual(
            self.client.get(f"/iclock/cdata?SN={LEGACY_SN}&options=all").text,
            LEGACY_BLOCK_TEMPLATE.format(sn=LEGACY_SN),
        )
        self.assertEqual(self.client.get(f"/iclock/ping?SN={LEGACY_SN}").text, "OK")
        self.assertEqual(self.client.get(f"/iclock/getrequest?SN={LEGACY_SN}").text, "OK")
        self.assertEqual(
            self.client.post(f"/iclock/cdata?SN={LEGACY_SN}&table=ATTLOG", content="").text,
            "OK",
        )
        self.assertEqual(
            self.client.post(f"/iclock/devicecmd?SN={LEGACY_SN}", content="").text, "OK"
        )

    def test_a_wrong_method_on_a_real_path_is_logged_rather_than_405ing(self):
        self.add_device(LEGACY_SN)
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.client.put(f"/iclock/ping?SN={LEGACY_SN}", content="")
        self.assertEqual(response.status_code, 404)
        self.assertIn("/iclock/ping", "\n".join(captured.output))

    def test_the_exchange_endpoint_is_named_rather_than_mystifying(self):
        """Device-side encryption is unimplementable here (it needs ZKTeco's
        own library), so the point is that the failure is diagnosable."""
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.client.post(
                f"/iclock/exchange?SN={ACC_SN}&type=publickey", content="PublicKey=abc"
            )
        self.assertEqual(response.status_code, 404)
        self.assertIn("/iclock/exchange", "\n".join(captured.output))

    def test_the_catch_all_never_returns_2xx(self):
        """A 200 on an unexpected reply is documented to make some firmware
        treat setup as complete and stop re-handshaking until power-cycled."""
        for method in ("get", "post", "put", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)("/iclock/whatever")
                self.assertGreaterEqual(response.status_code, 400)


# ---------------------------------------------------------------------------
# 6. Migration onto an existing database
# ---------------------------------------------------------------------------

class MigrationTests(unittest.TestCase):
    """Existing installs must keep today's behaviour with no manual step."""

    def test_protocol_column_is_added_and_backfills_existing_rows_as_att(self):
        from app.migrations import run_migrations

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        # A pre-D9 `devices` table: everything except the four new columns.
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE devices ("
                " id INTEGER PRIMARY KEY,"
                " serial_number VARCHAR(50) NOT NULL,"
                " ip_address VARCHAR(50) NOT NULL,"
                " port INTEGER,"
                " name VARCHAR(100),"
                " last_seen DATETIME,"
                " is_online BOOLEAN,"
                " created_at DATETIME,"
                " status VARCHAR(10),"
                " approved_at DATETIME,"
                " approved_by VARCHAR(150),"
                " ip_check_enabled BOOLEAN,"
                " allowed_cidrs TEXT,"
                " last_ip VARCHAR(64),"
                " comm_key INTEGER"
                ")"
            ))
            conn.execute(text(
                "INSERT INTO devices (serial_number, ip_address, status, comm_key)"
                " VALUES ('ESY4241100079', '10.0.0.5', 'approved', 0),"
                "        ('CQZ7230961348', '10.0.0.6', 'approved', 0)"
            ))

        run_migrations(engine)

        columns = {c["name"] for c in inspect(engine).get_columns("devices")}
        for expected in ("protocol", "registry_code", "session_id", "capabilities"):
            self.assertIn(expected, columns)

        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT serial_number, protocol FROM devices ORDER BY id")
            ).fetchall()
        # The whole point: the two production serials keep the legacy path.
        self.assertEqual(
            rows, [("ESY4241100079", "att"), ("CQZ7230961348", "att")]
        )

        # Idempotent — a second boot must be a no-op, not an error.
        run_migrations(engine)
        engine.dispose()

    def test_attendance_provenance_columns_are_added_to_an_existing_table(self):
        from app.migrations import run_migrations

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE attendance_logs ("
                " id INTEGER PRIMARY KEY,"
                " device_sn VARCHAR(50) NOT NULL,"
                " user_id VARCHAR(24) NOT NULL,"
                " timestamp DATETIME NOT NULL,"
                " status INTEGER NOT NULL,"
                " punch INTEGER,"
                " source VARCHAR(10) NOT NULL,"
                " created_at DATETIME"
                ")"
            ))
            conn.execute(text(
                "INSERT INTO attendance_logs"
                " (device_sn, user_id, timestamp, status, punch, source)"
                " VALUES ('ESY4241100079', '1001', '2026-08-01 09:00:00', 0, 1, 'adms_push')"
            ))

        run_migrations(engine)

        columns = {c["name"] for c in inspect(engine).get_columns("attendance_logs")}
        for expected in ("event_code", "verify_type", "record_index"):
            self.assertIn(expected, columns)

        with engine.connect() as conn:
            row = conn.execute(text(
                "SELECT status, punch, event_code FROM attendance_logs"
            )).fetchone()
        # The pre-existing row is untouched and its new columns are empty.
        self.assertEqual(row, (0, 1, None))
        engine.dispose()


# ---------------------------------------------------------------------------
# 7. Timezone provenance (D10)
# ---------------------------------------------------------------------------
#
# A ZKTeco device sends "time=2026-08-20 14:48:22" — no offset, no zone name.
# The digits were always right; nothing recorded what they meant, so two
# separate layers guessed differently and a 14:48 punch was displayed as
# 18:48. These tests assert the thing that actually fixes that: the digits are
# stored and pushed *unchanged*, and a label travels alongside them.

class RecordTimezoneStampTests(AdmsTestCase):
    """Every ingest path must label what it stores. Both, not one."""

    def test_rtlog_stamps_the_device_timezone_on_the_record(self):
        self.add_device(ACC_SN, protocol="acc", timezone="Asia/Dubai")
        self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=rtlog",
            content="time=2026-08-20 14:48:22\tpin=1001\tevent=0\t"
                    "inoutstatus=0\tverifytype=1\tindex=501\n",
        )
        row = self.attendance_rows()[0]
        self.assertEqual(row.timezone, "Asia/Dubai")
        # And the digits are the device's own, not shifted by four hours.
        self.assertEqual(row.timestamp.replace(tzinfo=None),
                         datetime(2026, 8, 20, 14, 48, 22))

    def test_attlog_stamps_the_device_timezone_on_the_record(self):
        self.add_device(LEGACY_SN, timezone="Asia/Dubai")
        self.client.post(
            f"/iclock/cdata?SN={LEGACY_SN}&table=ATTLOG",
            content="1001\t2026-08-20 14:48:22\t0\t1\n",
        )
        row = self.attendance_rows()[0]
        self.assertEqual(row.timezone, "Asia/Dubai")
        self.assertEqual(row.timestamp.replace(tzinfo=None),
                         datetime(2026, 8, 20, 14, 48, 22))

    def test_each_device_stamps_its_own_zone_not_a_global_one(self):
        """Two sites, two zones — the point of a per-record snapshot."""
        self.add_device(ACC_SN, protocol="acc", timezone="Asia/Dubai")
        self.add_device(LEGACY_SN, timezone="Europe/London")
        self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=rtlog",
            content="time=2026-08-20 14:48:22\tpin=1001\tevent=0\t"
                    "inoutstatus=0\tindex=601\n",
        )
        self.client.post(
            f"/iclock/cdata?SN={LEGACY_SN}&table=ATTLOG",
            content="2002\t2026-08-20 14:48:22\t0\t1\n",
        )
        by_sn = {r.device_sn: r for r in self.attendance_rows()}
        self.assertEqual(by_sn[ACC_SN].timezone, "Asia/Dubai")
        self.assertEqual(by_sn[LEGACY_SN].timezone, "Europe/London")
        # Same wall-clock digits, different meanings — which is exactly the
        # information that used to be lost.
        self.assertEqual(by_sn[ACC_SN].timestamp.replace(tzinfo=None),
                         by_sn[LEGACY_SN].timestamp.replace(tzinfo=None))

    def test_device_with_no_zone_falls_back_to_the_configured_default(self):
        """A row that slipped through must never be stored unlabelled."""
        self.add_device(ACC_SN, protocol="acc", timezone=None)
        self.client.post(
            f"/iclock/cdata?SN={ACC_SN}&table=rtlog",
            content="time=2026-08-20 14:48:22\tpin=1001\tevent=0\t"
                    "inoutstatus=0\tindex=701\n",
        )
        self.assertEqual(self.attendance_rows()[0].timezone,
                         config.DEFAULT_DEVICE_TIMEZONE)

    def test_auto_registered_device_is_seeded_with_the_default_zone(self):
        db = self.Session()
        try:
            db.add(AdmsPairing(id=1, open_until=datetime(2099, 1, 1)))
            db.commit()
        finally:
            db.close()

        self.client.get("/iclock/cdata?SN=D10SEEDTEST01&options=all")
        device = self.get_device("D10SEEDTEST01")
        self.assertIsNotNone(device)
        self.assertEqual(device.timezone, config.DEFAULT_DEVICE_TIMEZONE)


class TimezoneRelabelTests(unittest.TestCase):
    """The bulk relabel: labels change, punch times never do.

    This is the operation with teeth — one call rewrites a column on every
    historical row for a device — so the assertions read the raw stored
    timestamp text before and after and require it byte-identical.
    """

    OTHER_SN = "D10OTHERDEV01"

    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        from app.deps import require_admin, require_auth
        from app.models import User
        from app.routers import devices as devices_router

        app = FastAPI()
        app.include_router(devices_router.router)

        def _override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        # A signed-in admin is a precondition of this endpoint, not the
        # subject of this test — D1/D6 own that. Stubbed so these tests stay
        # about the relabel.
        admin = User(id=1, username="tester", role="admin", password_hash="x")
        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides[require_auth] = lambda: admin
        app.dependency_overrides[require_admin] = lambda: admin
        self.client = TestClient(app, client=("203.0.113.10", 40000))

        db = self.Session()
        try:
            db.add(Device(serial_number=ACC_SN, ip_address="203.0.113.10", port=4370,
                          name="Main Door", status="approved", timezone="UTC"))
            db.add(Device(serial_number=self.OTHER_SN, ip_address="203.0.113.11", port=4370,
                          name="Other Site", status="approved", timezone="Europe/London"))
            for i, moment in enumerate([
                datetime(2026, 8, 20, 14, 48, 22),
                datetime(2026, 8, 20, 17, 2, 0),
                datetime(2026, 8, 21, 8, 30, 15),
            ]):
                db.add(AttendanceLog(device_sn=ACC_SN, user_id=f"100{i}", timestamp=moment,
                                     status=0, punch=1, source="adms_push", timezone="UTC"))
            db.add(AttendanceLog(device_sn=self.OTHER_SN, user_id="2001",
                                 timestamp=datetime(2026, 8, 20, 9, 0, 0),
                                 status=0, punch=1, source="adms_push",
                                 timezone="Europe/London"))
            db.commit()
        finally:
            db.close()

    def tearDown(self):
        self.client.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    def raw_rows(self, sn):
        """(timestamp, timezone) straight from SQLite, as stored text."""
        with self.engine.connect() as conn:
            return conn.execute(
                text("SELECT timestamp, timezone FROM attendance_logs "
                     "WHERE device_sn = :sn ORDER BY id"),
                {"sn": sn},
            ).fetchall()

    def test_relabel_updates_every_record_and_leaves_digits_identical(self):
        before = self.raw_rows(ACC_SN)

        response = self.client.patch(f"/devices/{ACC_SN}/timezone",
                                     json={"timezone": "Asia/Dubai"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["timezone"], "Asia/Dubai")

        after = self.raw_rows(ACC_SN)
        self.assertEqual(len(after), 3)
        # Every label changed...
        self.assertEqual([r[1] for r in after], ["Asia/Dubai"] * 3)
        # ...and not one digit of any punch time did.
        self.assertEqual([r[0] for r in before], [r[0] for r in after])

    def test_relabel_does_not_touch_another_devices_rows(self):
        before_other = self.raw_rows(self.OTHER_SN)
        self.client.patch(f"/devices/{ACC_SN}/timezone", json={"timezone": "Asia/Dubai"})
        self.assertEqual(self.raw_rows(self.OTHER_SN), before_other)

    def test_relabel_is_audited_with_the_row_count(self):
        from app.models import AuditLog

        self.client.patch(f"/devices/{ACC_SN}/timezone", json={"timezone": "Asia/Dubai"})
        db = self.Session()
        try:
            entry = db.query(AuditLog).filter_by(action="device_timezone_change").first()
        finally:
            db.close()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.target, ACC_SN)
        self.assertEqual(entry.actor, "tester")
        self.assertIn("UTC -> Asia/Dubai", entry.detail)
        self.assertIn("3 attendance record(s) relabelled", entry.detail)

    def test_an_unknown_zone_is_refused_and_changes_nothing(self):
        before = self.raw_rows(ACC_SN)
        response = self.client.patch(f"/devices/{ACC_SN}/timezone",
                                     json={"timezone": "Asia/Dubaii"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("not a known IANA timezone", response.json()["detail"])
        self.assertEqual(self.raw_rows(ACC_SN), before)

    def test_setting_the_same_zone_is_a_no_op(self):
        before = self.raw_rows(ACC_SN)
        response = self.client.patch(f"/devices/{ACC_SN}/timezone",
                                     json={"timezone": "UTC"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.raw_rows(ACC_SN), before)

        from app.models import AuditLog
        db = self.Session()
        try:
            self.assertEqual(
                db.query(AuditLog).filter_by(action="device_timezone_change").count(), 0
            )
        finally:
            db.close()

    def test_the_generic_device_patch_cannot_change_the_timezone(self):
        """No if/else dance: one deliberate action, one endpoint."""
        response = self.client.patch(f"/devices/{ACC_SN}",
                                     json={"name": "Renamed", "timezone": "Asia/Dubai"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], "Renamed")
        self.assertEqual(response.json()["timezone"], "UTC")
        self.assertEqual([r[1] for r in self.raw_rows(ACC_SN)], ["UTC"] * 3)


class ProtocolCorrectionTests(unittest.TestCase):
    """PATCH /devices/{sn}/protocol — the operator-facing correction (E6).

    Both routers are mounted in this app, unlike TimezoneRelabelTests: the one
    behaviour that actually needs proving here is how a manual correction
    interacts with the ADMS module's own automatic classification, so this
    class exercises the devices endpoint AND real /iclock/* traffic against
    the same database.
    """

    SN = "E6PROTOTEST01"

    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        from app.deps import require_admin, require_auth
        from app.models import User
        from app.routers import devices as devices_router

        app = FastAPI()
        app.include_router(devices_router.router)
        app.include_router(adms.router)

        def _override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        admin = User(id=1, username="tester", role="admin", password_hash="x")
        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides[require_auth] = lambda: admin
        app.dependency_overrides[require_admin] = lambda: admin
        self.client = TestClient(app, client=("203.0.113.10", 40000))

        db = self.Session()
        try:
            db.add(Device(serial_number=self.SN, ip_address="203.0.113.10", port=4370,
                          name="Front Door", status="approved", protocol="att"))
            db.commit()
        finally:
            db.close()

    def tearDown(self):
        self.client.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    def device(self):
        db = self.Session()
        try:
            return db.query(Device).filter_by(serial_number=self.SN).first()
        finally:
            db.close()

    def audit_rows(self, action):
        from app.models import AuditLog
        db = self.Session()
        try:
            return db.query(AuditLog).filter_by(action=action).order_by(AuditLog.id).all()
        finally:
            db.close()

    # -- 1. invalid value rejected -----------------------------------------

    def test_an_invalid_protocol_value_is_rejected(self):
        response = self.client.patch(f"/devices/{self.SN}/protocol", json={"protocol": "bogus"})
        self.assertEqual(response.status_code, 422)
        # Nothing changed: still the seeded default, still unpinned.
        device = self.device()
        self.assertEqual(device.protocol, "att")
        self.assertFalse(device.protocol_pinned)

    def test_a_missing_protocol_field_is_rejected(self):
        response = self.client.patch(f"/devices/{self.SN}/protocol", json={})
        self.assertEqual(response.status_code, 422)

    # -- 2. a valid change persists and is audited ---------------------------

    def test_a_valid_change_persists_pins_and_is_audited(self):
        response = self.client.patch(f"/devices/{self.SN}/protocol", json={"protocol": "acc"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["protocol"], "acc")
        self.assertTrue(response.json()["protocol_pinned"])

        device = self.device()
        self.assertEqual(device.protocol, "acc")
        self.assertTrue(device.protocol_pinned)

        entries = self.audit_rows("device_protocol_change")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].actor, "tester")
        self.assertEqual(entries[0].target, self.SN)
        self.assertIn("att -> acc", entries[0].detail)
        self.assertIn("manual", entries[0].detail.lower())

    def test_setting_the_same_already_pinned_value_is_a_no_op(self):
        self.client.patch(f"/devices/{self.SN}/protocol", json={"protocol": "acc"})
        before = len(self.audit_rows("device_protocol_change"))

        response = self.client.patch(f"/devices/{self.SN}/protocol", json={"protocol": "acc"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.audit_rows("device_protocol_change")), before)

    # -- 3. the generic PATCH cannot touch protocol --------------------------

    def test_the_generic_device_patch_cannot_change_protocol(self):
        """protocol is deliberately absent from DeviceUpdate — prove it."""
        response = self.client.patch(f"/devices/{self.SN}",
                                     json={"name": "Renamed", "protocol": "acc"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], "Renamed")
        # Ignored, not rejected: the field simply is not part of the schema.
        self.assertEqual(response.json()["protocol"], "att")
        self.assertFalse(response.json()["protocol_pinned"])

        device = self.device()
        self.assertEqual(device.protocol, "att")
        self.assertFalse(device.protocol_pinned)
        self.assertEqual(self.audit_rows("device_protocol_change"), [])

    # -- 4. the interaction rule, pinned by a test ---------------------------
    #
    # Chosen rule: "manual wins until contradicted by strong evidence." A
    # manual PATCH takes effect immediately and pins the value; automatic
    # classification in adms.py keeps working exactly as D9 built it — a
    # device that actually proves it speaks the other protocol still gets
    # reclassified, because trapping a genuinely reconfigured terminal on the
    # wrong protocol forever would be worse than the problem this unit
    # exists to fix. What changes is that the override is never silent: the
    # pin is cleared and the audit trail says explicitly that it overrode an
    # operator's manual choice.

    def test_manual_pin_survives_when_no_contradicting_evidence_arrives(self):
        """The whole point of pinning: nothing flips it on its own."""
        self.client.patch(f"/devices/{self.SN}/protocol", json={"protocol": "acc"})

        # An unrelated request that carries no protocol evidence at all.
        self.client.get(f"/iclock/ping?SN={self.SN}")

        device = self.device()
        self.assertEqual(device.protocol, "acc")
        self.assertTrue(device.protocol_pinned)

    def test_attlog_from_a_manually_pinned_acc_device_still_demotes_it(self):
        """The self-healing case: the pin must not trap a real T&A terminal."""
        self.client.patch(f"/devices/{self.SN}/protocol", json={"protocol": "acc"})
        self.assertTrue(self.device().protocol_pinned)

        response = self.client.post(
            f"/iclock/cdata?SN={self.SN}&table=ATTLOG",
            content="1001\t2026-08-20 09:15:00\t0\t1\n",
        )
        self.assertEqual(response.status_code, 200)

        device = self.device()
        # Reclassified by real evidence, exactly as an unpinned device would be...
        self.assertEqual(device.protocol, "att")
        # ...and the pin is gone, not left dangling on a value that no longer
        # reflects an operator's intent.
        self.assertFalse(device.protocol_pinned)

    def test_the_override_of_a_manual_pin_is_audited_distinctly(self):
        """A pinned device flipped by device evidence must never read as a
        silent revert — this is the visibility requirement E6 exists to meet.

        The manual PATCH and the automatic override write to two different
        audit actions on purpose (`device_protocol_change` vs
        `adms_protocol_change`, matching the pre-existing convention for
        operator-driven vs device-driven changes) — that split is itself part
        of what makes an override distinguishable from a manual set.
        """
        self.client.patch(f"/devices/{self.SN}/protocol", json={"protocol": "acc"})
        self.assertEqual(len(self.audit_rows("device_protocol_change")), 1)
        self.assertEqual(len(self.audit_rows("adms_protocol_change")), 0)

        self.client.post(
            f"/iclock/cdata?SN={self.SN}&table=ATTLOG",
            content="1001\t2026-08-20 09:15:00\t0\t1\n",
        )

        # The manual row is untouched...
        self.assertEqual(len(self.audit_rows("device_protocol_change")), 1)
        # ...and the override is its own row, worded so it cannot be mistaken
        # for an ordinary automatic transition.
        entries = self.audit_rows("adms_protocol_change")
        self.assertEqual(len(entries), 1)
        override_entry = entries[-1]
        self.assertEqual(override_entry.actor, "device")
        self.assertIn("acc -> att", override_entry.detail)
        self.assertIn("overriding manual pin", override_entry.detail.lower())
        self.assertIn("pin cleared", override_entry.detail.lower())

    def test_an_unpinned_device_still_reclassifies_silently_as_before(self):
        """Regression guard: E6 must not change behaviour for devices an
        operator has never touched — no pin, no special audit wording."""
        db = self.Session()
        try:
            db.query(Device).filter_by(serial_number=self.SN).update({"protocol": "acc"})
            db.commit()
        finally:
            db.close()
        self.assertFalse(self.device().protocol_pinned)

        self.client.post(
            f"/iclock/cdata?SN={self.SN}&table=ATTLOG",
            content="1001\t2026-08-20 09:15:00\t0\t1\n",
        )

        device = self.device()
        self.assertEqual(device.protocol, "att")
        self.assertFalse(device.protocol_pinned)

        entry = self.audit_rows("adms_protocol_change")[-1]
        self.assertNotIn("overriding manual pin", entry.detail.lower())
        self.assertNotIn("pin cleared", entry.detail.lower())

    def test_pin_check_is_load_bearing_not_incidental(self):
        """Pins _set_protocol's actual override-and-clear behaviour directly,
        so a future refactor of that function cannot silently drop the check
        that makes the override visible (the failure mode this unit exists to
        avoid) while still passing the end-to-end tests above by accident."""
        db = self.Session()
        try:
            device = Device(serial_number="E6DIRECTTEST1", ip_address="203.0.113.20",
                            status="approved", protocol="acc", protocol_pinned=True)
            db.add(device)
            db.commit()
            db.refresh(device)

            adms._set_protocol(db, device, "att", "unit test evidence", "203.0.113.20")

            self.assertEqual(device.protocol, "att")
            self.assertFalse(
                device.protocol_pinned,
                "a pinned device that receives contradicting evidence must have "
                "its pin cleared, or a later PATCH /protocol would look like it "
                "did nothing",
            )
            from app.models import AuditLog
            entry = (
                db.query(AuditLog)
                .filter_by(action="adms_protocol_change", target="E6DIRECTTEST1")
                .order_by(AuditLog.id.desc())
                .first()
            )
            self.assertIsNotNone(entry)
            self.assertIn("overriding manual pin", entry.detail.lower())
        finally:
            db.close()


class HrmMappingTests(unittest.TestCase):
    """What actually leaves the building. The HRM has been damaged once by a
    bad push, so this asserts the payload field by field."""

    def _map(self, record, device=None):
        from app.services.hrm_sync import _map
        dev_cache = {device.serial_number: device} if device is not None else {}
        return _map(record, {}, dev_cache, "1")

    def test_the_records_own_timezone_is_sent_with_unchanged_digits(self):
        record = AttendanceLog(
            id=7, device_sn=ACC_SN, user_id="1001",
            timestamp=datetime(2026, 8, 20, 14, 48, 22),
            status=0, punch=1, source="adms_push", timezone="Asia/Dubai",
        )
        device = Device(serial_number=ACC_SN, ip_address="203.0.113.10",
                        name="Main Door", timezone="Asia/Dubai")
        payload = self._map(record, device)

        self.assertEqual(payload["timezone"], "Asia/Dubai")
        # Byte-for-byte what the device reported. No +04:00, no shift to 10:48.
        self.assertEqual(payload["authdatetime"], "2026-08-20 14:48:22")
        self.assertEqual(payload["authdate"], "2026-08-20")
        self.assertEqual(payload["authtime"], "14:48:22")

    def test_a_records_own_label_wins_over_the_devices_current_one(self):
        """A device relabelled after the fact must not silently re-mean rows
        that were never relabelled with it."""
        record = AttendanceLog(
            id=8, device_sn=ACC_SN, user_id="1001",
            timestamp=datetime(2026, 8, 20, 14, 48, 22),
            status=0, punch=1, source="adms_push", timezone="Europe/London",
        )
        device = Device(serial_number=ACC_SN, ip_address="203.0.113.10",
                        timezone="Asia/Dubai")
        self.assertEqual(self._map(record, device)["timezone"], "Europe/London")

    def test_a_null_record_timezone_falls_back_to_the_device(self):
        record = AttendanceLog(
            id=9, device_sn=ACC_SN, user_id="1001",
            timestamp=datetime(2026, 8, 20, 14, 48, 22),
            status=0, punch=1, source="adms_push", timezone=None,
        )
        device = Device(serial_number=ACC_SN, ip_address="203.0.113.10",
                        timezone="Europe/London")
        payload = self._map(record, device)
        self.assertEqual(payload["timezone"], "Europe/London")
        self.assertEqual(payload["authdatetime"], "2026-08-20 14:48:22")

    def test_a_null_record_and_missing_device_fall_back_to_the_default(self):
        """Never blank, never a crash — the push must still go out labelled."""
        record = AttendanceLog(
            id=10, device_sn="GONE", user_id="1001",
            timestamp=datetime(2026, 8, 20, 14, 48, 22),
            status=0, punch=1, source="adms_push", timezone=None,
        )
        payload = self._map(record)
        self.assertEqual(payload["timezone"], config.DEFAULT_DEVICE_TIMEZONE)
        self.assertTrue(payload["timezone"])
        self.assertEqual(payload["authdatetime"], "2026-08-20 14:48:22")

    def test_the_hrm_config_timezone_is_no_longer_part_of_the_api(self):
        from app.routers.hrm_sync import HrmConfigUpdate, _serialize
        from app.models import HrmIntegration

        self.assertNotIn("timezone", HrmConfigUpdate.model_fields)
        # The column stays (migrations are additive-only) but nothing reads it.
        row = HrmIntegration(id=1, endpoint="http://example.invalid", secret="s",
                             location_id="1", timezone="America/New_York")
        self.assertNotIn("timezone", _serialize(row))


class TimezoneMigrationTests(unittest.TestCase):
    """An upgraded install must come up labelled, with no manual step."""

    LEGACY_DEVICES = (
        "CREATE TABLE devices ("
        " id INTEGER PRIMARY KEY,"
        " serial_number VARCHAR(50) NOT NULL,"
        " ip_address VARCHAR(50) NOT NULL,"
        " port INTEGER,"
        " name VARCHAR(100),"
        " last_seen DATETIME,"
        " is_online BOOLEAN,"
        " created_at DATETIME"
        "{extra})"
    )
    LEGACY_ATTENDANCE = (
        "CREATE TABLE attendance_logs ("
        " id INTEGER PRIMARY KEY,"
        " device_sn VARCHAR(50) NOT NULL,"
        " user_id VARCHAR(24) NOT NULL,"
        " timestamp DATETIME NOT NULL,"
        " status INTEGER NOT NULL,"
        " punch INTEGER,"
        " source VARCHAR(10) NOT NULL,"
        " created_at DATETIME"
        ")"
    )

    def _engine(self, devices_extra=""):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        with engine.begin() as conn:
            conn.execute(text(self.LEGACY_DEVICES.format(extra=devices_extra)))
            conn.execute(text(self.LEGACY_ATTENDANCE))
        return engine

    def test_existing_devices_and_records_are_labelled_with_the_default(self):
        from app.migrations import run_migrations

        engine = self._engine()
        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO devices (serial_number, ip_address, port)"
                " VALUES ('ESY4241100079', '10.0.0.5', 4370)"
            ))
            conn.execute(text(
                "INSERT INTO attendance_logs"
                " (device_sn, user_id, timestamp, status, punch, source)"
                " VALUES ('ESY4241100079', '1001', '2026-08-01 09:00:00', 0, 1, 'adms_push')"
            ))

        run_migrations(engine)

        with engine.connect() as conn:
            device_tz = conn.execute(text("SELECT timezone FROM devices")).scalar()
            stamp, record_tz = conn.execute(text(
                "SELECT timestamp, timezone FROM attendance_logs"
            )).fetchone()
        self.assertEqual(device_tz, config.DEFAULT_DEVICE_TIMEZONE)
        self.assertEqual(record_tz, config.DEFAULT_DEVICE_TIMEZONE)
        # The backfill labels. It does not rewrite a single punch time.
        self.assertEqual(stamp, "2026-08-01 09:00:00")
        engine.dispose()

    def test_records_inherit_their_own_devices_zone_not_a_global_one(self):
        """The half-migrated case: devices already labelled, records not yet.

        A multi-site install must not have every historical row stamped with
        one global answer — each row takes its own device's zone, and only a
        row whose device is gone falls back to the default.
        """
        from app.migrations import run_migrations

        engine = self._engine(devices_extra=", timezone VARCHAR(64)")
        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO devices (serial_number, ip_address, port, timezone)"
                " VALUES ('ESY4241100079', '10.0.0.5', 4370, 'Europe/London')"
            ))
            conn.execute(text(
                "INSERT INTO attendance_logs"
                " (device_sn, user_id, timestamp, status, punch, source) VALUES"
                " ('ESY4241100079', '1001', '2026-08-01 09:00:00', 0, 1, 'adms_push'),"
                " ('DECOMMISSIONED', '2002', '2026-08-01 10:00:00', 0, 1, 'adms_push')"
            ))

        run_migrations(engine)

        with engine.connect() as conn:
            rows = dict(conn.execute(text(
                "SELECT device_sn, timezone FROM attendance_logs"
            )).fetchall())
        self.assertEqual(rows["ESY4241100079"], "Europe/London")
        self.assertEqual(rows["DECOMMISSIONED"], config.DEFAULT_DEVICE_TIMEZONE)
        engine.dispose()

    def test_the_backfill_does_not_re_run_and_overwrite_an_operators_choice(self):
        from app.migrations import run_migrations

        engine = self._engine()
        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO devices (serial_number, ip_address, port)"
                " VALUES ('ESY4241100079', '10.0.0.5', 4370)"
            ))
            conn.execute(text(
                "INSERT INTO attendance_logs"
                " (device_sn, user_id, timestamp, status, punch, source)"
                " VALUES ('ESY4241100079', '1001', '2026-08-01 09:00:00', 0, 1, 'adms_push')"
            ))
        run_migrations(engine)

        # The operator corrects the zone, then the app restarts.
        with engine.begin() as conn:
            conn.execute(text("UPDATE devices SET timezone = 'Europe/London'"))
            conn.execute(text("UPDATE attendance_logs SET timezone = 'Europe/London'"))
        run_migrations(engine)

        with engine.connect() as conn:
            self.assertEqual(
                conn.execute(text("SELECT timezone FROM devices")).scalar(),
                "Europe/London")
            self.assertEqual(
                conn.execute(text("SELECT timezone FROM attendance_logs")).scalar(),
                "Europe/London")
        engine.dispose()


class AttendanceSerialisationTests(unittest.TestCase):
    """What the browser is given. It must be the stored digits, full stop."""

    def test_the_punch_time_is_serialised_with_no_offset_to_convert(self):
        from app.schemas import AttendanceOut

        record = AttendanceLog(
            id=1, device_sn=ACC_SN, user_id="1001",
            timestamp=datetime(2026, 8, 20, 14, 48, 22),
            status=0, punch=1, source="adms_push", timezone="Asia/Dubai",
        )
        payload = AttendanceOut.model_validate(record).model_dump()
        self.assertEqual(payload["timestamp"], "2026-08-20 14:48:22")
        self.assertEqual(payload["timezone"], "Asia/Dubai")
        # No "Z", no "+00:00" — nothing for new Date() to re-zone into 18:48.
        self.assertNotIn("+", payload["timestamp"])
        self.assertNotIn("Z", payload["timestamp"])
        self.assertNotIn("T", payload["timestamp"])

    def test_a_utc_stamped_read_still_serialises_the_stored_digits(self):
        """UTCDateTime labels every DateTime column it reads as UTC. That is
        right for created_at and wrong for a punch time, so the offset is
        dropped here rather than by changing UTCDateTime and disturbing the
        columns that genuinely are UTC."""
        from datetime import timezone as dt_timezone
        from app.schemas import AttendanceOut

        record = AttendanceLog(
            id=2, device_sn=ACC_SN, user_id="1001",
            timestamp=datetime(2026, 8, 20, 14, 48, 22, tzinfo=dt_timezone.utc),
            status=0, punch=1, source="adms_push", timezone="Asia/Dubai",
        )
        payload = AttendanceOut.model_validate(record).model_dump()
        self.assertEqual(payload["timestamp"], "2026-08-20 14:48:22")


class TimezoneConfigTests(unittest.TestCase):

    def test_only_real_iana_names_are_accepted(self):
        self.assertTrue(config.valid_timezone("Asia/Dubai"))
        self.assertTrue(config.valid_timezone("UTC"))
        self.assertFalse(config.valid_timezone("Asia/Dubaii"))
        self.assertFalse(config.valid_timezone("GMT+4"))
        self.assertFalse(config.valid_timezone(""))
        self.assertFalse(config.valid_timezone(None))

    def test_the_configured_default_is_itself_valid(self):
        self.assertTrue(config.valid_timezone(config.DEFAULT_DEVICE_TIMEZONE))


class AttendanceListFallbackTests(unittest.TestCase):
    """A null label must never reach the screen as a blank.

    The rows that predate the column are the *majority* on an upgraded
    install, so the list endpoint resolves them the same way the HRM push
    does — record, then device, then configured default.
    """

    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        from app.deps import require_auth
        from app.models import User
        from app.routers import attendance as attendance_router

        app = FastAPI()
        app.include_router(attendance_router.router)

        def _override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        viewer = User(id=1, username="tester", role="viewer", password_hash="x")
        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides[require_auth] = lambda: viewer
        self.client = TestClient(app, client=("203.0.113.10", 40000))

        db = self.Session()
        try:
            db.add(Device(serial_number=ACC_SN, ip_address="203.0.113.10", port=4370,
                          status="approved", timezone="Europe/London"))
            # Stamped at ingest.
            db.add(AttendanceLog(device_sn=ACC_SN, user_id="1001",
                                 timestamp=datetime(2026, 8, 20, 14, 48, 22),
                                 status=0, punch=1, source="adms_push",
                                 timezone="Asia/Dubai"))
            # Predates the column; its device is still here.
            db.add(AttendanceLog(device_sn=ACC_SN, user_id="1002",
                                 timestamp=datetime(2026, 8, 20, 15, 0, 0),
                                 status=0, punch=1, source="adms_push",
                                 timezone=None))
            # Predates the column; its device is gone.
            db.add(AttendanceLog(device_sn="DECOMMISSIONED", user_id="1003",
                                 timestamp=datetime(2026, 8, 20, 16, 0, 0),
                                 status=0, punch=1, source="adms_push",
                                 timezone=None))
            db.commit()
        finally:
            db.close()

    def tearDown(self):
        self.client.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    def test_every_row_comes_back_labelled_and_unconverted(self):
        items = self.client.get("/attendance").json()["items"]
        by_user = {i["user_id"]: i for i in items}

        self.assertEqual(by_user["1001"]["timezone"], "Asia/Dubai")
        self.assertEqual(by_user["1002"]["timezone"], "Europe/London")
        self.assertEqual(by_user["1003"]["timezone"], config.DEFAULT_DEVICE_TIMEZONE)

        # Not one of them is blank, and not one has an offset the browser
        # could act on.
        for item in items:
            self.assertTrue(item["timezone"])
            self.assertNotIn("+", item["timestamp"])
            self.assertNotIn("Z", item["timestamp"])

        self.assertEqual(by_user["1001"]["timestamp"], "2026-08-20 14:48:22")


if __name__ == "__main__":
    unittest.main()
