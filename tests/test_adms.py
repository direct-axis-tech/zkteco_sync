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

import base64
import hashlib
import os
import unittest
from datetime import datetime, timedelta, timezone

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

    def photos(self):
        """All EmployeePhoto rows, keyed the same way the table is."""
        from app.models import EmployeePhoto
        db = self.Session()
        try:
            return {
                (p.user_id, p.source): p
                for p in db.query(EmployeePhoto).all()
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



# ---------------------------------------------------------------------------
# 4d. `tabledata&tablename=biophoto` / `tablename=userpic` — face photos (E5)
# ---------------------------------------------------------------------------

# A realistic base64 payload — sized and structured like the operator's own
# captures (VGU6254600603, ~100KB decoded per photo, filename "1.jpg"), not a
# three-character stub. Large enough to prove the round trip survives real
# scale: this is what pushed EmployeePhoto.content past MariaDB/MySQL's plain
# TEXT ceiling (65,535 bytes) and onto MEDIUMTEXT.
_REALISTIC_PHOTO_BYTES = (b"\xff\xd8\xff" + bytes(range(256)) * 410)[:104904]
REALISTIC_PHOTO_B64 = base64.b64encode(_REALISTIC_PHOTO_BYTES).decode()


class PhotoTableUploadTests(AdmsTestCase):
    """Face photos stored verbatim, keyed on (user_id, source)."""

    def setUp(self):
        super().setUp()
        self.add_device(ACC_SN, protocol="acc")

    def post_photo(self, tablename, body, count=None, serial=ACC_SN):
        url = f"/iclock/cdata?SN={serial}&table=tabledata&tablename={tablename}"
        if count is not None:
            url += f"&count={count}"
        return self.client.post(url, content=body)

    def biophoto_line(self, pin="1", content=REALISTIC_PHOTO_B64, **extra):
        fields = dict(pin=pin, filename="1.jpg", type="9", size="104904")
        fields.update(extra)
        pairs = "\t".join(f"{k}={v}" for k, v in fields.items())
        return f"biophoto {pairs}\tcontent={content}\n"

    def userpic_line(self, pin="1", content=REALISTIC_PHOTO_B64, **extra):
        fields = dict(pin=pin, filename="1.jpg", size="104904")
        fields.update(extra)
        pairs = "\t".join(f"{k}={v}" for k, v in fields.items())
        return f"userpic {pairs}\tcontent={content}\n"

    # -- both tables parse and store --------------------------------------

    def test_a_biophoto_upload_is_stored(self):
        response = self.post_photo("biophoto", self.biophoto_line(), count=1)
        self.assertEqual(response.status_code, 200)
        photos = self.photos()
        self.assertEqual(list(photos), [("1", "biophoto")])
        self.assertEqual(photos[("1", "biophoto")].type, 9)
        self.assertEqual(photos[("1", "biophoto")].size, 104904)

    def test_a_userpic_upload_is_stored(self):
        response = self.post_photo("userpic", self.userpic_line(), count=1)
        self.assertEqual(response.status_code, 200)
        photos = self.photos()
        self.assertEqual(list(photos), [("1", "userpic")])
        # userpic carries no `type` field on the wire.
        self.assertIsNone(photos[("1", "userpic")].type)
        self.assertEqual(photos[("1", "userpic")].size, 104904)

    def test_both_tables_for_the_same_pin_coexist_as_two_rows(self):
        """biophoto and userpic are confirmed to carry the same image on the
        operator's own capture, but they are stored as two rows (one per
        `source`) rather than collapsed into one — see EmployeePhoto."""
        self.post_photo("biophoto", self.biophoto_line(), count=1)
        self.post_photo("userpic", self.userpic_line(), count=1)
        photos = self.photos()
        self.assertEqual(sorted(photos), [("1", "biophoto"), ("1", "userpic")])
        self.assertEqual(photos[("1", "biophoto")].content, photos[("1", "userpic")].content)

    def test_fields_are_read_by_key_and_never_by_position(self):
        body = f"biophoto content={REALISTIC_PHOTO_B64}\tsize=104904\tpin=21\ttype=9\tfilename=1.jpg\n"
        self.post_photo("biophoto", body, count=1)
        row = self.photos()[("21", "biophoto")]
        self.assertEqual(row.size, 104904)
        self.assertEqual(row.type, 9)
        self.assertEqual(row.filename, "1.jpg")

    # -- verbatim round-trip ------------------------------------------------

    def test_content_round_trips_byte_identical(self):
        self.post_photo("biophoto", self.biophoto_line(), count=1)
        row = self.photos()[("1", "biophoto")]
        self.assertEqual(row.content, REALISTIC_PHOTO_B64)
        self.assertEqual(base64.b64decode(row.content), _REALISTIC_PHOTO_BYTES)
        self.assertEqual(row.source_device_sn, ACC_SN)

    def test_the_acknowledgement_is_byte_exact(self):
        response = self.post_photo("biophoto", self.biophoto_line(), count=1)
        self.assertEqual(response.content, b"biophoto=1")
        response = self.post_photo("userpic", self.userpic_line(), count=1)
        self.assertEqual(response.content, b"userpic=1")

    # -- upsert semantics -----------------------------------------------

    def test_a_repeat_upload_is_idempotent(self):
        """Devices resend their whole photo set on reconnect. A replay must
        converge on the same row, not accumulate duplicates."""
        self.post_photo("biophoto", self.biophoto_line(), count=1)
        first = self.photos()

        response = self.post_photo("biophoto", self.biophoto_line(), count=1)

        self.assertEqual(response.content, b"biophoto=1")
        again = self.photos()
        self.assertEqual(sorted(again), sorted(first))
        self.assertEqual(len(again), 1)

    def test_a_changed_photo_on_reupload_updates_the_row_not_a_new_one(self):
        other_bytes = (b"\xff\xd8\xff" + bytes(range(255, -1, -1)) * 5)[:1000]
        other_b64 = base64.b64encode(other_bytes).decode()
        self.post_photo("biophoto", self.biophoto_line(content=REALISTIC_PHOTO_B64), count=1)
        self.post_photo("biophoto", self.biophoto_line(content=other_b64), count=1)
        photos = self.photos()
        self.assertEqual(len(photos), 1)
        self.assertEqual(photos[("1", "biophoto")].content, other_b64)

    def test_multiple_pins_in_one_batch_are_all_stored(self):
        body = (
            self.biophoto_line(pin="1", filename="1.jpg")
            + self.biophoto_line(pin="2", filename="2.jpg")
            + self.biophoto_line(pin="3", filename="3.jpg")
        )
        response = self.post_photo("biophoto", body, count=3)
        self.assertEqual(response.content, b"biophoto=3")
        self.assertEqual(
            sorted(self.photos()),
            [("1", "biophoto"), ("2", "biophoto"), ("3", "biophoto")],
        )

    # -- malformed records ---------------------------------------------

    def test_a_malformed_record_is_skipped_and_logged_without_dropping_the_batch(self):
        body = (
            self.biophoto_line(pin="1", filename="1.jpg")
            + "total garbage with no equals sign at all\n"
            + "biophoto pin=\tfilename=2.jpg\ttype=9\tsize=1\tcontent=AAAA\n"   # no pin
            + "biophoto pin=4\tfilename=4.jpg\ttype=9\tsize=1\tcontent=\n"      # no content
            + self.biophoto_line(pin="5", filename="5.jpg")
        )
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.post_photo("biophoto", body, count=5)

        self.assertEqual(response.content, b"biophoto=5")
        self.assertEqual(sorted(self.photos()), [("1", "biophoto"), ("5", "biophoto")])
        joined = "\n".join(captured.output)
        self.assertIn("total garbage", joined)

    def test_an_unapproved_serial_cannot_inject_photos(self):
        response = self.post_photo(
            "biophoto", self.biophoto_line(), count=1, serial="NOTAPPROVED01",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.photos(), {})

    def test_a_storage_failure_still_acknowledges_so_the_device_stops_retrying(self):
        def boom(*args, **kwargs):
            raise RuntimeError("simulated storage failure")

        original = adms._store_photo_table
        adms._store_photo_table = boom
        try:
            with self.assertLogs("app.routers.adms", level="ERROR"):
                response = self.post_photo("biophoto", self.biophoto_line(), count=1)
        finally:
            adms._store_photo_table = original

        self.assertEqual(response.content, b"biophoto=1")

    def test_photo_upload_does_not_touch_employees_or_device_links(self):
        """Collision guard: this table must not become a second writer of
        `employees` or `device_employees`."""
        self.post_photo("biophoto", self.biophoto_line(), count=1)
        self.assertEqual(self.employees(), {})
        self.assertEqual(self.device_links(ACC_SN), {})

    # -- the log summarises rather than dumps ------------------------------

    def test_a_photo_upload_is_summarised_in_the_log_not_dumped(self):
        with self.assertLogs("app.routers.adms", level="INFO") as captured:
            self.post_photo("biophoto", self.biophoto_line(), count=1)
        joined = "\n".join(captured.output)
        self.assertIn("not logged", joined)
        self.assertIn("stored", joined)
        self.assertNotIn(REALISTIC_PHOTO_B64, joined)

        with self.assertLogs("app.routers.adms", level="INFO") as captured:
            self.post_photo("userpic", self.userpic_line(), count=1)
        joined = "\n".join(captured.output)
        self.assertIn("not logged", joined)
        self.assertNotIn(REALISTIC_PHOTO_B64, joined)


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


# ---------------------------------------------------------------------------
# 12. Command delivery: the outbox, the log, and the move between them (E7)
# ---------------------------------------------------------------------------

class CommandDeliveryTestCase(unittest.TestCase):
    """Both routers against one database.

    The queue is only meaningful end to end: an operator queues through
    /devices/{sn}/commands, the device collects through /iclock/getrequest and
    reports back through /iclock/devicecmd. Splitting those across fixtures
    would test three halves of a mechanism and none of the mechanism.
    """

    SN = "E7CMDTEST0001"
    OTHER_SN = "E7CMDTEST0002"

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
            for serial in (self.SN, self.OTHER_SN):
                db.add(Device(serial_number=serial, ip_address="203.0.113.10",
                              port=4370, name="Terminal", status="approved",
                              protocol="acc"))
            db.commit()
        finally:
            db.close()

    def tearDown(self):
        self.client.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    # -- helpers ---------------------------------------------------------

    def session(self):
        return self.Session()

    def outbox(self, sn=None):
        from app.models import DeviceCommandOutbox
        db = self.Session()
        try:
            query = db.query(DeviceCommandOutbox)
            if sn:
                query = query.filter_by(device_sn=sn)
            return query.order_by(DeviceCommandOutbox.id).all()
        finally:
            db.close()

    def history(self, sn=None):
        from app.models import DeviceCommandLog
        db = self.Session()
        try:
            query = db.query(DeviceCommandLog)
            if sn:
                query = query.filter_by(device_sn=sn)
            return query.order_by(DeviceCommandLog.id).all()
        finally:
            db.close()

    def queue(self, command="DATA UPDATE user Pin=1\tName=Aisha", sn=None):
        """Queue through the real operator endpoint and return the new id."""
        response = self.client.post(f"/devices/{sn or self.SN}/commands",
                                    json={"command": command})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def poll(self, sn=None):
        """One /iclock/getrequest, as the device makes it."""
        return self.client.get(f"/iclock/getrequest?SN={sn or self.SN}").text

    def ack(self, command_id, return_code=0, cmd="DATA UPDATE", sn=None, in_query=False):
        """One /iclock/devicecmd, in the body (§3.9) or the query (§3.8)."""
        serial = sn or self.SN
        if in_query:
            return self.client.post(
                f"/iclock/devicecmd?SN={serial}&ID={command_id}"
                f"&Return={return_code}&CMD={cmd}",
                content="",
            )
        return self.client.post(
            f"/iclock/devicecmd?SN={serial}",
            content=f"ID={command_id}&Return={return_code}&CMD={cmd}&SN={serial}",
        )

    def rewind_backoff(self, command_id, seconds=1):
        """Pretend the retry window has elapsed, without sleeping through it."""
        from app.models import DeviceCommandOutbox
        db = self.Session()
        try:
            row = db.query(DeviceCommandOutbox).filter_by(id=command_id).first()
            row.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=seconds)
            db.commit()
        finally:
            db.close()

    def assert_exactly_one_home(self, command, sn=None):
        """The invariant: outstanding XOR concluded, never both, never neither.

        Matched on the command text rather than the id, because the two tables
        have independent id sequences — the log row is a new row, not the same
        row relabelled."""
        serial = sn or self.SN
        outstanding = [r for r in self.outbox(serial) if r.command == command]
        concluded = [r for r in self.history(serial) if r.command == command]
        self.assertEqual(
            len(outstanding) + len(concluded), 1,
            f"command {command!r} is in {len(outstanding)} outbox row(s) and "
            f"{len(concluded)} log row(s) — it must be in exactly one",
        )


class CommandDispatchTests(CommandDeliveryTestCase):
    """Queueing, and what a device is handed when it polls."""

    def test_a_queued_command_is_handed_out_once_and_marked_sent(self):
        command_id = self.queue()

        # Queued but not yet delivered: nothing has been attempted.
        row = self.outbox()[0]
        self.assertEqual(row.status, "pending")
        self.assertEqual(row.attempts, 0)
        self.assertIsNone(row.sent_at)
        self.assertIsNone(row.next_attempt_at)

        body = self.poll()
        self.assertEqual(body, f"C:{command_id}:DATA UPDATE user Pin=1\tName=Aisha")

        row = self.outbox()[0]
        self.assertEqual(row.status, "sent")
        self.assertEqual(row.attempts, 1)
        self.assertIsNotNone(row.sent_at)
        self.assertIsNotNone(row.next_attempt_at)

        # Handed out ONCE: the next poll, inside the backoff window, gets the
        # idle reply rather than the same command again.
        self.assertEqual(self.poll(), "OK")
        self.assertEqual(self.outbox()[0].attempts, 1)

    def test_the_wire_format_carries_the_id_the_device_must_quote_back(self):
        """Without the C:<id>: envelope there is no id for the device to
        report, and matching an acknowledgement becomes impossible."""
        command_id = self.queue("DATA DELETE user Pin=7")
        self.assertEqual(self.poll(), f"C:{command_id}:DATA DELETE user Pin=7")

    def test_an_id_envelope_supplied_by_the_caller_is_not_nested(self):
        """A caller that helpfully pre-formats the command must not produce
        C:12:C:99:… — the device would quote back an id we never issued."""
        command_id = self.queue("C:99:DATA UPDATE user Pin=3")
        self.assertEqual(self.outbox()[0].command, "DATA UPDATE user Pin=3")
        self.assertEqual(self.poll(), f"C:{command_id}:DATA UPDATE user Pin=3")

    def test_an_idle_queue_still_answers_the_heartbeat(self):
        self.assertEqual(self.poll(), "OK")

    def test_commands_are_handed_out_oldest_first(self):
        first = self.queue("DATA UPDATE user Pin=1")
        second = self.queue("DATA UPDATE user Pin=2")

        self.assertEqual(self.poll(), f"C:{first}:DATA UPDATE user Pin=1")
        self.ack(first)
        self.assertEqual(self.poll(), f"C:{second}:DATA UPDATE user Pin=2")

    def test_one_devices_queue_is_never_handed_to_another(self):
        mine = self.queue("DATA UPDATE user Pin=1", sn=self.SN)
        self.queue("DATA UPDATE user Pin=2", sn=self.OTHER_SN)

        self.assertEqual(self.poll(self.SN), f"C:{mine}:DATA UPDATE user Pin=1")
        self.assertEqual(len(self.outbox(self.OTHER_SN)), 1)
        self.assertEqual(self.outbox(self.OTHER_SN)[0].attempts, 0)

    def test_a_batch_is_lf_separated_when_the_batch_size_allows_it(self):
        """§3.8 allows several commands in one reply. The default is 1 because
        no real terminal here has ever been sent a command, but the mechanism
        is built and must be correct when an operator raises the setting."""
        from unittest import mock
        first = self.queue("DATA UPDATE user Pin=1")
        second = self.queue("DATA UPDATE user Pin=2")

        with mock.patch.object(config, "COMMAND_BATCH_SIZE", 3):
            body = self.poll()

        self.assertEqual(
            body,
            f"C:{first}:DATA UPDATE user Pin=1\nC:{second}:DATA UPDATE user Pin=2",
        )
        # Each is independently tracked, so a partial acknowledgement works.
        self.assertEqual([r.attempts for r in self.outbox()], [1, 1])

    def test_an_unapproved_serial_cannot_drain_a_queue(self):
        self.queue()
        db = self.Session()
        try:
            db.query(Device).filter_by(serial_number=self.SN).first().status = "pending"
            db.commit()
        finally:
            db.close()

        self.assertEqual(self.client.get(f"/iclock/getrequest?SN={self.SN}").status_code, 401)
        self.assertEqual(self.outbox()[0].attempts, 0)


class CommandAcknowledgementTests(CommandDeliveryTestCase):
    """The bug this unit exists to fix, and the semantics around it."""

    def test_a_matching_ack_moves_the_command_to_history(self):
        command_id = self.queue("DATA UPDATE user Pin=1")
        self.poll()

        response = self.ack(command_id, return_code=0)
        self.assertEqual(response.text, "OK")

        self.assertEqual(self.outbox(), [])
        concluded = self.history()
        self.assertEqual(len(concluded), 1)
        self.assertEqual(concluded[0].outcome, "acknowledged")
        self.assertEqual(concluded[0].return_code, 0)
        self.assertEqual(concluded[0].command, "DATA UPDATE user Pin=1")
        self.assertEqual(concluded[0].attempts, 1)
        self.assertIsNotNone(concluded[0].sent_at)
        self.assertIsNotNone(concluded[0].concluded_at)
        self.assert_exactly_one_home("DATA UPDATE user Pin=1")

    # -- THE REGRESSION TEST -------------------------------------------------

    def test_an_ack_for_one_command_does_not_conclude_a_different_one(self):
        """The pre-existing bug, precisely.

        adms_devicecmd used to take the OLDEST `sent` command for the serial
        and mark it acknowledged, ignoring the id the device reported and
        discarding Return= entirely. With two commands in flight it therefore
        closed the wrong one every time — reporting a success the device never
        gave, and leaving the command that actually ran to be retried until it
        was declared failed.
        """
        from unittest import mock

        first = self.queue("DATA UPDATE user Pin=1")
        second = self.queue("DATA UPDATE user Pin=2")

        # Both delivered, so both are `sent` and the old code had a choice to
        # get wrong. `first` is the oldest — the one the bug would have taken.
        with mock.patch.object(config, "COMMAND_BATCH_SIZE", 2):
            self.poll()
        self.assertEqual([r.status for r in self.outbox()], ["sent", "sent"])

        # The device reports on the SECOND one.
        self.ack(second, return_code=0)

        remaining = self.outbox()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(
            remaining[0].id, first,
            "the wrong command was concluded — the ack was matched by "
            "position, not by the id the device reported",
        )
        self.assertEqual(remaining[0].command, "DATA UPDATE user Pin=1")

        concluded = self.history()
        self.assertEqual(len(concluded), 1)
        self.assertEqual(concluded[0].command, "DATA UPDATE user Pin=2")

        self.assert_exactly_one_home("DATA UPDATE user Pin=1")
        self.assert_exactly_one_home("DATA UPDATE user Pin=2")

    def test_an_ack_naming_another_devices_command_concludes_nothing(self):
        """Serial and id must BOTH match: an id is only unique to us, and a
        device must never be able to close another device's work."""
        mine = self.queue("DATA UPDATE user Pin=1", sn=self.SN)
        self.poll(self.SN)

        with self.assertLogs("app.services.commands", level="WARNING"):
            response = self.ack(mine, return_code=0, sn=self.OTHER_SN)

        self.assertEqual(response.text, "OK")
        self.assertEqual(len(self.outbox(self.SN)), 1)
        self.assertEqual(self.history(), [])

    def test_an_ack_for_an_unknown_id_concludes_nothing_and_still_says_ok(self):
        command_id = self.queue()
        self.poll()

        with self.assertLogs("app.services.commands", level="WARNING") as captured:
            response = self.ack(command_id + 4242, return_code=0)

        self.assertEqual(response.text, "OK")
        self.assertEqual(len(self.outbox()), 1)
        self.assertEqual(self.history(), [])
        self.assertIn("not outstanding", "\n".join(captured.output))

    def test_a_repeated_ack_does_not_write_a_second_history_row(self):
        command_id = self.queue()
        self.poll()
        self.ack(command_id)

        with self.assertLogs("app.services.commands", level="WARNING"):
            self.ack(command_id)

        self.assertEqual(len(self.history()), 1)
        self.assertEqual(self.outbox(), [])

    # -- Return= semantics ---------------------------------------------------

    def test_a_non_zero_return_fails_permanently_and_is_never_retried(self):
        """A non-zero Return is the device REFUSING the command. It received
        it, understood it and declined. Retrying earns the same refusal while
        occupying the queue, so it is concluded immediately."""
        command_id = self.queue("DATA UPDATE user Pin=1")
        self.poll()

        with self.assertLogs("app.services.commands", level="WARNING") as captured:
            self.ack(command_id, return_code=-14, cmd="DATA UPDATE")

        self.assertEqual(self.outbox(), [], "a refused command must not stay queued")
        concluded = self.history()
        self.assertEqual(len(concluded), 1)
        self.assertEqual(concluded[0].outcome, "failed")
        self.assertEqual(concluded[0].return_code, -14)
        self.assertIn("Return=-14", concluded[0].last_error)
        self.assertEqual(concluded[0].attempts, 1,
                         "a refusal must not consume the retry budget — it ends it")
        self.assertIn("rejected", "\n".join(captured.output))

        # And there is nothing left to hand out on the next poll.
        self.assertEqual(self.poll(), "OK")

    def test_a_positive_non_zero_return_is_a_refusal_too(self):
        command_id = self.queue()
        self.poll()
        with self.assertLogs("app.services.commands", level="WARNING"):
            self.ack(command_id, return_code=1)
        self.assertEqual(self.history()[0].outcome, "failed")
        self.assertEqual(self.history()[0].return_code, 1)

    def test_an_ack_with_no_return_code_leaves_the_command_outstanding(self):
        """Absence is not success. Nothing is concluded on a guess; the
        ordinary retry path gets another chance at it."""
        command_id = self.queue()
        self.poll()

        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.client.post(
                f"/iclock/devicecmd?SN={self.SN}",
                content=f"ID={command_id}&CMD=DATA UPDATE",
            )

        self.assertEqual(response.text, "OK")
        self.assertEqual(len(self.outbox()), 1)
        self.assertEqual(self.history(), [])
        self.assertIn("no Return=", "\n".join(captured.output))

    # -- what the device actually sends --------------------------------------

    def test_the_ack_is_read_from_the_body_as_the_spec_specifies(self):
        command_id = self.queue()
        self.poll()
        response = self.client.post(
            f"/iclock/devicecmd?SN={self.SN}",
            content=f"ID={command_id}&Return=0&CMD=DATA UPDATE&SN={self.SN}",
        )
        self.assertEqual(response.text, "OK")
        self.assertEqual(self.history()[0].outcome, "acknowledged")

    def test_the_ack_is_also_read_from_the_query_string(self):
        """§3.9 puts these in the body; §3.8's own example writes them as a
        query string, and no capture from the operator's terminal contains a
        devicecmd request at all — the device has been polling a queue that
        was never given anything. So both forms are accepted rather than
        betting on one."""
        command_id = self.queue()
        self.poll()
        response = self.ack(command_id, return_code=0, in_query=True)
        self.assertEqual(response.text, "OK")
        self.assertEqual(self.history()[0].outcome, "acknowledged")

    def test_a_command_name_containing_a_space_is_parsed(self):
        """CMD=DATA UPDATE arrives unencoded, which a strict form parser
        handles but a naive split on whitespace does not."""
        parsed = adms._parse_devicecmd("ID=295&Return=0&CMD=DATA UPDATE&SN=X")
        self.assertEqual(parsed, [{"id": 295, "return_code": 0, "cmd": "DATA UPDATE"}])

    def test_several_results_in_one_post_are_each_parsed(self):
        parsed = adms._parse_devicecmd(
            "ID=1&Return=0&CMD=DATA UPDATE\nID=2&Return=-14&CMD=DATA DELETE\n"
        )
        self.assertEqual([p["id"] for p in parsed], [1, 2])
        self.assertEqual([p["return_code"] for p in parsed], [0, -14])

    def test_several_results_in_one_post_are_each_concluded(self):
        from unittest import mock
        first = self.queue("DATA UPDATE user Pin=1")
        second = self.queue("DATA UPDATE user Pin=2")
        with mock.patch.object(config, "COMMAND_BATCH_SIZE", 2):
            self.poll()

        with self.assertLogs("app.services.commands", level="WARNING"):
            self.client.post(
                f"/iclock/devicecmd?SN={self.SN}",
                content=f"ID={first}&Return=0&CMD=DATA UPDATE\n"
                        f"ID={second}&Return=-14&CMD=DATA UPDATE",
            )

        self.assertEqual(self.outbox(), [])
        outcomes = {r.command: r.outcome for r in self.history()}
        self.assertEqual(outcomes, {
            "DATA UPDATE user Pin=1": "acknowledged",
            "DATA UPDATE user Pin=2": "failed",
        })

    def test_a_junk_body_concludes_nothing_and_never_500s(self):
        self.queue()
        self.poll()
        with self.assertLogs("app.routers.adms", level="WARNING"):
            response = self.client.post(f"/iclock/devicecmd?SN={self.SN}",
                                        content="something went wrong")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "OK")
        self.assertEqual(len(self.outbox()), 1)
        self.assertEqual(self.history(), [])

    def test_an_empty_body_concludes_nothing(self):
        """The catch-all suite already posts an empty devicecmd; with a real
        queue behind it that must still touch nothing."""
        self.queue()
        self.poll()
        with self.assertLogs("app.routers.adms", level="WARNING"):
            response = self.client.post(f"/iclock/devicecmd?SN={self.SN}", content="")
        self.assertEqual(response.text, "OK")
        self.assertEqual(len(self.outbox()), 1)


class CommandRetryTests(CommandDeliveryTestCase):
    """Silence, backoff, and the bounded end of it."""

    def test_a_sent_but_unacked_command_is_offered_again_after_its_backoff(self):
        command_id = self.queue("DATA UPDATE user Pin=1")
        self.assertEqual(self.poll(), f"C:{command_id}:DATA UPDATE user Pin=1")

        # Inside the backoff window: not offered, not counted.
        self.assertEqual(self.poll(), "OK")
        self.assertEqual(self.outbox()[0].attempts, 1)

        self.rewind_backoff(command_id)

        self.assertEqual(self.poll(), f"C:{command_id}:DATA UPDATE user Pin=1")
        row = self.outbox()[0]
        self.assertEqual(row.attempts, 2)
        self.assertEqual(row.status, "sent")

        # And an ack for it still works after a retry.
        self.ack(command_id)
        self.assertEqual(self.history()[0].outcome, "acknowledged")
        self.assertEqual(self.history()[0].attempts, 2)

    def test_the_backoff_lengthens_and_is_bounded_by_the_last_entry(self):
        from app.services import commands as command_service
        from unittest import mock

        with mock.patch.object(config, "COMMAND_BACKOFF_SECONDS", [60, 300, 900]):
            waits = [command_service.backoff_for(n).total_seconds() for n in range(1, 7)]

        self.assertEqual(waits, [60, 300, 900, 900, 900, 900],
                         "the schedule must lengthen and then hold, never grow "
                         "without bound and never fall back to the start")

    def test_attempts_exhaust_to_a_visible_failure(self):
        from unittest import mock

        with mock.patch.object(config, "COMMAND_MAX_ATTEMPTS", 3):
            command_id = self.queue("DATA UPDATE user Pin=1")

            for expected in (1, 2, 3):
                self.assertEqual(self.poll(), f"C:{command_id}:DATA UPDATE user Pin=1")
                self.assertEqual(self.outbox()[0].attempts, expected)
                self.rewind_backoff(command_id)

            # Fourth eligible poll: nothing left to try.
            with self.assertLogs("app.services.commands", level="WARNING") as captured:
                self.assertEqual(self.poll(), "OK")

        self.assertEqual(self.outbox(), [])
        concluded = self.history()
        self.assertEqual(len(concluded), 1)
        self.assertEqual(concluded[0].outcome, "failed")
        self.assertEqual(concluded[0].attempts, 3)
        self.assertIsNone(concluded[0].return_code,
                          "no code: the device never answered at all")
        self.assertIn("no acknowledgement after 3 attempts", concluded[0].last_error)
        self.assertIn("never acknowledged", "\n".join(captured.output))
        self.assert_exactly_one_home("DATA UPDATE user Pin=1")

    def test_a_failure_is_reported_with_a_reason_an_operator_can_read(self):
        """'Visibly fail' means the reason survives to the API, not just a log."""
        from unittest import mock
        with mock.patch.object(config, "COMMAND_MAX_ATTEMPTS", 1):
            command_id = self.queue("DATA UPDATE user Pin=1")
            self.poll()
            self.rewind_backoff(command_id)
            with self.assertLogs("app.services.commands", level="WARNING"):
                self.poll()

        items = self.client.get(f"/devices/{self.SN}/commands/history").json()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["outcome"], "failed")
        self.assertEqual(items[0]["attempts"], 1)
        self.assertIn("no acknowledgement", items[0]["last_error"])
        self.assertEqual(self.client.get(f"/devices/{self.SN}/commands").json(), [])


class OfflineIsNotFailureTests(CommandDeliveryTestCase):
    """The distinction the operator cares about most.

    A command waiting for a device that has not polled is the queue doing its
    job — it is what recovered a weekend of missing punches. It must not be
    counted as an attempt, and a device that comes back after days away must
    find its work waiting, not a pile of failures it never had a chance at.
    """

    def test_a_device_that_never_polls_accrues_no_attempts_and_no_failures(self):
        from app.services import commands as command_service
        from unittest import mock

        self.queue("DATA UPDATE user Pin=1")

        # Days pass. The sweep runs many times. The device never polls.
        now = datetime.now(timezone.utc)
        db = self.Session()
        try:
            with mock.patch.object(config, "COMMAND_MAX_ATTEMPTS", 1):
                for day in range(1, 6):
                    command_service.sweep(db, now=now + timedelta(days=day))
        finally:
            db.close()

        rows = self.outbox()
        self.assertEqual(len(rows), 1, "the command must still be queued")
        self.assertEqual(rows[0].status, "pending")
        self.assertEqual(rows[0].attempts, 0,
                         "not polling is not an attempt")
        self.assertEqual(self.history(), [],
                         "an offline device must not produce failures")

    def test_the_command_is_still_delivered_when_the_device_finally_returns(self):
        """The whole point: the queue holds the work until the device comes
        back, however long that takes."""
        from app.services import commands as command_service

        command_id = self.queue("DATA UPDATE user Pin=1")

        now = datetime.now(timezone.utc)
        db = self.Session()
        try:
            for day in range(1, 4):
                command_service.sweep(db, now=now + timedelta(days=day))
        finally:
            db.close()

        self.assertEqual(self.poll(), f"C:{command_id}:DATA UPDATE user Pin=1")
        self.ack(command_id)
        self.assertEqual(self.history()[0].outcome, "acknowledged")

    def test_a_pending_command_is_untouched_by_the_sweep_within_its_expiry(self):
        from app.services import commands as command_service

        self.queue()
        db = self.Session()
        try:
            result = command_service.sweep(db)
        finally:
            db.close()

        self.assertEqual(result, {"exhausted": 0, "expired": 0, "pruned": 0})
        self.assertEqual(len(self.outbox()), 1)

    def test_the_absolute_expiry_is_a_separate_much_longer_clock(self):
        """A command queued for a terminal that was decommissioned should not
        sit in the queue forever — but the clock that gives up on it is
        measured in weeks and is nothing to do with the retry count."""
        from app.services import commands as command_service
        from unittest import mock

        self.queue("DATA UPDATE user Pin=1")

        db = self.Session()
        try:
            with mock.patch.object(config, "COMMAND_PENDING_EXPIRY_DAYS", 30):
                # Day 29: still waiting, still fine.
                inside = command_service.sweep(
                    db, now=datetime.now(timezone.utc) + timedelta(days=29))
                self.assertEqual(inside["expired"], 0)
                self.assertEqual(len(self.outbox()), 1)

                # Day 31: given up on, with the reason recorded.
                beyond = command_service.sweep(
                    db, now=datetime.now(timezone.utc) + timedelta(days=31))
        finally:
            db.close()

        self.assertEqual(beyond["expired"], 1)
        self.assertEqual(self.outbox(), [])
        concluded = self.history()
        self.assertEqual(concluded[0].outcome, "failed")
        self.assertEqual(concluded[0].attempts, 0)
        self.assertIn("without the device ever polling", concluded[0].last_error)
        self.assert_exactly_one_home("DATA UPDATE user Pin=1")

    def test_the_absolute_expiry_can_be_switched_off_entirely(self):
        from app.services import commands as command_service
        from unittest import mock

        self.queue()
        db = self.Session()
        try:
            with mock.patch.object(config, "COMMAND_PENDING_EXPIRY_DAYS", 0):
                result = command_service.sweep(
                    db, now=datetime.now(timezone.utc) + timedelta(days=3650))
        finally:
            db.close()

        self.assertEqual(result["expired"], 0)
        self.assertEqual(len(self.outbox()), 1)


class CommandSweepTests(CommandDeliveryTestCase):
    """The scheduled job: conclude the hopeless, prune the history."""

    def test_a_device_that_stops_polling_mid_retry_still_fails_on_a_timer(self):
        """getrequest concludes an exhausted command on the next poll — but a
        device that has gone silent will never poll again, so the failure has
        to surface some other way."""
        from app.services import commands as command_service
        from unittest import mock

        with mock.patch.object(config, "COMMAND_MAX_ATTEMPTS", 2):
            command_id = self.queue("DATA UPDATE user Pin=1")
            self.poll()
            self.rewind_backoff(command_id)
            self.poll()
            self.assertEqual(self.outbox()[0].attempts, 2)
            self.rewind_backoff(command_id)

            db = self.Session()
            try:
                result = command_service.sweep(db)
            finally:
                db.close()

        self.assertEqual(result["exhausted"], 1)
        self.assertEqual(self.outbox(), [])
        self.assertEqual(self.history()[0].outcome, "failed")
        self.assertEqual(self.history()[0].attempts, 2)

    def test_the_sweep_does_not_touch_a_command_still_inside_its_backoff(self):
        from app.services import commands as command_service
        from unittest import mock

        with mock.patch.object(config, "COMMAND_MAX_ATTEMPTS", 1):
            self.queue()
            self.poll()          # attempts=1, next_attempt_at in the future

            db = self.Session()
            try:
                result = command_service.sweep(db)
            finally:
                db.close()

        self.assertEqual(result["exhausted"], 0)
        self.assertEqual(len(self.outbox()), 1,
                         "its retry window has not elapsed yet")

    def test_cleanup_prunes_only_concluded_history(self):
        from app.models import DeviceCommandLog
        from app.services import commands as command_service
        from unittest import mock

        # One command still outstanding, queued long ago.
        self.queue("DATA UPDATE user Pin=1")
        # One concluded a long time ago, one concluded just now.
        self.queue("DATA UPDATE user Pin=2")
        recent = self.queue("DATA UPDATE user Pin=3")

        db = self.Session()
        try:
            old = self.outbox()[1]
            command_service.conclude(db, db.merge(old), "acknowledged", return_code=0)
            row = db.query(DeviceCommandLog).order_by(DeviceCommandLog.id.desc()).first()
            row.concluded_at = datetime.now(timezone.utc) - timedelta(days=200)
            db.commit()
        finally:
            db.close()

        self.poll()
        self.ack(recent)

        self.assertEqual(len(self.history()), 2)

        db = self.Session()
        try:
            with mock.patch.object(config, "COMMAND_LOG_RETENTION_DAYS", 90):
                result = command_service.sweep(db)
        finally:
            db.close()

        self.assertEqual(result["pruned"], 1)

        remaining = self.history()
        self.assertEqual([r.command for r in remaining], ["DATA UPDATE user Pin=3"])

        # The live queue is untouched: cleanup prunes history, never work.
        self.assertEqual([r.command for r in self.outbox()], ["DATA UPDATE user Pin=1"])

    def test_history_retention_can_be_switched_off(self):
        from app.models import DeviceCommandLog
        from app.services import commands as command_service
        from unittest import mock

        command_id = self.queue()
        self.poll()
        self.ack(command_id)

        db = self.Session()
        try:
            db.query(DeviceCommandLog).first().concluded_at = (
                datetime.now(timezone.utc) - timedelta(days=3650))
            db.commit()
            with mock.patch.object(config, "COMMAND_LOG_RETENTION_DAYS", 0):
                result = command_service.sweep(db)
        finally:
            db.close()

        self.assertEqual(result["pruned"], 0)
        self.assertEqual(len(self.history()), 1)

    def test_the_sweep_is_registered_on_the_existing_scheduler(self):
        """One scheduler, not two — a second would be a second thing to leak."""
        import inspect as _inspect
        from app import main as app_main

        source = _inspect.getsource(app_main._start_scheduler)
        self.assertEqual(source.count("BackgroundScheduler()"), 1)
        self.assertIn("command_sweep", source)
        self.assertIn("hrm_tick", source)


class CommandAtomicityTests(CommandDeliveryTestCase):
    """A command is outstanding or concluded. Never both. Never neither."""

    def test_the_invariant_holds_at_every_step_of_a_normal_life(self):
        command_id = self.queue("DATA UPDATE user Pin=1")
        self.assert_exactly_one_home("DATA UPDATE user Pin=1")

        self.poll()
        self.assert_exactly_one_home("DATA UPDATE user Pin=1")

        self.rewind_backoff(command_id)
        self.poll()
        self.assert_exactly_one_home("DATA UPDATE user Pin=1")

        self.ack(command_id)
        self.assert_exactly_one_home("DATA UPDATE user Pin=1")

    def test_a_failed_history_write_leaves_the_command_outstanding(self):
        """The move is one transaction, so a log row that cannot be written
        must take the outbox delete down with it. The alternative — a command
        deleted from the queue with no record of it anywhere — is the one
        outcome this design must never produce."""
        from unittest import mock
        from app.services import commands as command_service

        command_id = self.queue("DATA UPDATE user Pin=1")
        self.poll()

        db = self.Session()
        try:
            with mock.patch.object(command_service, "DeviceCommandLog",
                                   side_effect=RuntimeError("history write failed")):
                with self.assertRaises(RuntimeError):
                    command_service.acknowledge(db, self.SN, command_id, 0)
            # What a request-scoped session does on the way out.
            db.rollback()
        finally:
            db.close()

        self.assertEqual(len(self.outbox()), 1,
                         "the command vanished — deleted from the queue with "
                         "no history row to show for it")
        self.assertEqual(self.history(), [])
        self.assert_exactly_one_home("DATA UPDATE user Pin=1")

        # And it is still deliverable afterwards, having lost nothing.
        self.rewind_backoff(command_id)
        self.assertEqual(self.poll(), f"C:{command_id}:DATA UPDATE user Pin=1")

    def test_two_acks_racing_for_one_command_produce_exactly_one_log_row(self):
        """The DELETE's row count is the arbiter, not the read that precedes
        it, so the loser writes nothing."""
        from app.services import commands as command_service

        command_id = self.queue("DATA UPDATE user Pin=1")
        self.poll()

        first_db = self.Session()
        second_db = self.Session()
        try:
            # Both sessions read the row while it is still outstanding.
            row_a = first_db.query(command_service.DeviceCommandOutbox).get(command_id)
            row_b = second_db.query(command_service.DeviceCommandOutbox).get(command_id)
            self.assertIsNotNone(row_a)
            self.assertIsNotNone(row_b)

            self.assertTrue(command_service.conclude(first_db, row_a, "acknowledged", return_code=0))
            with self.assertLogs("app.services.commands", level="WARNING"):
                self.assertFalse(
                    command_service.conclude(second_db, row_b, "failed",
                                             last_error="racing loser"))
        finally:
            first_db.close()
            second_db.close()

        concluded = self.history()
        self.assertEqual(len(concluded), 1)
        self.assertEqual(concluded[0].outcome, "acknowledged")
        self.assertEqual(self.outbox(), [])


class CommandVisibilityTests(CommandDeliveryTestCase):
    """How an operator inspects the queue. API-only by deliberate choice."""

    def test_the_outbox_is_readable_and_shows_pending_as_pending(self):
        self.queue("DATA UPDATE user Pin=1")

        items = self.client.get(f"/devices/{self.SN}/commands").json()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["status"], "pending")
        self.assertEqual(items[0]["attempts"], 0)
        self.assertIsNone(items[0]["sent_at"])
        self.assertIsNone(items[0]["next_attempt_at"])
        self.assertEqual(items[0]["command"], "DATA UPDATE user Pin=1")

    def test_the_outbox_shows_a_delivery_in_flight(self):
        self.queue()
        self.poll()
        items = self.client.get(f"/devices/{self.SN}/commands").json()
        self.assertEqual(items[0]["status"], "sent")
        self.assertEqual(items[0]["attempts"], 1)
        self.assertIsNotNone(items[0]["sent_at"])
        self.assertIsNotNone(items[0]["next_attempt_at"])

    def test_history_distinguishes_a_refusal_from_a_giving_up(self):
        refused = self.queue("DATA UPDATE user Pin=1")
        self.poll()
        with self.assertLogs("app.services.commands", level="WARNING"):
            self.ack(refused, return_code=-14)

        from unittest import mock
        with mock.patch.object(config, "COMMAND_MAX_ATTEMPTS", 1):
            given_up = self.queue("DATA UPDATE user Pin=2")
            self.poll()
            self.rewind_backoff(given_up)
            with self.assertLogs("app.services.commands", level="WARNING"):
                self.poll()

        by_command = {i["command"]: i
                      for i in self.client.get(f"/devices/{self.SN}/commands/history").json()}

        self.assertEqual(by_command["DATA UPDATE user Pin=1"]["return_code"], -14)
        self.assertIn("rejected", by_command["DATA UPDATE user Pin=1"]["last_error"])

        self.assertIsNone(by_command["DATA UPDATE user Pin=2"]["return_code"])
        self.assertIn("no acknowledgement", by_command["DATA UPDATE user Pin=2"]["last_error"])

    def test_an_unknown_serial_is_a_404_on_both_views(self):
        self.assertEqual(self.client.get("/devices/NOSUCHSERIAL/commands").status_code, 404)
        self.assertEqual(
            self.client.get("/devices/NOSUCHSERIAL/commands/history").status_code, 404)

    def test_one_devices_history_never_shows_anothers(self):
        mine = self.queue("DATA UPDATE user Pin=1", sn=self.SN)
        self.poll(self.SN)
        self.ack(mine, sn=self.SN)

        theirs = self.queue("DATA UPDATE user Pin=2", sn=self.OTHER_SN)
        self.poll(self.OTHER_SN)
        self.ack(theirs, sn=self.OTHER_SN)

        items = self.client.get(f"/devices/{self.SN}/commands/history").json()
        self.assertEqual([i["command"] for i in items], ["DATA UPDATE user Pin=1"])


class DeadCommandTableTests(CommandDeliveryTestCase):
    """device_commands is superseded. Nothing may quietly start using it again."""

    def test_nothing_writes_to_the_old_table_any_more(self):
        from app.models import DeviceCommand

        command_id = self.queue("DATA UPDATE user Pin=1")
        self.poll()
        self.ack(command_id)

        db = self.Session()
        try:
            self.assertEqual(db.query(DeviceCommand).count(), 0,
                             "device_commands is dead — queue through "
                             "app/services/commands.py, not this table")
        finally:
            db.close()

    def test_a_row_left_in_the_old_table_is_never_delivered(self):
        """The one production row is a D3 test artefact. It must stay inert."""
        from app.models import DeviceCommand

        db = self.Session()
        try:
            db.add(DeviceCommand(device_sn=self.SN, command="DATA UPDATE user Pin=999",
                                 status="pending"))
            db.commit()
        finally:
            db.close()

        self.assertEqual(self.poll(), "OK")


class CommandSchemaTests(unittest.TestCase):
    """Both tables are new, so create_all builds them on every dialect and
    nothing has to widen the existing device_command_status enum in place."""

    def setUp(self):
        self.engine = create_engine("sqlite://", poolclass=StaticPool)
        Base.metadata.create_all(bind=self.engine)

    def tearDown(self):
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    def test_both_tables_are_created_with_every_column(self):
        columns = {
            table: {c["name"] for c in inspect(self.engine).get_columns(table)}
            for table in ("device_command_outbox", "device_command_log")
        }
        self.assertEqual(columns["device_command_outbox"], {
            "id", "device_sn", "command", "status", "attempts",
            "next_attempt_at", "created_at", "sent_at",
        })
        self.assertEqual(columns["device_command_log"], {
            "id", "device_sn", "command", "outcome", "attempts", "return_code",
            "last_error", "created_at", "sent_at", "concluded_at",
        })

    def test_the_old_enum_was_not_widened(self):
        """`failed` is a value on a NEW column of a NEW table. Adding it to
        device_command_status instead would have needed dialect-specific DDL
        (MariaDB MODIFY COLUMN, PostgreSQL ALTER TYPE ADD VALUE outside a
        transaction, MSSQL no native enum) that app/migrations.py cannot do."""
        from app.models import DeviceCommand, DeviceCommandLog, DeviceCommandOutbox

        self.assertEqual(
            set(DeviceCommand.__table__.c.status.type.enums),
            {"pending", "sent", "acknowledged"},
            "the old enum must be left exactly as it was",
        )
        self.assertEqual(
            set(DeviceCommandOutbox.__table__.c.status.type.enums),
            {"pending", "sent"},
            "only outstanding states belong in the outbox",
        )
        self.assertEqual(
            set(DeviceCommandLog.__table__.c.outcome.type.enums),
            {"acknowledged", "failed"},
        )

    def test_a_command_longer_than_the_old_500_char_limit_fits(self):
        """E3/E4 push biophoto/facev7 commands whose Content= is base64 image
        or template data, which the dead table's String(500) would truncate."""
        from app.models import DeviceCommandOutbox

        long_command = "DATA UPDATE biophoto PIN=1\tContent=" + ("A" * 40000)
        Session = sessionmaker(bind=self.engine)
        db = Session()
        try:
            db.add(DeviceCommandOutbox(device_sn="X", command=long_command,
                                       status="pending", attempts=0,
                                       created_at=datetime.now(timezone.utc)))
            db.commit()
            self.assertEqual(len(db.query(DeviceCommandOutbox).first().command),
                             len(long_command))
        finally:
            db.close()


# ---------------------------------------------------------------------------
# 20. E3 — creating a person centrally and provisioning them onto a terminal
# ---------------------------------------------------------------------------
#
# This is the first code in the application that writes to physical
# access-control hardware, so the assertions below are about literal bytes and
# about which table a row does *not* appear in, not about status codes.
#
# The two failure modes being guarded:
#
#   1. A command shape the terminal refuses, or — worse — accepts with the
#      wrong meaning. Hence the exact-string assertions against §3.8, taken
#      from the vendor's own worked example rather than from the code.
#   2. Both transports writing device_employees for the same (device, user),
#      which is the collision the whole bulk-data programme is routed around.


class ProvisioningTestCase(CommandDeliveryTestCase):
    """Devices + ADMS + employees routers over one database.

    Inherits the two `acc` terminals and the admin session from the E7 case
    and adds an `att` one, because the point of these tests is the difference
    between them.
    """

    ATT_SN = "E3ATTTEST00001"
    DEFAULT_SN = "E3DEFAULT00001"

    def setUp(self):
        super().setUp()
        from app.routers import employees as employees_router
        # The app object the E7 fixture built; routes are consulted per
        # request, so including another router now is enough.
        self.client.app.include_router(employees_router.router)

        db = self.Session()
        try:
            db.add(Device(serial_number=self.ATT_SN, ip_address="203.0.113.11",
                          port=4370, name="Attendance terminal",
                          status="approved", protocol="att"))
            # Deliberately does NOT set protocol: this is what a device row
            # that nobody has classified looks like.
            db.add(Device(serial_number=self.DEFAULT_SN, ip_address="203.0.113.12",
                          port=4370, name="Unclassified terminal",
                          status="approved"))
            db.commit()
        finally:
            db.close()

    # -- helpers ---------------------------------------------------------

    def create_employee(self, user_id="9001", **fields):
        payload = {"user_id": user_id}
        payload.update(fields)
        return self.client.post("/employees", json=payload)

    def links(self, sn=None):
        db = self.Session()
        try:
            query = db.query(DeviceEmployee)
            if sn:
                query = query.filter_by(device_sn=sn)
            return query.order_by(DeviceEmployee.id).all()
        finally:
            db.close()

    def employee(self, user_id):
        db = self.Session()
        try:
            return db.query(Employee).filter_by(user_id=user_id).first()
        finally:
            db.close()

    def push(self, sn, user_id):
        return self.client.post(f"/devices/{sn}/users/{user_id}/push")


class FakeConnection:
    """Just enough pyzk for the SDK push path, and a record of what it wrote."""

    def __init__(self, next_uid=5, users=()):
        self.next_uid = next_uid
        self._users = list(users)
        self.written = []

    def get_users(self):
        return self._users

    def set_user(self, **kwargs):
        self.written.append(kwargs)


def fake_sdk(conn):
    """Patch for app.routers.devices.device_connection."""
    from contextlib import contextmanager

    @contextmanager
    def _connect(device):
        yield conn

    return _connect


# ---------------------------------------------------------------------------
# 20a. The command shapes, against the vendor's own text
# ---------------------------------------------------------------------------

class ProvisioningCommandShapeTests(unittest.TestCase):
    """The literal bytes. §3.8 is the authority; this file is not.

    Verbatim from the protocol reference, with <HT> spelled as the tab it is::

        DATA UPDATE user Pin=1<HT>CardNo=<n><HT>Password=234<HT>Group=0<HT>
        StartTime=0<HT>EndTime=0<HT>Name=<s><HT>Privilege=0
        DATA UPDATE userauthorize Pin=<n><HT>AuthorizeTimezoneId=<n>

    If a refactor reorders or renames a field, or turns one separator into a
    space, this fails — which is the only warning available before a real
    terminal either misreads the record or refuses it.
    """

    def setUp(self):
        from app.services import provisioning
        self.provisioning = provisioning

    def employee(self, **fields):
        values = dict(user_id="9001", name="Aisha Rahman", privilege=0, card="0")
        values.update(fields)
        return Employee(**values)

    def test_the_user_command_is_exactly_the_documented_shape(self):
        self.assertEqual(
            self.provisioning.user_command(self.employee()),
            "DATA UPDATE user Pin=9001\tCardNo=0\tPassword=\tGroup=0\t"
            "StartTime=0\tEndTime=0\tName=Aisha Rahman\tPrivilege=0",
        )

    def test_the_authorize_command_is_exactly_the_documented_shape(self):
        self.assertEqual(
            self.provisioning.authorize_command("9001"),
            "DATA UPDATE userauthorize Pin=9001\tAuthorizeTimezoneId=1",
        )

    def test_the_command_name_is_space_separated_and_the_fields_are_tabs(self):
        """§3.8, verbatim: 'the command name is space-separated, its fields are
        TAB-separated'. Getting this backwards produces a command the device
        parses as one enormous field."""
        command = self.provisioning.user_command(self.employee())
        head, _, rest = command.partition("Pin=")
        self.assertEqual(head, "DATA UPDATE user ")
        self.assertNotIn("\t", head)
        self.assertEqual(len(command.split("\t")), 8)

    def test_every_documented_field_is_present_in_order(self):
        fields = self.provisioning.user_command(self.employee()).split("\t")
        names = [f.split("=")[0] for f in fields]
        names[0] = names[0].replace("DATA UPDATE user ", "")
        self.assertEqual(names, [
            "Pin", "CardNo", "Password", "Group",
            "StartTime", "EndTime", "Name", "Privilege",
        ])

    def test_a_card_number_is_carried_and_a_missing_one_becomes_zero(self):
        self.assertIn("CardNo=778899",
                      self.provisioning.user_command(self.employee(card="778899")))
        for empty in ("", "0", None):
            self.assertIn("CardNo=0",
                          self.provisioning.user_command(self.employee(card=empty)))

    def test_privilege_zero_is_written_not_dropped(self):
        """0 is a real privilege (ordinary user), not a missing one."""
        self.assertTrue(
            self.provisioning.user_command(self.employee(privilege=0))
            .endswith("Privilege=0")
        )
        self.assertTrue(
            self.provisioning.user_command(self.employee(privilege=14))
            .endswith("Privilege=14")
        )

    def test_a_tab_in_a_name_cannot_forge_an_extra_field(self):
        """Field injection. A name is operator input; a raw TAB inside it would
        invent a field boundary and could hand somebody Privilege=14."""
        command = self.provisioning.user_command(
            self.employee(name="Aisha\tPrivilege=14")
        )
        fields = command.split("\t")
        # Still eight fields, and the injected text is a value inside the Name
        # field rather than a field of its own — the device splits on TAB and
        # then on the first "=", so it reads this person's name as the whole
        # string "Aisha Privilege=14".
        self.assertEqual(len(fields), 8)
        self.assertEqual(fields[6], "Name=Aisha Privilege=14")
        self.assertEqual(fields[7], "Privilege=0")

    def test_a_newline_in_a_name_cannot_forge_an_extra_record(self):
        """Records are LF-separated, so a newline is a second command."""
        command = self.provisioning.user_command(
            self.employee(name="Aisha\nDATA DELETE user Pin=1")
        )
        fields = command.split("\t")
        # One line, one command, eight fields: the injected text is carried as
        # part of the name, not as a second record the device would execute.
        self.assertNotIn("\n", command)
        self.assertNotIn("\r", command)
        self.assertEqual(len(fields), 8)
        self.assertEqual(fields[6], "Name=Aisha DATA DELETE user Pin=1")
        self.assertTrue(command.startswith("DATA UPDATE user Pin=9001\t"))

    def test_the_authorize_timezone_is_configurable(self):
        original = config.PROVISION_AUTHORIZE_TIMEZONE_ID
        try:
            config.PROVISION_AUTHORIZE_TIMEZONE_ID = 7
            self.assertEqual(
                self.provisioning.authorize_command("9001"),
                "DATA UPDATE userauthorize Pin=9001\tAuthorizeTimezoneId=7",
            )
        finally:
            config.PROVISION_AUTHORIZE_TIMEZONE_ID = original

    def test_the_default_authorize_timezone_is_not_zero(self):
        """0 means 'no access time zone': the person verifies and the door
        stays shut. That half-success is the thing this unit exists to avoid,
        so it must not be what an operator gets by doing nothing."""
        self.assertNotEqual(config.PROVISION_AUTHORIZE_TIMEZONE_ID, 0)

    def test_both_commands_are_produced_in_delivery_order(self):
        bodies = self.provisioning.commands_for(self.employee())
        self.assertEqual(len(bodies), 2)
        self.assertTrue(bodies[0].startswith("DATA UPDATE user "))
        self.assertTrue(bodies[1].startswith("DATA UPDATE userauthorize "))

    def test_only_the_user_command_identifies_a_provisioned_person(self):
        """An acknowledged door permission is not evidence that the terminal
        accepted the person, so it must not create a device link."""
        self.assertEqual(
            self.provisioning.pin_from_user_command(
                "DATA UPDATE user Pin=9001\tCardNo=0"), "9001")
        self.assertIsNone(self.provisioning.pin_from_user_command(
            "DATA UPDATE userauthorize Pin=9001\tAuthorizeTimezoneId=1"))
        self.assertIsNone(self.provisioning.pin_from_user_command(
            "DATA UPDATE biophoto PIN=9001\tContent=xx"))
        self.assertIsNone(self.provisioning.pin_from_user_command("REBOOT"))


# ---------------------------------------------------------------------------
# 20b. Employee creation and editing
# ---------------------------------------------------------------------------

class EmployeeCreationTests(ProvisioningTestCase):
    """Admin-authored people, written through the one employee writer."""

    def test_an_operator_can_create_an_employee(self):
        response = self.create_employee("9001", name="Aisha Rahman", card="778899")
        self.assertEqual(response.status_code, 201, response.text)
        emp = self.employee("9001")
        self.assertEqual((emp.name, emp.card, emp.privilege),
                         ("Aisha Rahman", "778899", 0))

    def test_a_created_employee_is_on_no_device_yet(self):
        """Creating somebody centrally must not put them on a door. Which
        doors a person may open is an explicit, per-device decision."""
        self.create_employee("9001", name="Aisha Rahman")
        self.assertEqual(self.links(), [])
        self.assertEqual(self.outbox(), [])

    def test_a_missing_card_is_stored_as_the_no_card_convention(self):
        self.create_employee("9002", name="Bilal")
        self.assertEqual(self.employee("9002").card, "0")

    def test_a_duplicate_pin_is_refused_rather_than_merged(self):
        """The PIN is the device's key for a person. Merging a typo into
        somebody else's row would attach the wrong face to the wrong name."""
        self.create_employee("9001", name="Aisha Rahman")
        response = self.create_employee("9001", name="Someone Else")
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(self.employee("9001").name, "Aisha Rahman")

    def test_creation_and_editing_go_through_the_shared_writer(self):
        """Structural, not behavioural: E1 removed a competing writer to make
        employee_sync the only one. This fails if anyone adds a third."""
        import inspect as _inspect
        from app.routers import employees as employees_router

        source = _inspect.getsource(employees_router)
        self.assertIn("employee_sync.create_employee", source)
        self.assertIn("employee_sync.apply_operator_edit", source)
        self.assertNotIn("db.add(Employee(", source)

    def test_employee_sync_is_the_only_module_that_writes_employees(self):
        """Repo-wide. The guard E1 put on the poller, widened to everything."""
        import pathlib
        offenders = []
        for path in pathlib.Path("app").rglob("*.py"):
            if path.name == "employee_sync.py":
                continue
            text_ = path.read_text()
            if "db.add(Employee(" in text_ or "db.add(DeviceEmployee(" in text_:
                offenders.append(str(path))
        self.assertEqual(offenders, [])

    def test_creating_and_editing_are_admin_only(self):
        """The endpoints are proved to require an admin by their declaration,
        which is testable without a session; require_admin itself is D1's."""
        import inspect as _inspect
        from fastapi import params
        from app.deps import require_admin
        from app.routers import employees as employees_router

        for endpoint in (employees_router.create_employee,
                         employees_router.update_employee):
            dependencies = [
                p.default.dependency
                for p in _inspect.signature(endpoint).parameters.values()
                if isinstance(p.default, params.Depends)
            ]
            self.assertIn(require_admin, dependencies, endpoint.__name__)

    # -- editing ---------------------------------------------------------

    def test_a_deliberate_edit_can_clear_a_name(self):
        """The difference between the two kinds of source. A device saying
        `name=` means 'nothing to say'; an operator emptying the field means
        'remove it', and both go through the same module."""
        self.create_employee("9001", name="Aisha Rahman")
        response = self.client.patch("/employees/9001", json={"name": ""})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.employee("9001").name, "")

    def test_a_device_still_cannot_clear_what_an_operator_typed(self):
        """E1's rule survives the new writer."""
        self.create_employee("9001", name="Aisha Rahman", card="778899")
        self.client.post(
            f"/iclock/cdata?SN={self.SN}&table=tabledata&tablename=user&count=1",
            content="user uid=1\tpin=9001\tname=\tcardno=\n",
        )
        emp = self.employee("9001")
        self.assertEqual(emp.name, "Aisha Rahman")
        self.assertEqual(emp.card, "778899")

    def test_an_edit_touches_only_the_fields_that_were_sent(self):
        self.create_employee("9001", name="Aisha Rahman", card="778899")
        self.client.patch("/employees/9001", json={"card": "112233"})
        emp = self.employee("9001")
        self.assertEqual(emp.card, "112233")
        self.assertEqual(emp.name, "Aisha Rahman")

    def test_an_edit_can_clear_a_card(self):
        self.create_employee("9001", name="Aisha Rahman", card="778899")
        self.client.patch("/employees/9001", json={"card": ""})
        self.assertEqual(self.employee("9001").card, "0")

    def test_privilege_can_be_lowered_to_zero(self):
        """0 is a value, not an absence — demoting a device admin has to work."""
        self.create_employee("9001", name="Aisha Rahman", privilege=14)
        self.client.patch("/employees/9001", json={"privilege": 0})
        self.assertEqual(self.employee("9001").privilege, 0)

    def test_editing_somebody_who_does_not_exist_is_a_404(self):
        self.assertEqual(
            self.client.patch("/employees/nobody", json={"name": "X"}).status_code, 404)

    def test_an_edit_does_not_push_anything_to_any_device(self):
        """A silent fan-out to every terminal is exactly the auto-push the
        operator ruled out. The device keeps the old record until pushed."""
        self.create_employee("9001", name="Aisha Rahman")
        self.push(self.SN, "9001")
        before = len(self.outbox())
        self.client.patch("/employees/9001", json={"name": "Aisha R"})
        self.assertEqual(len(self.outbox()), before)


# ---------------------------------------------------------------------------
# 20c. Provisioning onto an `acc` terminal, over the queue
# ---------------------------------------------------------------------------

class AccProvisioningTests(ProvisioningTestCase):

    def setUp(self):
        super().setUp()
        self.create_employee("9001", name="Aisha Rahman", card="778899")

    def test_a_push_queues_the_user_record_and_the_door_permission(self):
        """Both, in order. A user command without an authorize command is a
        person the terminal recognises and refuses."""
        response = self.push(self.SN, "9001")
        self.assertEqual(response.status_code, 202, response.text)

        queued = [row.command for row in self.outbox(self.SN)]
        self.assertEqual(queued, [
            "DATA UPDATE user Pin=9001\tCardNo=778899\tPassword=\tGroup=0\t"
            "StartTime=0\tEndTime=0\tName=Aisha Rahman\tPrivilege=0",
            "DATA UPDATE userauthorize Pin=9001\tAuthorizeTimezoneId=1",
        ])

    def test_the_bytes_the_device_is_handed_carry_the_id_envelope(self):
        """§3.8 on the wire: C:<id>:<command>. Without the id the device has
        nothing to quote back and the acknowledgement cannot be matched."""
        self.push(self.SN, "9001")
        ids = [row.id for row in self.outbox(self.SN)]

        self.assertEqual(
            self.poll(),
            f"C:{ids[0]}:DATA UPDATE user Pin=9001\tCardNo=778899\tPassword=\t"
            "Group=0\tStartTime=0\tEndTime=0\tName=Aisha Rahman\tPrivilege=0",
        )
        self.assertEqual(
            self.poll(),
            f"C:{ids[1]}:DATA UPDATE userauthorize Pin=9001\tAuthorizeTimezoneId=1",
        )

    def test_the_response_says_queued_and_does_not_claim_success(self):
        body = self.push(self.SN, "9001").json()
        self.assertEqual(body["status"], "queued")
        self.assertEqual(body["transport"], "adms_queue")
        self.assertIn("not delivered yet", body["message"])
        self.assertEqual(len(body["command_ids"]), 2)

    def test_pushing_somebody_who_does_not_exist_is_a_404(self):
        self.assertEqual(self.push(self.SN, "nobody").status_code, 404)
        self.assertEqual(self.outbox(), [])

    def test_pushing_to_an_unknown_device_is_a_404(self):
        self.assertEqual(self.push("NOSUCHSERIAL", "9001").status_code, 404)
        self.assertEqual(self.outbox(), [])

    def test_a_push_is_per_device_and_never_fans_out(self):
        """Manual and explicit, per the operator's decision."""
        self.push(self.SN, "9001")
        self.assertEqual(len(self.outbox(self.SN)), 2)
        self.assertEqual(self.outbox(self.OTHER_SN), [])

    def test_an_unnamed_person_is_pushed_as_their_pin_not_an_invented_name(self):
        self.create_employee("9002")
        self.push(self.SN, "9002")
        self.assertIn("Name=\tPrivilege=0", self.outbox(self.SN)[0].command)

    # -- what an acknowledgement means --------------------------------------

    def test_no_device_link_exists_until_the_device_acknowledges(self):
        """Queued is not delivered, so `enrolled on this device` is not yet
        true and the table must not say it is."""
        self.push(self.SN, "9001")
        self.assertEqual(self.links(), [])

        self.poll()          # device collects the user command
        self.assertEqual(self.links(), [])   # collected, not yet confirmed

    def test_the_link_appears_when_the_user_command_is_acknowledged(self):
        self.push(self.SN, "9001")
        user_id_command = self.outbox(self.SN)[0].id
        self.poll()
        self.ack(user_id_command, return_code=0)

        links = self.links(self.SN)
        self.assertEqual([l.user_id for l in links], ["9001"])
        # Un-slotted: the terminal assigns its own uid and never tells us
        # what it chose. Inventing one would make a later SDK write address
        # the wrong user.
        self.assertEqual(links[0].uid, 0)

    def test_acknowledging_the_authorize_command_adds_no_second_link(self):
        self.push(self.SN, "9001")
        first, second = [row.id for row in self.outbox(self.SN)]
        self.poll()
        self.ack(first, return_code=0)
        self.poll()
        self.ack(second, return_code=0)
        self.assertEqual(len(self.links(self.SN)), 1)

    def test_a_refused_user_command_leaves_no_link_behind(self):
        """A non-zero Return is the device rejecting the record. Recording the
        person as provisioned anyway would be the lie that matters most."""
        self.push(self.SN, "9001")
        command_id = self.outbox(self.SN)[0].id
        self.poll()
        self.ack(command_id, return_code=-14)

        self.assertEqual(self.links(), [])
        concluded = [r for r in self.history(self.SN) if r.outcome == "failed"]
        self.assertEqual(len(concluded), 1)
        self.assertEqual(concluded[0].return_code, -14)

    def test_an_acknowledgement_in_the_query_string_also_provisions(self):
        """Which of the two framings this firmware uses is unverified — §3.9
        says body, §3.8's example reads as a query string. Both must work."""
        self.push(self.SN, "9001")
        command_id = self.outbox(self.SN)[0].id
        self.poll()
        self.ack(command_id, return_code=0, in_query=True)
        self.assertEqual([l.user_id for l in self.links(self.SN)], ["9001"])

    def test_an_ack_for_a_command_that_was_never_issued_provisions_nobody(self):
        self.ack(4242, return_code=0)
        self.assertEqual(self.links(), [])

    def test_a_second_push_of_the_same_person_does_not_duplicate_the_link(self):
        for _ in range(2):
            self.push(self.SN, "9001")
        for row in list(self.outbox(self.SN)):
            self.poll()
            self.ack(row.id, return_code=0)
        self.assertEqual(len(self.links(self.SN)), 1)

    def test_bulk_provisioning_queues_everyone_and_reports_the_wait(self):
        """Batching is not raised speculatively: one command per ~10s poll, so
        the honest thing to report is how long the queue will take to drain."""
        self.create_employee("9002", name="Bilal Khan")
        response = self.client.post(f"/devices/{self.SN}/users/push_bulk",
                                    json={"user_ids": ["9001", "9002", "nobody"]})
        self.assertEqual(response.status_code, 202, response.text)
        body = response.json()
        self.assertEqual(body["status"], "queued")
        self.assertEqual(body["pushed"], ["9001", "9002"])
        self.assertEqual(len(body["errors"]), 1)
        self.assertEqual(len(self.outbox(self.SN)), 4)
        self.assertIn("40 seconds", body["message"])
        self.assertEqual(config.COMMAND_BATCH_SIZE, 1)


# ---------------------------------------------------------------------------
# 20d. Transport routing: never both, for the same (device, user)
# ---------------------------------------------------------------------------

class TransportRoutingTests(ProvisioningTestCase):
    """The collision the whole bulk-data programme is routed around.

    The SDK path writes device_employees synchronously; the ADMS path writes
    it on acknowledgement. If a device could take both, the two would race and
    disagree about uid. It cannot: the transport is a function of
    Device.protocol, and a device has exactly one.
    """

    def setUp(self):
        super().setUp()
        self.create_employee("9001", name="Aisha Rahman", card="778899")

    def test_an_att_device_uses_the_sdk_and_never_touches_the_outbox(self):
        from unittest import mock
        conn = FakeConnection(next_uid=5)
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            response = self.push(self.ATT_SN, "9001")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["transport"], "sdk")
        self.assertEqual(response.json()["status"], "written")
        self.assertEqual(len(conn.written), 1)
        self.assertEqual(conn.written[0]["user_id"], "9001")
        self.assertEqual(self.outbox(self.ATT_SN), [])
        self.assertEqual([l.uid for l in self.links(self.ATT_SN)], [5])

    def test_an_acc_device_uses_the_queue_and_never_opens_a_socket(self):
        from unittest import mock
        conn = FakeConnection()
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            self.push(self.SN, "9001")

        self.assertEqual(conn.written, [])
        self.assertEqual(len(self.outbox(self.SN)), 2)
        self.assertEqual(self.links(self.SN), [])

    def test_a_device_with_no_protocol_set_takes_the_sdk_path(self):
        """Predictable, and deliberately the loud direction: an SDK push to a
        device that cannot answer fails with a 503 in front of the operator,
        whereas acc-shaped commands queued to an attendance terminal would sit
        in the outbox looking healthy and be refused on collection."""
        from unittest import mock
        conn = FakeConnection(next_uid=9)
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            response = self.push(self.DEFAULT_SN, "9001")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["transport"], "sdk")
        self.assertEqual(self.outbox(self.DEFAULT_SN), [])

    def test_the_routing_function_is_total_and_defaults_to_the_sdk(self):
        """Including for values no column constraint allows but a stale row
        might still hold."""
        from app.routers import devices as devices_router

        class Stub:
            def __init__(self, protocol):
                self.protocol = protocol

        self.assertTrue(devices_router._uses_command_queue(Stub("acc")))
        for value in ("att", None, "", "ACC-ish", "unknown"):
            self.assertFalse(devices_router._uses_command_queue(Stub(value)), value)

    def test_neither_transport_writes_device_employees_inline(self):
        """Both go through employee_sync.link_device_employee. This is the
        structural half of the proof; the behavioural half is above."""
        import inspect as _inspect
        from app.routers import devices as devices_router
        from app.services import provisioning

        for module in (devices_router, provisioning):
            source = _inspect.getsource(module)
            self.assertNotIn("db.add(DeviceEmployee(", source, module.__name__)
        self.assertIn("employee_sync.link_device_employee",
                      _inspect.getsource(devices_router))
        self.assertIn("employee_sync.link_device_employee",
                      _inspect.getsource(provisioning))

    def test_one_pair_ends_with_one_link_even_if_the_protocol_is_corrected(self):
        """The only way a pair could see both transports is an operator
        correcting the protocol between two pushes (E6). The link converges on
        one row rather than growing a second."""
        from unittest import mock

        self.push(self.SN, "9001")
        user_command_id = self.outbox(self.SN)[0].id
        self.poll()
        self.ack(user_command_id, return_code=0)
        self.assertEqual(len(self.links(self.SN)), 1)
        self.assertEqual(self.links(self.SN)[0].uid, 0)

        db = self.Session()
        try:
            db.query(Device).filter_by(serial_number=self.SN).first().protocol = "att"
            db.commit()
        finally:
            db.close()

        conn = FakeConnection(next_uid=11)
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            self.push(self.SN, "9001")

        links = self.links(self.SN)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].uid, 11)   # converged on the real slot number

    def test_an_unreachable_att_device_reports_a_failure_rather_than_queueing(self):
        """Asymmetric fallback, per the shared constraint: SDK failure is
        detectable, so it is reported. It does NOT silently become a queued
        acc-shaped command the terminal has no tables for."""
        from unittest import mock
        from zk.exception import ZKNetworkError

        def _boom(device):
            raise ZKNetworkError("unreachable")

        with mock.patch("app.routers.devices.device_connection", _boom):
            response = self.push(self.ATT_SN, "9001")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.outbox(self.ATT_SN), [])
        self.assertEqual(self.links(self.ATT_SN), [])


# ---------------------------------------------------------------------------
# 20e. E4 — enrol once, work everywhere: pushing a captured template onward
# ---------------------------------------------------------------------------
#
# The highest-consequence write in this application. A `DATA UPDATE BIODATA`
# command puts a biometric credential onto physical door hardware, so the
# assertions here are about literal bytes, about which device a template is
# NOT sent to, and about the order two commands are queued in — never about
# status codes alone.
#
# Four failure modes are guarded:
#
#   1. A command shape the terminal misreads. §3.8's field names are CamelCase
#      (`Index`, `MajorVer`, `Tmp`) while the upload that produced the stored
#      row used lowercase; getting that asymmetry wrong writes a credential
#      the device parses differently than intended.
#   2. A template pushed back to the device that captured it — wasted work at
#      best, and at worst this server overwriting a terminal's own live
#      enrolment with its copy of it.
#   3. A template landing on a terminal that never accepted the person, which
#      is a credential attached to nobody and invisible from the server.
#   4. Both transports writing the same device, which is the collision the
#      whole bulk-data programme is routed around.

# One record from the operator's own BioFace A1 capture, and one invented
# alongside it, so the command below is built from data a real device sent.
CAPTURED_FACE_TMP = "apUBFjYCAABuuOlOCQAoAQFM+ZoWAGJobX4kJSYnGSkqKw=="
CAPTURED_FINGER_TMP = "apUBEBgEfAQBAA0AAVH4AAgJCgs42CmiExIxE2A4o0xKdg=="


class _TemplateRow:
    """A BiometricTemplate's fields without a database behind it."""

    def __init__(self, **fields):
        defaults = dict(
            id=1, user_id="1", no=0, record_index=0, valid=1, duress=0,
            type=9, majorver=40, minorver=1, format=0, tmp=CAPTURED_FACE_TMP,
            source_device_sn=ACC_SN,
        )
        defaults.update(fields)
        for key, value in defaults.items():
            setattr(self, key, value)


class BiodataCommandShapeTests(unittest.TestCase):
    """The literal bytes, against the vendor's own command constant.

    Verbatim from push-protocol.md §3.8, which took it from ZKTeco's
    access-control SDK (`Access/Commands.cs`)::

        DATA UPDATE BIODATA Pin={0}\tNo={1}\tIndex={2}\tValid={3}\tDuress={4}
        \tType={5}\tMajorVer={6}\tMinorVer={7}\tFormat={8}\tTmp={9}

    This file is not the authority on that string; the vendor is. The literals
    below are transcribed from the protocol reference, not from the code.
    """

    def test_the_command_is_byte_for_byte_the_vendor_shape(self):
        from app.services import provisioning

        command = provisioning.biodata_command(_TemplateRow(
            user_id="9001", no=3, record_index=9, valid=1, duress=1, type=1,
            majorver=13, minorver=2, format=1, tmp="QUJDREVGRw==",
        ))
        self.assertEqual(
            command,
            "DATA UPDATE BIODATA Pin=9001\tNo=3\tIndex=9\tValid=1\tDuress=1\t"
            "Type=1\tMajorVer=13\tMinorVer=2\tFormat=1\tTmp=QUJDREVGRw==",
        )

    def test_the_separator_is_a_tab_and_the_command_name_is_spaced(self):
        """§3.8: the command *name* is space-separated, its *fields* are
        TAB-separated. A single space where a tab belongs is a command the
        terminal cannot parse, and it is exactly the kind of thing an editor
        or a copy-paste turns silently."""
        from app.services import provisioning

        command = provisioning.biodata_command(_TemplateRow(user_id="7"))
        head, sep, rest = command.partition("\t")
        self.assertEqual(head, "DATA UPDATE BIODATA Pin=7")
        self.assertEqual(sep, "\t")
        self.assertEqual(command.count("\t"), 9)      # ten fields, nine separators
        self.assertNotIn("\n", command)
        self.assertNotIn("  ", command)

    def test_the_field_names_are_camelcase_not_the_uploads_lowercase(self):
        """The documented §3.7/§3.8 asymmetry: `index=` arrives, `Index=` is
        sent back. Renaming either to match the other is the mistake."""
        from app.services import provisioning

        command = provisioning.biodata_command(_TemplateRow())
        names = [field.split("=")[0] for field in
                 command.replace("DATA UPDATE BIODATA ", "").split("\t")]
        self.assertEqual(names, [
            "Pin", "No", "Index", "Valid", "Duress", "Type",
            "MajorVer", "MinorVer", "Format", "Tmp",
        ])
        for lowercase in ("pin=", "index=", "type=", "majorver=", "tmp="):
            self.assertNotIn(lowercase, command)

    def test_every_field_comes_from_storage_and_nothing_is_defaulted(self):
        """E2 kept `duress`, `index`, `majorver`, `minorver` and `format`
        verbatim precisely so this command never has to invent them."""
        from app.services import provisioning

        row = _TemplateRow(user_id="42", no=5, record_index=7, valid=0,
                           duress=1, type=1, majorver=13, minorver=4, format=2,
                           tmp=CAPTURED_FINGER_TMP)
        command = provisioning.biodata_command(row)
        for expected in ("Pin=42", "No=5", "Index=7", "Valid=0", "Duress=1",
                         "Type=1", "MajorVer=13", "MinorVer=4", "Format=2",
                         f"Tmp={CAPTURED_FINGER_TMP}"):
            self.assertIn(expected, command)

    def test_the_template_bytes_are_replayed_untouched(self):
        """Not decoded, not re-encoded, not padded, not trimmed. The server
        has no business understanding a template — only holding it."""
        from app.services import provisioning

        command = provisioning.biodata_command(_TemplateRow(tmp=CAPTURED_FACE_TMP))
        self.assertTrue(command.endswith(f"\tTmp={CAPTURED_FACE_TMP}"))

    def test_the_type_is_passed_through_and_never_interpreted(self):
        """`type` is the device's data. 1 and 9 have been read as fingerprint
        and visible-light face in the field, but nothing branches on that and
        an unfamiliar value must still be sent, not dropped."""
        from app.services import provisioning

        for value in (0, 1, 2, 8, 9, 23):
            command = provisioning.biodata_command(_TemplateRow(type=value))
            self.assertIn(f"\tType={value}\t", command)

    def test_a_tab_inside_the_template_is_refused_not_stripped(self):
        """Trimming a character out of a credential to make it fit the wire is
        the one thing worse than refusing to send it."""
        from app.services import provisioning

        with self.assertRaises(ValueError) as caught:
            provisioning.biodata_command(_TemplateRow(tmp="AAAA\tBBBB"))
        self.assertIn("Tmp", str(caught.exception))

    def test_a_newline_inside_the_template_is_refused_too(self):
        """A newline would invent a whole extra record (§3.8: records are
        LF-separated), so half the template would be read as a second one."""
        from app.services import provisioning

        with self.assertRaises(ValueError):
            provisioning.biodata_command(_TemplateRow(tmp="AAAA\nBBBB"))

    def test_a_missing_field_is_refused_rather_than_guessed(self):
        from app.services import provisioning

        with self.assertRaises(ValueError):
            provisioning.biodata_command(_TemplateRow(majorver=None))


class TemplatePushTestCase(ProvisioningTestCase):
    """The endpoint, over the same two acc terminals and one att terminal."""

    def setUp(self):
        super().setUp()
        self.create_employee("9001", name="Aisha Rahman", card="778899")

    def add_template(self, user_id="9001", type=9, no=0, source=None, **fields):
        row = dict(
            user_id=user_id, type=type, no=no, record_index=0, valid=1,
            duress=0, majorver=40, minorver=1, format=0,
            tmp=CAPTURED_FACE_TMP, source_device_sn=source or self.OTHER_SN,
        )
        row.update(fields)
        db = self.Session()
        try:
            db.add(BiometricTemplate(**row))
            db.commit()
        finally:
            db.close()

    def push_templates(self, sn, user_id="9001"):
        return self.client.post(f"/devices/{sn}/users/{user_id}/templates/push")

    def commands_on(self, sn):
        return [row.command for row in self.outbox(sn)]

    def link(self, sn, user_id="9001"):
        """Pretend the terminal has already confirmed it holds this person."""
        db = self.Session()
        try:
            employee_sync.link_device_employee(db, sn, user_id)
            db.commit()
        finally:
            db.close()


class TemplatePushQueueTests(TemplatePushTestCase):
    """What lands in the outbox, and in what order."""

    def test_the_queued_command_is_the_vendor_shape_byte_for_byte(self):
        self.add_template(no=2, record_index=4, type=9, majorver=40,
                          minorver=1, format=0, tmp=CAPTURED_FACE_TMP)
        self.link(self.SN)          # person already confirmed on this terminal

        response = self.push_templates(self.SN)
        self.assertEqual(response.status_code, 202, response.text)

        self.assertEqual(self.commands_on(self.SN), [
            "DATA UPDATE BIODATA Pin=9001\tNo=2\tIndex=4\tValid=1\tDuress=0\t"
            "Type=9\tMajorVer=40\tMinorVer=1\tFormat=0\t"
            f"Tmp={CAPTURED_FACE_TMP}",
        ])

    def test_the_bytes_the_device_is_handed_carry_the_id_envelope(self):
        self.add_template(no=2)
        self.link(self.SN)
        self.push_templates(self.SN)
        command_id = self.outbox(self.SN)[0].id

        self.assertEqual(
            self.poll(),
            f"C:{command_id}:DATA UPDATE BIODATA Pin=9001\tNo=2\tIndex=0\t"
            f"Valid=1\tDuress=0\tType=9\tMajorVer=40\tMinorVer=1\tFormat=0\t"
            f"Tmp={CAPTURED_FACE_TMP}",
        )

    def test_two_templates_are_queued_as_two_commands(self):
        self.add_template(type=1, no=5, tmp=CAPTURED_FINGER_TMP)
        self.add_template(type=9, no=0, tmp=CAPTURED_FACE_TMP)
        self.link(self.SN)

        self.push_templates(self.SN)
        queued = self.commands_on(self.SN)
        self.assertEqual(len(queued), 2)
        self.assertIn("\tType=1\t", queued[0])
        self.assertIn("\tType=9\t", queued[1])

    def test_the_response_says_queued_and_does_not_claim_success(self):
        self.add_template()
        self.link(self.SN)
        body = self.push_templates(self.SN).json()
        self.assertEqual(body["status"], "queued")
        self.assertEqual(body["transport"], "adms_queue")
        self.assertEqual(body["templates_queued"], 1)
        self.assertIn("not delivered yet", body["message"])

    def test_the_response_never_carries_the_template_bytes(self):
        """A credential does not need to travel back out of the database to a
        browser to be logged, cached or screenshotted."""
        self.add_template()
        self.link(self.SN)
        body = self.push_templates(self.SN).json()
        self.assertNotIn(CAPTURED_FACE_TMP, response_text := str(body))
        self.assertNotIn("Tmp=", response_text)
        self.assertEqual(body["commands"], ["DATA UPDATE BIODATA Pin=9001"])

    def test_a_push_is_per_device_and_never_fans_out(self):
        self.add_template(source=self.ATT_SN)
        self.link(self.SN)
        self.push_templates(self.SN)
        self.assertEqual(len(self.outbox(self.SN)), 1)
        self.assertEqual(self.outbox(self.OTHER_SN), [])

    def test_the_queue_stays_at_one_command_per_poll(self):
        """Two templates plus a user record is four commands and about forty
        seconds. The batch size is not raised to hide that."""
        self.add_template(type=1, no=5)
        self.add_template(type=9, no=0)
        body = self.push_templates(self.SN).json()
        self.assertEqual(config.COMMAND_BATCH_SIZE, 1)
        self.assertEqual(len(body["command_ids"]), 4)
        self.assertIn("40 seconds", body["message"])


class TemplateNeverGoesHomeTests(TemplatePushTestCase):
    """A template is never pushed back to the device that captured it."""

    def test_a_template_is_not_queued_to_its_own_source_device(self):
        self.add_template(type=9, no=0, source=self.SN)      # captured here
        self.add_template(type=1, no=5, source=self.OTHER_SN)  # captured elsewhere
        self.link(self.SN)

        self.push_templates(self.SN)
        queued = self.commands_on(self.SN)
        self.assertEqual(len(queued), 1)
        self.assertIn("\tType=1\t", queued[0])       # only the foreign one

    def test_the_skipped_template_is_named_rather_than_silently_dropped(self):
        self.add_template(type=9, no=0, source=self.SN)
        self.add_template(type=1, no=5, source=self.OTHER_SN)
        self.link(self.SN)

        body = self.push_templates(self.SN).json()
        self.assertEqual(body["skipped_from_this_device"], [{"type": 9, "no": 0}])
        self.assertEqual(body["templates_queued"], 1)

    def test_pushing_only_its_own_templates_back_is_refused_and_queues_nothing(self):
        self.add_template(type=9, no=0, source=self.SN)
        self.link(self.SN)

        response = self.push_templates(self.SN)
        self.assertEqual(response.status_code, 409)
        self.assertIn("never pushed back", response.json()["detail"])
        self.assertEqual(self.outbox(self.SN), [])

    def test_the_same_template_still_goes_to_every_other_device(self):
        """The exclusion is per target device, not a global veto: the whole
        point of the unit is that one enrolment reaches every other door."""
        self.add_template(type=9, no=0, source=self.SN)
        self.link(self.OTHER_SN)

        response = self.push_templates(self.OTHER_SN)
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(len(self.commands_on(self.OTHER_SN)), 1)
        self.assertEqual(self.outbox(self.SN), [])


class TemplateOrderingTests(TemplatePushTestCase):
    """The user record reaches the terminal before the credential does."""

    def test_the_user_record_is_queued_ahead_of_the_template(self):
        """A template for a Pin the terminal has never heard of has nothing to
        attach to, so the person and their door permission go first."""
        self.add_template()
        self.push_templates(self.SN)

        self.assertEqual([c.split("\t")[0] for c in self.commands_on(self.SN)], [
            "DATA UPDATE user Pin=9001",
            "DATA UPDATE userauthorize Pin=9001",
            "DATA UPDATE BIODATA Pin=9001",
        ])

    def test_the_device_is_handed_them_in_that_order(self):
        """The outbox is FIFO per device (ordered by created_at, id), so the
        ordering survives delivery: the user record is offered on an earlier
        poll than the template every time."""
        self.add_template()
        self.push_templates(self.SN)

        handed = [self.poll() for _ in range(3)]
        self.assertIn(":DATA UPDATE user Pin=9001\t", handed[0])
        self.assertIn(":DATA UPDATE userauthorize Pin=9001\t", handed[1])
        self.assertIn(":DATA UPDATE BIODATA Pin=9001\t", handed[2])

    def test_the_user_record_is_not_re_sent_when_the_device_confirmed_it(self):
        """`device_employees` is written only on a real acknowledgement, so
        its presence is evidence the terminal has the person. Re-queueing the
        record would cost two more polls for nothing."""
        self.add_template()
        self.link(self.SN)
        body = self.push_templates(self.SN).json()

        self.assertFalse(body["user_record_queued"])
        self.assertEqual([c.split("\t")[0] for c in self.commands_on(self.SN)],
                         ["DATA UPDATE BIODATA Pin=9001"])

    def test_a_queued_but_unconfirmed_user_record_does_not_count_as_confirmed(self):
        """Provisioned ten seconds ago and not yet acknowledged is not "on the
        device". The template goes behind a second user record rather than
        being sent on the strength of a hope."""
        self.add_template()
        self.push(self.SN, "9001")           # E3 provisioning, not yet acked
        self.push_templates(self.SN)

        self.assertEqual([c.split("\t")[0] for c in self.commands_on(self.SN)], [
            "DATA UPDATE user Pin=9001",
            "DATA UPDATE userauthorize Pin=9001",
            "DATA UPDATE user Pin=9001",
            "DATA UPDATE userauthorize Pin=9001",
            "DATA UPDATE BIODATA Pin=9001",
        ])

    def test_a_confirmed_push_leaves_the_person_on_the_device_afterwards(self):
        """End to end: queue, collect, acknowledge — and the terminal now
        holds both the person and their template."""
        self.add_template()
        self.push_templates(self.SN)
        for row in list(self.outbox(self.SN)):
            self.poll()
            self.ack(row.id, return_code=0)

        self.assertEqual([l.user_id for l in self.links(self.SN)], ["9001"])
        self.assertEqual(self.outbox(self.SN), [])
        self.assertEqual({r.outcome for r in self.history(self.SN)}, {"acknowledged"})


class TemplateRefusalTests(TemplatePushTestCase):
    """What the device refused must be visible, never silently absent."""

    def test_a_refused_template_is_recorded_with_its_return_code(self):
        self.add_template()
        self.link(self.SN)
        self.push_templates(self.SN)
        command_id = self.outbox(self.SN)[0].id
        self.poll()
        self.ack(command_id, return_code=-14)

        failed = [r for r in self.history(self.SN) if r.outcome == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].return_code, -14)
        self.assertTrue(failed[0].command.startswith("DATA UPDATE BIODATA Pin=9001"))
        self.assertEqual(self.outbox(self.SN), [])

    def test_a_refused_template_is_not_retried(self):
        """A refusal is permanent (E7): the device understood the command and
        declined it. Re-offering a multi-KB credential earns the same answer
        more slowly."""
        self.add_template()
        self.link(self.SN)
        self.push_templates(self.SN)
        command_id = self.outbox(self.SN)[0].id
        self.poll()
        self.ack(command_id, return_code=-14)

        self.assertEqual(self.poll(), "OK")

    def test_a_refused_template_is_visible_through_the_operator_api(self):
        """The UI reads this endpoint to show "refused" next to the person —
        the whole point of not swallowing the outcome."""
        self.add_template()
        self.link(self.SN)
        self.push_templates(self.SN)
        command_id = self.outbox(self.SN)[0].id
        self.poll()
        self.ack(command_id, return_code=-14)

        rows = self.client.get(f"/devices/{self.SN}/commands/history").json()
        refused = [r for r in rows if r["outcome"] == "failed"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["return_code"], -14)
        self.assertTrue(refused[0]["command"].startswith("DATA UPDATE BIODATA"))

    def test_a_refused_template_does_not_unmake_the_person(self):
        """The person is still on the terminal; only the credential failed.
        They can walk up and enrol a face there — which is the state the whole
        workflow started from, not a regression."""
        self.add_template()
        self.link(self.SN)
        self.push_templates(self.SN)
        command_id = self.outbox(self.SN)[0].id
        self.poll()
        self.ack(command_id, return_code=-14)

        self.assertEqual([l.user_id for l in self.links(self.SN)], ["9001"])


class OrphanedTemplateTests(TemplatePushTestCase):
    """The half-success this unit refuses to leave silent.

    FIFO guarantees the user record is *offered* first. It cannot guarantee it
    was *accepted*. If it is refused, or never acknowledged at all, the
    template queued behind it is owed to a terminal that does not have the
    person — so it is withdrawn and the reason recorded, rather than delivered
    and filed against nobody.
    """

    def test_a_refused_user_record_withdraws_the_template_behind_it(self):
        self.add_template()
        self.push_templates(self.SN)
        user_command_id = self.outbox(self.SN)[0].id

        self.poll()
        self.ack(user_command_id, return_code=-14)

        remaining = [c.split("\t")[0] for c in self.commands_on(self.SN)]
        self.assertNotIn("DATA UPDATE BIODATA Pin=9001", remaining)
        self.assertEqual(self.links(self.SN), [])

    def test_the_withdrawal_is_recorded_with_a_reason_not_just_deleted(self):
        self.add_template()
        self.push_templates(self.SN)
        self.poll()
        self.ack(self.outbox(self.SN)[0].id, return_code=-14)

        withdrawn = [r for r in self.history(self.SN)
                     if r.command.startswith("DATA UPDATE BIODATA")]
        self.assertEqual(len(withdrawn), 1)
        self.assertEqual(withdrawn[0].outcome, "failed")
        self.assertIsNone(withdrawn[0].return_code)   # nobody refused it; we withdrew it
        self.assertIn("no confirmed user record", withdrawn[0].last_error)

    def test_a_withdrawn_template_is_never_handed_to_the_device(self):
        self.add_template()
        self.push_templates(self.SN)
        self.poll()
        self.ack(self.outbox(self.SN)[0].id, return_code=-14)

        for _ in range(3):
            self.assertNotIn("BIODATA", self.poll())

    def test_a_user_record_that_is_never_acknowledged_withdraws_it_too(self):
        """The refusal case is caught on the acknowledgement. This one has no
        acknowledgement to catch — it fails on the sweep's timer instead, and
        the template must not outlive it."""
        from app.services import commands as commands_service
        from app.services import provisioning

        self.add_template()
        self.push_templates(self.SN)

        # Hand the user record over until it runs out of attempts, never
        # acknowledging it — a terminal that collects and stays silent.
        for _ in range(config.COMMAND_MAX_ATTEMPTS + 2):
            self.poll()
            for row in self.outbox(self.SN):
                self.rewind_backoff(row.id)

        db = self.Session()
        try:
            commands_service.sweep(db)
            withdrawn = provisioning.withdraw_orphaned_templates(db)
        finally:
            db.close()

        self.assertEqual(len(withdrawn), 1)
        self.assertNotIn("DATA UPDATE BIODATA Pin=9001",
                         [c.split("\t")[0] for c in self.commands_on(self.SN)])
        biodata = [r for r in self.history(self.SN)
                   if r.command.startswith("DATA UPDATE BIODATA")]
        self.assertEqual([r.outcome for r in biodata], ["failed"])
        self.assertIn("no confirmed user record", biodata[0].last_error)

    def test_a_template_waiting_behind_an_uncollected_user_record_is_left_alone(self):
        """Offline is not failure (E7). A device that has not polled yet owes
        both commands and neither has failed at anything."""
        from app.services import provisioning

        self.add_template()
        self.push_templates(self.SN)

        db = self.Session()
        try:
            self.assertEqual(provisioning.withdraw_orphaned_templates(db), [])
        finally:
            db.close()
        self.assertEqual(len(self.outbox(self.SN)), 3)

    def test_a_template_behind_a_confirmed_user_record_is_left_alone(self):
        from app.services import provisioning

        self.add_template()
        self.push_templates(self.SN)
        self.poll()
        self.ack(self.outbox(self.SN)[0].id, return_code=0)   # user record confirmed

        db = self.Session()
        try:
            self.assertEqual(provisioning.withdraw_orphaned_templates(db), [])
        finally:
            db.close()
        self.assertTrue(any(c.startswith("DATA UPDATE BIODATA")
                            for c in self.commands_on(self.SN)))

    def test_the_withdrawal_only_touches_the_device_that_failed(self):
        self.add_template(source=self.ATT_SN)
        self.push_templates(self.SN)
        self.push_templates(self.OTHER_SN)

        self.poll()
        self.ack(self.outbox(self.SN)[0].id, return_code=-14)

        self.assertTrue(any(c.startswith("DATA UPDATE BIODATA")
                            for c in self.commands_on(self.OTHER_SN)))

    def test_the_scheduled_sweep_runs_the_withdrawal(self):
        """It is wired into the existing 15-minute job, not a second
        scheduler, and not left as a function nothing calls.

        Read off disk rather than imported: importing app.main runs
        `Base.metadata.create_all` at module level, against whatever database
        .env names — which for this repo is the operator's live one. A test
        that only wants to read a function body has no business opening that
        connection."""
        import os.path

        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "app", "main.py",
        )
        with open(path) as handle:
            source = handle.read()
        body = source.split("def _command_sweep_tick")[1].split("\ndef ")[0]
        self.assertIn("commands.sweep(db)", body)
        self.assertIn("withdraw_orphaned_templates(db)", body)


class TemplatePushRefusalTests(TemplatePushTestCase):
    """Clear errors instead of a queue that quietly does nothing."""

    def test_a_person_with_no_templates_is_an_error_not_an_empty_success(self):
        response = self.push_templates(self.SN)
        self.assertEqual(response.status_code, 404)
        self.assertIn("No biometric templates captured", response.json()["detail"])
        self.assertEqual(self.outbox(self.SN), [])

    def test_a_person_with_no_templates_queues_no_user_record_either(self):
        """Not even the harmless half: an operator who asked to send a
        biometric and got a user record instead would reasonably read the
        person as enrolled."""
        self.push_templates(self.SN)
        self.assertEqual(self.outbox(self.SN), [])

    def test_an_unknown_employee_is_a_404(self):
        response = self.push_templates(self.SN, user_id="nobody")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.outbox(self.SN), [])

    def test_an_unknown_device_is_a_404(self):
        self.add_template()
        self.assertEqual(self.push_templates("NOSUCHSERIAL").status_code, 404)
        self.assertEqual(self.outbox(), [])

    def test_an_unsendable_template_is_refused_and_queues_nothing(self):
        """Every command is built before anything is queued, so a person whose
        stored data cannot go on the wire does not end up with a user record
        queued for a template that will never follow."""
        self.add_template(tmp="AAAA\tBBBB")
        response = self.push_templates(self.SN)
        self.assertEqual(response.status_code, 422)
        self.assertIn("cannot be put on the wire", response.json()["detail"])
        self.assertEqual(self.outbox(self.SN), [])


class TemplateTransportRoutingTests(TemplatePushTestCase):
    """acc goes to the outbox, att goes to the SDK, never both."""

    def add_fingerprint(self, user_id="9001", finger_id=1):
        from app.models import FingerprintTemplate
        db = self.Session()
        try:
            db.add(FingerprintTemplate(user_id=user_id, finger_id=finger_id,
                                       valid=1, template="0a0b0c",
                                       source_device_sn=self.OTHER_SN))
            db.commit()
        finally:
            db.close()

    def test_an_att_device_uses_the_sdk_and_never_touches_the_outbox(self):
        from unittest import mock

        self.add_template(source=self.OTHER_SN)   # an ADMS-captured template
        self.add_fingerprint()
        self.link(self.ATT_SN)

        class Conn(FakeConnection):
            def __init__(self):
                super().__init__(users=[type("U", (), {"user_id": "9001", "uid": 5})()])
                self.templates = None

            def save_user_template(self, user, fingers):
                self.templates = fingers

        conn = Conn()
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            response = self.push_templates(self.ATT_SN)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["templates_pushed"], 1)
        self.assertEqual(len(conn.templates), 1)
        self.assertEqual(self.outbox(self.ATT_SN), [])

    def test_an_att_device_never_queues_a_biodata_command(self):
        """The two tables are not each other's format: `biometric_templates`
        is ADMS base64, `fingerprint_templates` is a pyzk-packed blob. Neither
        is offered on the other's wire."""
        from unittest import mock

        self.add_template(source=self.OTHER_SN)
        self.link(self.ATT_SN)
        conn = FakeConnection(users=[type("U", (), {"user_id": "9001", "uid": 5})()])
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            response = self.push_templates(self.ATT_SN)

        # No fingerprint_templates row, so the SDK path has nothing to write —
        # and it says so rather than quietly reaching for the acc table.
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.outbox(self.ATT_SN), [])
        self.assertEqual(self.outbox(), [])

    def test_an_acc_device_never_opens_a_socket(self):
        from unittest import mock

        self.add_template()
        self.link(self.SN)
        conn = FakeConnection()
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            self.push_templates(self.SN)

        self.assertEqual(conn.written, [])
        self.assertEqual(len(self.outbox(self.SN)), 1)

    def test_a_device_with_no_protocol_set_takes_the_sdk_path(self):
        from unittest import mock

        self.add_template()
        self.link(self.DEFAULT_SN)
        conn = FakeConnection(users=[type("U", (), {"user_id": "9001", "uid": 5})()])
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            self.push_templates(self.DEFAULT_SN)

        self.assertEqual(self.outbox(self.DEFAULT_SN), [])

    def test_the_template_push_writes_no_device_link_inline(self):
        """Same discipline E3 established for employees and device links: the
        template path adds no new writer of either table."""
        import inspect as _inspect
        from app.routers import devices as devices_router
        from app.services import provisioning

        for module in (devices_router, provisioning):
            source = _inspect.getsource(module)
            self.assertNotIn("db.add(DeviceEmployee(", source, module.__name__)
            self.assertNotIn("db.add(Employee(", source, module.__name__)

    def test_queueing_a_template_writes_no_device_link(self):
        """Queued is not delivered — and a template is not what makes somebody
        present on a terminal in the first place."""
        self.add_template()
        self.push_templates(self.SN)
        self.assertEqual(self.links(), [])


class BiometricListingTests(TemplatePushTestCase):
    """What the operator reads before deciding to copy an enrolment."""

    def test_the_listing_describes_the_templates_without_handing_them_over(self):
        self.add_template(type=9, no=0, source=self.OTHER_SN)
        rows = self.client.get("/employees/9001/biometrics").json()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["type"], 9)
        self.assertEqual(rows[0]["source_device_sn"], self.OTHER_SN)
        self.assertEqual(rows[0]["tmp_bytes"], len(CAPTURED_FACE_TMP))
        self.assertNotIn("tmp", rows[0])
        self.assertNotIn(CAPTURED_FACE_TMP, str(rows))

    def test_a_person_with_nothing_enrolled_lists_nothing(self):
        self.assertEqual(self.client.get("/employees/9001/biometrics").json(), [])

    def test_an_unknown_person_is_a_404(self):
        self.assertEqual(self.client.get("/employees/nobody/biometrics").status_code, 404)


# ---------------------------------------------------------------------------
# 21. The SPA shell must not be cached over its own API path
# ---------------------------------------------------------------------------

class SpaShellCachingTests(unittest.TestCase):
    """/employees is a page AND an API route, told apart by request headers.

    Found while exercising E3 in a real browser: after a hard reload of
    /employees the page showed "0 employees" while the API was answering
    correctly. FileResponse had served the shell with an ETag and no Vary, so
    the browser reused that cached HTML for the page's own
    fetch('/employees') — which is not JSON, so the list came back empty. The
    same trap applies to /devices, /attendance and /users.
    """

    def setUp(self):
        import tempfile
        from app.middleware import SpaNavigationMiddleware

        self.tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w")
        self.tmp.write("<!doctype html><title>shell</title>")
        self.tmp.close()

        app = FastAPI()

        @app.get("/employees")
        def _employees():
            return [{"user_id": "1"}]

        app.add_middleware(SpaNavigationMiddleware, index_html=self.tmp.name)
        self.client = TestClient(app)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def navigate(self):
        return self.client.get("/employees", headers={
            "Sec-Fetch-Mode": "navigate",
            "Accept": "text/html,application/xhtml+xml",
        })

    def test_a_navigation_still_gets_the_shell(self):
        response = self.navigate()
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])

    def test_the_shell_is_not_stored_by_the_browser_cache(self):
        self.assertEqual(self.navigate().headers.get("cache-control"), "no-store")

    def test_the_shell_declares_what_it_varies_on(self):
        vary = self.navigate().headers.get("vary", "").lower()
        for header in ("x-requested-with", "sec-fetch-mode", "accept"):
            self.assertIn(header, vary)

    def test_the_api_answer_on_the_same_path_is_untouched(self):
        response = self.client.get("/employees",
                                   headers={"X-Requested-With": "XMLHttpRequest"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.headers["content-type"])
        self.assertEqual(response.json(), [{"user_id": "1"}])


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# 22. E5 — faces visible in the UI: serving a captured photo
# ---------------------------------------------------------------------------


class EmployeePhotoEndpointTests(ProvisioningTestCase):
    """GET /employees/{id}/photo — the endpoint the browser's <img> tag hits.

    Built on ProvisioningTestCase rather than AdmsTestCase deliberately: this
    exercises the real flow end to end on one app/database — a device
    uploads a photo through /iclock/cdata, an operator's authenticated
    browser fetches it back through the employees router.
    """

    def push_photo(self, tablename, pin, content=REALISTIC_PHOTO_B64, sn=None, **extra):
        fields = dict(pin=pin, filename="1.jpg", size=str(len(base64.b64decode(content))))
        if tablename == "biophoto":
            fields["type"] = "9"
        fields.update(extra)
        pairs = "\t".join(f"{k}={v}" for k, v in fields.items())
        body = f"{tablename} {pairs}\tcontent={content}\n"
        return self.client.post(
            f"/iclock/cdata?SN={sn or self.SN}&table=tabledata&tablename={tablename}&count=1",
            content=body,
        )

    def test_a_pushed_photo_is_served_decoded_and_byte_identical(self):
        self.create_employee("1")
        response = self.push_photo("biophoto", "1")
        self.assertEqual(response.status_code, 200)

        photo = self.client.get("/employees/1/photo")
        self.assertEqual(photo.status_code, 200)
        self.assertEqual(photo.headers["content-type"], "image/jpeg")
        self.assertEqual(photo.content, _REALISTIC_PHOTO_BYTES)

    def test_userpic_is_served_when_biophoto_is_absent(self):
        self.create_employee("2")
        self.push_photo("userpic", "2")

        photo = self.client.get("/employees/2/photo")
        self.assertEqual(photo.status_code, 200)
        self.assertEqual(photo.content, _REALISTIC_PHOTO_BYTES)

    def test_biophoto_is_preferred_over_userpic_when_both_exist(self):
        """Both are the same image on every real capture (E5), but if a
        firmware ever sends genuinely different bytes under the two names,
        `biophoto` — the table §3.7 documents as the comparison photo — wins
        rather than whichever upload happened to arrive last."""
        biophoto_bytes = b"\xff\xd8\xff" + b"\x01" * 500
        userpic_bytes = b"\xff\xd8\xff" + b"\x02" * 500
        self.create_employee("3")
        self.push_photo("biophoto", "3", content=base64.b64encode(biophoto_bytes).decode())
        self.push_photo("userpic", "3", content=base64.b64encode(userpic_bytes).decode())

        photo = self.client.get("/employees/3/photo")
        self.assertEqual(photo.content, biophoto_bytes)

    def test_an_employee_with_no_photo_is_404(self):
        self.create_employee("4")
        photo = self.client.get("/employees/4/photo")
        self.assertEqual(photo.status_code, 404)

    def test_an_unknown_employee_is_404(self):
        photo = self.client.get("/employees/nope/photo")
        self.assertEqual(photo.status_code, 404)

    def test_the_employee_list_response_does_not_carry_photo_bytes(self):
        """The whole reason this endpoint exists: inlining ~100KB of base64
        per person into GET /employees would turn a modest roster into a
        multi-megabyte response on every load."""
        self.create_employee("5", name="Aisha Rahman")
        self.push_photo("biophoto", "5")

        response = self.client.get("/employees")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 1)
        self.assertNotIn("content", body[0])
        self.assertNotIn("photo", body[0])
        # The list response as a whole must stay small — nowhere near the
        # ~140,000-character base64 payload a single photo carries.
        self.assertLess(len(response.content), 2000)


# ---------------------------------------------------------------------------
# 24. Revocation: taking a person off a door (E8)
# ---------------------------------------------------------------------------
#
# The half of provisioning where being slow is dangerous rather than merely
# incomplete. E3/E4 could put somebody on the operator's BioFace A1; before
# this unit nothing could take them off it, because both delete endpoints
# dialled TCP 4370 unconditionally and an `acc` terminal behind NAT answered
# 503.
#
# The assertions that matter here are not about status codes. They are:
#
#   * the exact bytes queued, because they are a command to physical door
#     hardware and §3.8 gives a literal example for exactly one of them;
#   * that the local "this person is on this door" record survives until the
#     terminal acknowledges, because removing it earlier would make a screen
#     claim a revocation nobody performed;
#   * that a revocation nobody collected stays visibly outstanding, because a
#     revocation that quietly looks finished is the worst outcome available.

class RevocationTestCase(TemplatePushTestCase):
    """Two acc terminals, one att terminal, one employee (9001)."""

    def revoke(self, sn, user_id="9001"):
        return self.client.delete(f"/devices/{sn}/users/{user_id}")

    def cancel(self, sn, user_id="9001"):
        return self.client.delete(f"/devices/{sn}/users/{user_id}/revocation")

    def commands_on(self, sn):
        return [row.command for row in self.outbox(sn)]


class SdkRevocation(FakeConnection):
    """FakeConnection plus a record of what was deleted over the SDK."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.deleted = []

    def delete_user(self, uid=None, user_id=None):
        self.deleted.append({"uid": uid, "user_id": user_id})


class RevocationCommandShapeTests(unittest.TestCase):
    """The literal bytes, against the protocol reference.

    §3.8 gives ONE verbatim delete example::

        C:296:DATA DELETE user Pin=1

    That is the whole documented authority for this unit's wire format, and it
    is reproduced here exactly rather than paraphrased. The `userauthorize`
    delete is DERIVED from the documented generic form `DATA DELETE <table> …`
    plus the confirmed table name and key field; the test says so, so a reader
    is never left thinking both shapes carry the same evidence.
    """

    def setUp(self):
        from app.services import provisioning
        self.provisioning = provisioning

    def test_the_user_delete_is_exactly_the_documented_shape(self):
        self.assertEqual(
            self.provisioning.user_delete_command("1"),
            "DATA DELETE user Pin=1",
        )

    def test_the_user_delete_matches_the_specs_own_worked_example(self):
        """§3.8, verbatim: `C:296:DATA DELETE user Pin=1`. The `C:<id>:`
        envelope is added at dispatch by commands.wire_line, so the body this
        module builds is the remainder of that line, character for character."""
        spec_line = "C:296:DATA DELETE user Pin=1"
        body = spec_line.split(":", 2)[2]
        self.assertEqual(self.provisioning.user_delete_command("1"), body)

    def test_the_user_delete_carries_no_tabs(self):
        """One field. A TAB here would invent a second field the device would
        try to read as a filter."""
        self.assertNotIn("\t", self.provisioning.user_delete_command("9001"))

    def test_the_authorize_delete_is_the_derived_shape(self):
        """DERIVED, not quoted — see authorize_delete_command's docstring."""
        self.assertEqual(
            self.provisioning.authorize_delete_command("9001"),
            "DATA DELETE userauthorize Pin=9001",
        )

    def test_the_user_record_is_deleted_first(self):
        """Order is the argument in revoke_commands_for: a terminal that
        collects exactly one command and then dies should have collected the
        one that definitely revokes."""
        self.assertEqual(
            self.provisioning.revoke_commands_for("9001"),
            ["DATA DELETE user Pin=9001",
             "DATA DELETE userauthorize Pin=9001"],
        )

    def test_no_biometric_delete_is_invented_anywhere(self):
        """The finding this unit was asked to establish rather than guess.

        §3.8 reproduces ZKTeco's own access-control SDK command constants and
        they contain no biometric delete at all — only `DATA DELETE user`. So
        nothing in this application may build one. If a later change adds a
        `DATA DELETE biodata`/`facev7`/`templatev10`/`biophoto`, this fails,
        and whoever added it has to justify the shape against real evidence
        first."""
        import inspect as _inspect
        from app.routers import devices as devices_router

        for module in (self.provisioning, devices_router):
            source = _inspect.getsource(module).upper()
            for table in ("BIODATA", "BIOPHOTO", "TEMPLATEV10", "FACEV7"):
                self.assertNotIn(
                    f"DATA DELETE {table}", source,
                    f"{module.__name__} builds a {table} delete, which no "
                    f"source confirms exists",
                )

    def test_a_pin_with_wire_breaking_characters_cannot_break_the_framing(self):
        self.assertEqual(
            self.provisioning.user_delete_command("90\t01"),
            "DATA DELETE user Pin=90 01",
        )

    def test_the_user_delete_parser_does_not_match_the_authorize_delete(self):
        """The parser that drops the `device_employees` link keys on the user
        delete only. An acknowledged permission delete is not evidence that
        the person is off the terminal — if it were treated as such, a
        cascade-less device would have its link dropped while the person was
        still enrolled."""
        self.assertEqual(
            self.provisioning.pin_from_revocation_command("DATA DELETE user Pin=9001"),
            "9001",
        )
        self.assertIsNone(
            self.provisioning.pin_from_revocation_command(
                "DATA DELETE userauthorize Pin=9001"
            )
        )
        self.assertIsNone(
            self.provisioning.pin_from_revocation_command("DATA UPDATE user Pin=9001")
        )


class RevocationTransportRoutingTests(RevocationTestCase):
    """acc queues, att dials. Never both — the E3 rule, applied to deletes."""

    def test_an_acc_revocation_queues_the_exact_command_and_never_opens_a_socket(self):
        from unittest import mock

        self.link(self.SN)
        conn = SdkRevocation()
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            response = self.revoke(self.SN)

        self.assertEqual(response.status_code, 202, response.text)
        body = response.json()
        self.assertEqual(body["transport"], "adms_queue")
        self.assertEqual(body["status"], "queued")

        # Byte-exact, in order, and nothing else.
        self.assertEqual(
            self.commands_on(self.SN),
            ["DATA DELETE user Pin=9001",
             "DATA DELETE userauthorize Pin=9001"],
        )
        # The SDK was never touched.
        self.assertEqual(conn.deleted, [])
        self.assertEqual(conn.written, [])

    def test_the_queued_bytes_are_what_the_device_is_actually_handed(self):
        """Not the outbox column — the reply body of a real getrequest, which
        is the only thing the terminal ever sees."""
        self.link(self.SN)
        self.revoke(self.SN)

        first = self.poll()
        self.assertEqual(first, "C:1:DATA DELETE user Pin=9001")
        self.assertEqual(first.encode(), b"C:1:DATA DELETE user Pin=9001")

        second = self.poll()
        self.assertEqual(second, "C:2:DATA DELETE userauthorize Pin=9001")

    def test_an_att_revocation_uses_the_sdk_and_leaves_the_outbox_empty(self):
        from unittest import mock

        self.link(self.ATT_SN)
        conn = SdkRevocation()
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            response = self.revoke(self.ATT_SN)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["transport"], "sdk")
        self.assertEqual(response.json()["status"], "removed")
        self.assertEqual(conn.deleted, [{"uid": 0, "user_id": "9001"}])
        # Nothing queued anywhere — not on this device and not on any other.
        self.assertEqual(self.outbox(), [])
        # The SDK path IS synchronous, so the link goes now.
        self.assertEqual(self.links(self.ATT_SN), [])

    def test_an_unclassified_device_takes_the_sdk_path(self):
        """Same safe default as every other write: anything not explicitly
        `acc` fails loudly on TCP rather than sitting in a queue looking
        healthy."""
        from unittest import mock

        self.link(self.DEFAULT_SN)
        conn = SdkRevocation()
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            response = self.revoke(self.DEFAULT_SN)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.outbox(self.DEFAULT_SN), [])
        self.assertEqual(len(conn.deleted), 1)

    def test_an_unreachable_att_device_still_reports_503_and_keeps_the_link(self):
        from unittest import mock
        from contextlib import contextmanager
        from zk.exception import ZKNetworkError

        self.link(self.ATT_SN)

        @contextmanager
        def _refuse(device):
            raise ZKNetworkError("unreachable")
            yield  # pragma: no cover

        with mock.patch("app.routers.devices.device_connection", _refuse):
            response = self.revoke(self.ATT_SN)

        self.assertEqual(response.status_code, 503)
        # Nothing was removed, so nothing may claim it was.
        self.assertEqual(len(self.links(self.ATT_SN)), 1)


class RevocationLinkOnAckTests(RevocationTestCase):
    """E3's rule in reverse: the link goes when the DEVICE says so."""

    def test_the_link_survives_queueing_and_delivery_and_goes_only_on_ack(self):
        self.link(self.SN)
        self.assertEqual(len(self.links(self.SN)), 1)

        self.revoke(self.SN)
        # Queued: the terminal has not been told anything yet.
        self.assertEqual(len(self.links(self.SN)), 1,
                         "the link was dropped at queue time — that claims a "
                         "revocation the device has not performed")

        self.poll()
        # Delivered, but not confirmed. Still not a fact.
        self.assertEqual(len(self.links(self.SN)), 1)

        self.ack(1, return_code=0, cmd="DATA DELETE")
        self.assertEqual(self.links(self.SN), [])

    def test_only_the_user_delete_drops_the_link(self):
        """Acknowledging the permission delete first must not be read as the
        person being gone."""
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()
        self.poll()

        self.ack(2, return_code=0, cmd="DATA DELETE")   # userauthorize
        self.assertEqual(len(self.links(self.SN)), 1)

        self.ack(1, return_code=0, cmd="DATA DELETE")   # user
        self.assertEqual(self.links(self.SN), [])

    def test_revoking_from_one_door_does_not_touch_another(self):
        self.link(self.SN)
        self.link(self.OTHER_SN)

        self.revoke(self.SN)
        self.poll(self.SN)
        self.ack(1, return_code=0, cmd="DATA DELETE", sn=self.SN)

        self.assertEqual(self.links(self.SN), [])
        self.assertEqual(len(self.links(self.OTHER_SN)), 1)
        self.assertEqual(self.outbox(self.OTHER_SN), [])

    def test_the_employee_row_itself_survives_a_revocation(self):
        """Removing somebody from a door is not deleting the person: their
        attendance history and their central record stay."""
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()
        self.ack(1, return_code=0, cmd="DATA DELETE")

        self.assertIsNotNone(self.employee("9001"))


class RefusedRevocationTests(RevocationTestCase):
    """A device saying no is not the same as a device saying yes."""

    def test_a_refused_delete_keeps_the_link_and_is_recorded_as_failed(self):
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()

        self.ack(1, return_code=-14, cmd="DATA DELETE")

        # The person is STILL on that terminal as far as anything can tell.
        self.assertEqual(len(self.links(self.SN)), 1,
                         "a refused delete dropped the link — that is a "
                         "revocation claimed and not performed")

        concluded = [r for r in self.history(self.SN)
                     if r.command == "DATA DELETE user Pin=9001"]
        self.assertEqual(len(concluded), 1)
        self.assertEqual(concluded[0].outcome, "failed")
        self.assertEqual(concluded[0].return_code, -14)

    def test_a_refused_delete_is_not_retried(self):
        """E7's rule: a refusal is permanent. Re-offering it earns the same
        answer while occupying a queue that has a revocation in it."""
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()
        self.ack(1, return_code=-14, cmd="DATA DELETE")

        self.assertNotIn("DATA DELETE user Pin=9001", self.poll())

    def test_a_refused_delete_reaches_the_operators_view(self):
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()
        self.ack(1, return_code=-14, cmd="DATA DELETE")

        history = self.client.get(f"/devices/{self.SN}/commands/history").json()
        failed = [r for r in history
                  if r["command"] == "DATA DELETE user Pin=9001"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["outcome"], "failed")
        self.assertEqual(failed[0]["return_code"], -14)

    def test_a_refused_delete_is_logged_at_error_naming_the_door(self):
        """The 2am log line. `failed` alone is not loud enough for a command
        whose failure means somebody can still open a door."""
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()

        with self.assertLogs("app.services.commands", level="ERROR") as logs:
            self.ack(1, return_code=-14, cmd="DATA DELETE")

        joined = "\n".join(logs.output)
        self.assertIn("ACCESS NOT REVOKED", joined)
        self.assertIn(self.SN, joined)

    def test_an_empty_outbox_is_not_evidence_that_a_removal_happened(self):
        """The invariant a UI bug found during this unit's browser check.

        A refused delete leaves the outbox exactly as empty as a successful
        one does — `conclude` moves the row out either way. So "no delete is
        queued for this door" says nothing at all about whether the person is
        off it, and anything that infers success from that absence is wrong.
        The `device_employees` link is the evidence, and it is still here.

        Pinned as data rather than as UI, because the panel reasons off these
        two endpoints and this is the shape it must keep seeing."""
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()
        self.ack(1, return_code=-14, cmd="DATA DELETE")

        outstanding = [r.command for r in self.outbox(self.SN)]
        self.assertNotIn("DATA DELETE user Pin=9001", outstanding,
                         "a refusal must not leave the command outstanding")

        enrolled = self.client.get("/employees/9001/devices").json()
        self.assertEqual([d["device_sn"] for d in enrolled], [self.SN],
                         "the link is the only evidence of presence and it "
                         "must survive a refused delete")

    def test_an_ack_with_no_return_code_leaves_the_revocation_outstanding(self):
        """Absence of a Return is the device saying nothing, and must not be
        read as success — that would drop the link on no evidence at all."""
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()

        self.client.post(f"/iclock/devicecmd?SN={self.SN}",
                         content=f"ID=1&CMD=DATA DELETE&SN={self.SN}")

        self.assertEqual(len(self.links(self.SN)), 1)
        self.assertEqual(len(self.outbox(self.SN)), 2)


class OfflineRevocationStaysVisibleTests(RevocationTestCase):
    """The point of the whole unit: waiting is not the same as done."""

    def test_a_device_that_never_polls_leaves_the_revocation_outstanding(self):
        self.link(self.SN)
        response = self.revoke(self.SN)

        # 202, not 204 and not 200. The word in the body is "queued".
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["status"], "queued")

        # Nothing has been attempted, because the device has not come back.
        rows = self.outbox(self.SN)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r.status == "pending" for r in rows))
        self.assertTrue(all(r.attempts == 0 for r in rows))

        # And the person is still recorded as being on that door, which is
        # the truth.
        self.assertEqual(len(self.links(self.SN)), 1)

    def test_the_response_says_not_yet_confirmed_at_the_door(self):
        """The operator reads this string. It is not allowed to imply the
        removal happened."""
        self.link(self.SN)
        message = self.revoke(self.SN).json()["message"]

        self.assertIn("NOT yet confirmed at the door", message)
        self.assertIn("can still", message)
        self.assertNotIn("Removed from", message)

    def test_an_uncollected_revocation_is_visible_on_the_device_shape(self):
        """Surfaced on the DEVICE as well as the person, so an operator
        scanning the device list sees it without opening every employee."""
        self.link(self.SN)
        self.revoke(self.SN)

        listing = self.client.get("/devices").json()
        by_sn = {d["serial_number"]: d for d in listing}
        # One person, not two commands: this counts people, not queue rows.
        self.assertEqual(by_sn[self.SN]["pending_revocations"], 1)
        self.assertEqual(by_sn[self.OTHER_SN]["pending_revocations"], 0)

        single = self.client.get(f"/devices/{self.SN}").json()
        self.assertEqual(single["pending_revocations"], 1)

    def test_the_count_clears_only_when_the_device_confirms(self):
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()

        still = self.client.get(f"/devices/{self.SN}").json()
        self.assertEqual(still["pending_revocations"], 1,
                         "delivered is not confirmed")

        self.ack(1, return_code=0, cmd="DATA DELETE")
        done = self.client.get(f"/devices/{self.SN}").json()
        self.assertEqual(done["pending_revocations"], 0)

    def test_a_sweep_does_not_age_out_a_revocation_for_an_offline_device(self):
        """Offline is not failure, even here. What changes for a revocation is
        how loudly it is shown and how fast it is retried once the device IS
        polling — not that it is given up on while unreachable."""
        from app.services import commands as commands_service

        self.link(self.SN)
        self.revoke(self.SN)

        db = self.Session()
        try:
            for _ in range(30):
                commands_service.sweep(
                    db, now=datetime.now(timezone.utc) + timedelta(days=1)
                )
        finally:
            db.close()

        rows = self.outbox(self.SN)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r.attempts == 0 for r in rows))


class RevocationBackoffTests(unittest.TestCase):
    """A revocation is retried faster than anything else, and why.

    Every other command in this system can afford to wait out a 15-minute
    backoff. A delete cannot: the wait is time during which somebody who
    should have lost access still has it. Safe to be aggressive because a
    delete is idempotent in exactly the way E7 relies on for DATA UPDATE.
    """

    def test_a_revocation_uses_the_short_schedule(self):
        from app.services import commands as commands_service

        ordinary = commands_service.backoff_for(1, "DATA UPDATE user Pin=1")
        revocation = commands_service.backoff_for(1, "DATA DELETE user Pin=1")

        self.assertEqual(ordinary.total_seconds(), config.COMMAND_BACKOFF_SECONDS[0])
        self.assertEqual(revocation.total_seconds(),
                         config.REVOCATION_BACKOFF_SECONDS[0])
        self.assertLess(revocation, ordinary)

    def test_every_attempt_of_a_revocation_is_faster_than_the_ordinary_one(self):
        from app.services import commands as commands_service

        for attempts in range(1, 8):
            self.assertLess(
                commands_service.backoff_for(attempts, "DATA DELETE user Pin=1"),
                commands_service.backoff_for(attempts, "DATA UPDATE user Pin=1"),
                f"attempt {attempts}",
            )

    def test_an_unknown_or_missing_command_gets_the_ordinary_schedule(self):
        from app.services import commands as commands_service

        self.assertEqual(
            commands_service.backoff_for(1, None),
            commands_service.backoff_for(1),
        )
        self.assertEqual(
            commands_service.backoff_for(1, "SET OPTIONS IPAddress=10.0.0.1"),
            commands_service.backoff_for(1),
        )

    def test_the_short_schedule_is_bounded(self):
        from app.services import commands as commands_service

        last = commands_service.backoff_for(
            len(config.REVOCATION_BACKOFF_SECONDS) + 50, "DATA DELETE user Pin=1")
        self.assertEqual(last.total_seconds(), config.REVOCATION_BACKOFF_SECONDS[-1])


class RevocationDispatchBackoffTests(RevocationTestCase):
    """The short schedule as the dispatcher actually applies it."""

    def test_the_outbox_row_carries_the_short_window(self):
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()

        row = [r for r in self.outbox(self.SN) if r.status == "sent"][0]
        window = (row.next_attempt_at - row.sent_at).total_seconds()
        self.assertAlmostEqual(window, config.REVOCATION_BACKOFF_SECONDS[0], delta=2)
        self.assertLess(window, config.COMMAND_BACKOFF_SECONDS[0])

    def test_a_delivered_but_unacked_revocation_is_offered_again(self):
        self.link(self.SN)
        self.revoke(self.SN)
        self.assertIn("DATA DELETE user Pin=9001", self.poll())

        # Inside the window: not re-offered (the backoff is doing its job).
        self.assertNotIn("DATA DELETE user Pin=9001", self.poll())

        self.rewind_backoff(1)
        self.assertIn("DATA DELETE user Pin=9001", self.poll())


class RevocationWithdrawsPushesTests(RevocationTestCase):
    """A queued delete and a queued push for the same pair contradict."""

    def test_queueing_a_delete_withdraws_the_outstanding_pushes(self):
        self.push(self.SN, "9001")
        self.assertEqual(len(self.outbox(self.SN)), 2)   # user + userauthorize

        response = self.revoke(self.SN)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "withdrawn")
        self.assertEqual(len(response.json()["withdrawn_command_ids"]), 2)

        # Nothing contradicting is left in the outbox.
        self.assertEqual(self.outbox(self.SN), [])
        # The withdrawal is recorded, not silently dropped.
        concluded = self.history(self.SN)
        self.assertEqual(len(concluded), 2)
        self.assertTrue(all(r.outcome == "failed" for r in concluded))
        self.assertTrue(all("withdrawn" in (r.last_error or "") for r in concluded))

    def test_a_confirmed_person_with_a_queued_template_has_both_handled(self):
        """The link is real, so this is a genuine revocation — and the
        template still queued behind it is withdrawn to make room."""
        self.link(self.SN)
        self.add_template(source=self.OTHER_SN)
        self.push_templates(self.SN)
        self.assertEqual(len(self.outbox(self.SN)), 1)   # the BIODATA

        response = self.revoke(self.SN)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(len(response.json()["withdrawn_command_ids"]), 1)
        self.assertEqual(
            self.commands_on(self.SN),
            ["DATA DELETE user Pin=9001",
             "DATA DELETE userauthorize Pin=9001"],
        )

    def test_withdrawal_is_confined_to_this_person_on_this_door(self):
        self.create_employee("9002", name="Omar Said")
        self.push(self.SN, "9002")        # another person, same door
        self.push(self.OTHER_SN, "9001")  # same person, another door
        self.link(self.SN)

        self.revoke(self.SN, "9001")

        # The other person's push on this door is untouched.
        self.assertEqual(
            [c for c in self.commands_on(self.SN) if "9002" in c],
            ["DATA UPDATE user Pin=9002\tCardNo=0\tPassword=\tGroup=0\t"
             "StartTime=0\tEndTime=0\tName=Omar Said\tPrivilege=0",
             "DATA UPDATE userauthorize Pin=9002\tAuthorizeTimezoneId=1"],
        )
        # And the same person's push to the OTHER door is untouched.
        self.assertEqual(len(self.outbox(self.OTHER_SN)), 2)
        self.assertTrue(all(c.startswith("DATA UPDATE")
                            for c in self.commands_on(self.OTHER_SN)))

    def test_a_pin_prefix_is_not_mistaken_for_the_pin(self):
        """9001 must not withdraw 19001's commands, or vice versa."""
        self.create_employee("19001", name="Someone Else")
        self.push(self.SN, "19001")
        self.link(self.SN)

        self.revoke(self.SN, "9001")

        self.assertEqual(
            len([c for c in self.commands_on(self.SN) if "Pin=19001" in c]), 2)

    def test_revoking_someone_never_confirmed_withdraws_and_says_so(self):
        """Not a 404. Calling off an undelivered push is exactly what "remove"
        means at that moment, and 404ing would leave it in the outbox to be
        delivered later — the opposite of what was asked."""
        self.push(self.SN, "9001")
        response = self.revoke(self.SN)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "withdrawn")
        self.assertIn("never confirmed", body["message"])
        self.assertIn("Nothing was sent to the device", body["message"])
        # No delete is queued: there is nothing on the device to delete.
        self.assertEqual(self.outbox(self.SN), [])

    def test_revoking_somebody_who_is_neither_on_nor_owed_is_404(self):
        response = self.revoke(self.SN)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.outbox(self.SN), [])


class PushDuringRevocationTests(RevocationTestCase):
    """The other order of business — settled explicitly, not by FIFO."""

    def test_a_push_is_refused_while_a_revocation_is_outstanding(self):
        self.link(self.SN)
        self.revoke(self.SN)

        response = self.push(self.SN, "9001")
        self.assertEqual(response.status_code, 409, response.text)
        detail = response.json()["detail"]
        self.assertIn("not been confirmed by the device yet", detail)
        self.assertIn("nothing was queued", detail)

        # And nothing was: the outbox still holds exactly the revocation.
        self.assertEqual(
            self.commands_on(self.SN),
            ["DATA DELETE user Pin=9001",
             "DATA DELETE userauthorize Pin=9001"],
        )

    def test_a_template_push_is_refused_too(self):
        self.link(self.SN)
        self.add_template(source=self.OTHER_SN)
        self.revoke(self.SN)

        response = self.push_templates(self.SN)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(len(self.outbox(self.SN)), 2)

    def test_a_bulk_push_names_the_blocked_person_instead_of_skipping_silently(self):
        self.create_employee("9002", name="Omar Said")
        self.link(self.SN)
        self.revoke(self.SN)

        response = self.client.post(f"/devices/{self.SN}/users/push_bulk",
                                    json={"user_ids": ["9001", "9002"]})
        self.assertEqual(response.status_code, 202, response.text)
        body = response.json()
        self.assertEqual(body["pushed"], ["9002"])
        self.assertEqual(len(body["errors"]), 1)
        self.assertIn("9001", body["errors"][0])
        self.assertIn("revocation", body["errors"][0])

    def test_a_push_to_a_different_door_is_not_blocked(self):
        self.link(self.SN)
        self.revoke(self.SN)

        response = self.push(self.OTHER_SN, "9001")
        self.assertEqual(response.status_code, 202, response.text)

    def test_a_push_is_allowed_again_once_the_revocation_concludes(self):
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()
        self.ack(1, return_code=0, cmd="DATA DELETE")
        self.poll()
        self.ack(2, return_code=0, cmd="DATA DELETE")

        response = self.push(self.SN, "9001")
        self.assertEqual(response.status_code, 202, response.text)


class CancelRevocationTests(RevocationTestCase):
    """The escape hatch that stops the 409 from stranding an operator."""

    def test_cancelling_clears_the_outbox_and_leaves_a_record(self):
        self.link(self.SN)
        self.revoke(self.SN)

        response = self.cancel(self.SN)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(response.json()["cancelled_command_ids"]), 2)
        self.assertEqual(self.outbox(self.SN), [])

        concluded = self.history(self.SN)
        self.assertEqual(len(concluded), 2)
        self.assertTrue(all("cancelled by tester" in (r.last_error or "")
                            for r in concluded))

    def test_cancelling_leaves_the_person_on_the_device(self):
        """Nothing ever reached the terminal, so nothing about it changed."""
        self.link(self.SN)
        self.revoke(self.SN)
        self.cancel(self.SN)

        self.assertEqual(len(self.links(self.SN)), 1)

    def test_a_push_works_immediately_after_a_cancel(self):
        self.link(self.SN)
        self.revoke(self.SN)
        self.cancel(self.SN)

        self.assertEqual(self.push(self.SN, "9001").status_code, 202)

    def test_cancelling_nothing_is_a_404(self):
        self.link(self.SN)
        self.assertEqual(self.cancel(self.SN).status_code, 404)

    def test_a_cancel_cannot_recall_a_command_the_device_already_took(self):
        """Once a terminal has acknowledged the delete the person is off it,
        and no amount of cancelling here puts them back — the way to do that
        is to push them again."""
        self.link(self.SN)
        self.revoke(self.SN)
        self.poll()
        self.ack(1, return_code=0, cmd="DATA DELETE")

        response = self.cancel(self.SN)
        # The userauthorize delete is still outstanding, so this succeeds —
        # but the user delete is already history and the link is already gone.
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.links(self.SN), [])

    def test_cancelling_is_confined_to_one_door_and_one_person(self):
        self.create_employee("9002", name="Omar Said")
        self.link(self.SN)
        self.link(self.OTHER_SN)
        self.link(self.SN, "9002")
        self.revoke(self.SN, "9001")
        self.revoke(self.OTHER_SN, "9001")
        self.revoke(self.SN, "9002")

        self.cancel(self.SN, "9001")

        self.assertEqual(len(self.outbox(self.OTHER_SN)), 2)
        self.assertEqual(
            [c for c in self.commands_on(self.SN) if "Pin=9002" in c],
            ["DATA DELETE user Pin=9002",
             "DATA DELETE userauthorize Pin=9002"],
        )


class TemplateDeleteOnAccTests(RevocationTestCase):
    """No invented biodata delete — a refusal that says what to do instead."""

    def test_deleting_one_template_on_an_acc_terminal_is_refused_not_guessed(self):
        self.link(self.SN)
        response = self.client.delete(
            f"/devices/{self.SN}/users/9001/templates/1")

        self.assertEqual(response.status_code, 501, response.text)
        detail = response.json()["detail"]
        self.assertIn("no confirmed command", detail)
        self.assertIn("UNVERIFIED", detail)
        self.assertIn("remove the person", detail.lower())
        # The load-bearing assertion: nothing was queued to a door.
        self.assertEqual(self.outbox(self.SN), [])

    def test_the_att_path_still_deletes_a_template_over_the_sdk(self):
        from unittest import mock
        from app.models import FingerprintTemplate

        self.link(self.ATT_SN)
        db = self.Session()
        try:
            db.add(FingerprintTemplate(user_id="9001", finger_id=1, valid=1,
                                       template="0a0b", source_device_sn=self.ATT_SN))
            db.commit()
        finally:
            db.close()

        class Conn(FakeConnection):
            def __init__(self):
                super().__init__()
                self.removed = []

            def delete_user_template(self, uid=None, temp_id=None, user_id=None):
                self.removed.append((uid, temp_id, user_id))

        conn = Conn()
        with mock.patch("app.routers.devices.device_connection", fake_sdk(conn)):
            response = self.client.delete(
                f"/devices/{self.ATT_SN}/users/9001/templates/1")

        self.assertEqual(response.status_code, 204, response.text)
        self.assertEqual(conn.removed, [(0, 1, "9001")])
        self.assertEqual(self.outbox(), [])


class RevocationSingleWriterTests(RevocationTestCase):
    """`device_employees` has one creator and now one destroyer."""

    def test_nothing_outside_employee_sync_deletes_a_device_link(self):
        import inspect as _inspect
        from app.routers import devices as devices_router
        from app.services import provisioning

        for module in (devices_router, provisioning):
            source = _inspect.getsource(module)
            self.assertNotIn("db.delete(de)", source, module.__name__)
            self.assertNotIn("db.delete(link)", source, module.__name__)
            self.assertNotIn("DeviceEmployee).delete(", source, module.__name__)

    def test_the_revocation_path_adds_no_second_writer_of_the_link(self):
        import inspect as _inspect
        from app.services import provisioning

        source = _inspect.getsource(provisioning)
        self.assertNotIn("db.add(DeviceEmployee(", source)
        self.assertIn("employee_sync.unlink_device_employee", source)


# ---------------------------------------------------------------------------
# 20. `/iclock/querydata` — the answer to a DATA QUERY (E9)
#
# Written against a real captured request, not a document. On 2026-08-21
# 07:22 UTC the operator's BioFace A1 was handed the first command this
# codebase has ever delivered to hardware:
#
#     C:1:DATA QUERY tablename=user,fielddesc=*,filter=*
#
# It understood the query, produced all three of its user records, and POSTed
# them to /iclock/querydata — an endpoint push-protocol.md §3.12 had listed as
# folklore because it appears in neither vendor document. There was no route,
# so it 404d, so the device retried every ~5 seconds, indefinitely.
# ---------------------------------------------------------------------------

# The captured request line, verbatim, tabs and all. Only the serial is
# substituted in the tests that queue a command, so that no command is ever
# queued in a test against a serial belonging to a live terminal.
CAPTURED_QUERYDATA_PATH = (
    "/iclock/querydata?SN={sn}&type=tabledata&cmdid={cmdid}&tablename=user"
    "&count=3&packcnt=1&packidx=1"
)

QUERY_COMMAND = "DATA QUERY tablename=user,fielddesc=*,filter=*"


class QueryDataTestCase(CommandDeliveryTestCase):
    """Both routers, an outbox, and a device that answers queries.

    Built on CommandDeliveryTestCase because the half of this that matters
    most is not the parse — it is that answering the query concludes the
    command. Testing the ingest without the outbox would test the easy half.
    """

    QSN = "E9QUERY000001"
    CIDR_SN = "E9QUERY000002"

    def setUp(self):
        super().setUp()
        db = self.Session()
        try:
            db.add(Device(serial_number=self.QSN, ip_address="203.0.113.10",
                          port=4370, name="Face terminal", status="approved",
                          protocol="acc"))
            db.add(Device(serial_number=self.CIDR_SN, ip_address="198.51.100.7",
                          port=4370, name="Elsewhere", status="approved",
                          protocol="acc", ip_check_enabled=True,
                          allowed_cidrs="198.51.100.0/24"))
            db.commit()
        finally:
            db.close()
        # The reassembly buffer is module state, so a transfer left part-received
        # by one test would otherwise be visible to the next.
        adms._transfers.clear()

    def tearDown(self):
        adms._transfers.clear()
        super().tearDown()

    # -- helpers ---------------------------------------------------------

    def query_post(self, body="", sn=None, tablename="user", cmdid="",
                   count=None, packcnt=1, packidx=1, qtype="tabledata"):
        """One /iclock/querydata packet, as the device sends it."""
        if count is None:
            count = len([ln for ln in body.splitlines() if ln.strip()])
        url = (
            f"/iclock/querydata?SN={sn or self.QSN}&type={qtype}"
            f"&cmdid={cmdid}&tablename={tablename}&count={count}"
            f"&packcnt={packcnt}&packidx={packidx}"
        )
        return self.client.post(url, content=body)

    def queue_query(self, sn=None, command=QUERY_COMMAND):
        """Queue a DATA QUERY and hand it to the device, as really happened."""
        command_id = self.queue(command=command, sn=sn or self.QSN)
        self.poll(sn=sn or self.QSN)
        return command_id

    def employees(self):
        db = self.Session()
        try:
            return {e.user_id: e for e in db.query(Employee).all()}
        finally:
            db.close()

    def photos(self):
        from app.models import EmployeePhoto
        db = self.Session()
        try:
            return {(p.user_id, p.source): p for p in db.query(EmployeePhoto).all()}
        finally:
            db.close()

    def templates(self):
        db = self.Session()
        try:
            return {(t.user_id, t.type, t.no): t
                    for t in db.query(BiometricTemplate).all()}
        finally:
            db.close()


class QueryDataCapturedRequestTests(QueryDataTestCase):
    """The request that is looping right now, and what must happen to it."""

    def test_the_captured_request_is_accepted_and_stores_all_three_users(self):
        """The whole unit, in one test. The real path, the real query string,
        the real body — and three employees at the end of it."""
        command_id = self.queue_query()
        response = self.client.post(
            CAPTURED_QUERYDATA_PATH.format(sn=self.QSN, cmdid=command_id),
            content=CAPTURED_USER_UPLOAD,
        )

        self.assertEqual(response.status_code, 200)
        employees = self.employees()
        self.assertEqual(sorted(employees), ["1", "2", "3"])
        self.assertEqual(
            [employees[p].privilege for p in ("1", "2", "3")], [14, 14, 0]
        )

    def test_the_real_serials_own_request_no_longer_404s(self):
        """Byte-for-byte the captured request, real serial included — the one
        thing that must change is that it stops being a 404. No command is
        queued here on purpose: a real serial must never be given work in a
        test, and the ingest must not depend on the command existing anyway."""
        db = self.Session()
        try:
            db.add(Device(serial_number=ACC_SN, ip_address="203.0.113.10",
                          port=4370, name="BioFace A1", status="approved",
                          protocol="acc"))
            db.commit()
        finally:
            db.close()

        response = self.client.post(
            CAPTURED_QUERYDATA_PATH.format(sn=ACC_SN, cmdid=1),
            content=CAPTURED_USER_UPLOAD,
            headers={"User-Agent": "iClock Proxy/1.09"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])

    def test_the_catch_all_no_longer_claims_this_path(self):
        """It is the catch-all's 404 that produced the retry loop. A concrete
        route is declared, so the catch-all must not see this path at all."""
        self.queue_query()
        response = self.query_post(CAPTURED_USER_UPLOAD, cmdid=1)
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.text, "Not Found")

    def test_the_reply_follows_the_tabledata_convention(self):
        """UNCONFIRMED against hardware. The device declares `type=tabledata`
        and sends a tabledata body, so it is acknowledged like one. Pinned as
        a test so that changing it is a deliberate act with evidence behind
        it, not a drive-by edit."""
        self.queue_query()
        response = self.query_post(CAPTURED_USER_UPLOAD, cmdid=1, count=3)
        self.assertEqual(response.content, b"user=3")
        self.assertTrue(response.headers["content-type"].startswith("text/plain"))

    def test_the_acknowledgement_can_be_flipped_to_ok_without_a_code_change(self):
        """The other candidate. If the terminal is still looping after deploy,
        the operator flips one setting rather than waiting for a new unit."""
        self.queue_query()
        original = config.QUERYDATA_ACK_STYLE
        config.QUERYDATA_ACK_STYLE = "ok"
        try:
            response = self.query_post(CAPTURED_USER_UPLOAD, cmdid=1, count=3)
        finally:
            config.QUERYDATA_ACK_STYLE = original

        self.assertEqual(response.text, "OK")
        # ...and the ingest is unaffected either way.
        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])

    def test_the_request_is_named_in_the_log_whatever_it_carries(self):
        """This endpoint is one capture old. The next surprise has to be
        readable from the log without a debugger attached."""
        with self.assertLogs("app.routers.adms", level="INFO") as captured:
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=1, count=3)
        joined = "\n".join(captured.output)
        self.assertIn("querydata", joined)
        self.assertIn("tablename='user'", joined)
        self.assertIn("packet=1/1", joined)

    def test_a_get_is_answered_rather_than_left_to_the_catch_all(self):
        """Unobserved, and registered anyway: a firmware that used GET would
        otherwise fall to the 404 that started this."""
        response = self.client.get(
            f"/iclock/querydata?SN={self.QSN}&type=tabledata&tablename=user&count=0"
        )
        self.assertEqual(response.status_code, 200)


class QueryDataConcludesTheCommandTests(QueryDataTestCase):
    """`cmdid` is the acknowledgement. There is no devicecmd for a query."""

    def test_a_single_packet_transfer_concludes_the_command(self):
        command_id = self.queue_query()
        self.assertEqual(len(self.outbox(self.QSN)), 1)

        self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3)

        self.assertEqual(self.outbox(self.QSN), [])
        concluded = self.history(self.QSN)
        self.assertEqual(len(concluded), 1)
        self.assertEqual(concluded[0].outcome, "acknowledged")
        self.assertEqual(concluded[0].command, QUERY_COMMAND)
        self.assert_exactly_one_home(QUERY_COMMAND, sn=self.QSN)

    def test_without_this_the_answered_command_would_retry(self):
        """The point of concluding at all: an outstanding command comes back
        round on the next poll after its backoff, and is eventually declared
        failed — despite having been answered and its answer stored."""
        command_id = self.queue_query()
        self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3)

        # Nothing is left to offer again — there is not even a row to rewind.
        self.assertEqual(self.outbox(self.QSN), [])
        self.assertEqual(self.poll(sn=self.QSN), "OK")

        # The counterfactual, so this is a test of concluding rather than of
        # an empty queue: an identical command that is NOT answered does come
        # back round once its backoff has elapsed.
        unanswered = self.queue(command=QUERY_COMMAND, sn=self.QSN)
        self.poll(sn=self.QSN)
        self.rewind_backoff(unanswered)
        self.assertIn(f"C:{unanswered}:", self.poll(sn=self.QSN))

    def test_it_concludes_the_command_the_device_named_not_the_oldest(self):
        """The bug E7 fixed for devicecmd, which must not reappear here."""
        first = self.queue(command="DATA UPDATE user Pin=9\tName=Zoe", sn=self.QSN)
        second = self.queue(command=QUERY_COMMAND, sn=self.QSN)
        self.poll(sn=self.QSN)
        self.poll(sn=self.QSN)

        self.query_post(CAPTURED_USER_UPLOAD, cmdid=second, count=3)

        outstanding = [r.id for r in self.outbox(self.QSN)]
        self.assertEqual(outstanding, [first])
        self.assertEqual([r.command for r in self.history(self.QSN)], [QUERY_COMMAND])

    def test_a_query_answered_for_one_device_does_not_conclude_anothers(self):
        mine = self.queue_query()
        theirs = self.queue(command=QUERY_COMMAND, sn=self.SN)
        self.poll(sn=self.SN)

        self.query_post(CAPTURED_USER_UPLOAD, cmdid=theirs, sn=self.QSN, count=3)

        self.assertEqual([r.id for r in self.outbox(self.SN)], [theirs])
        self.assertEqual([r.id for r in self.outbox(self.QSN)], [mine])

    def test_an_unmatched_cmdid_still_stores_the_payload_and_says_so(self):
        """The data is real whether or not we can find the command it answers.
        Storing it is right; doing so silently is not."""
        with self.assertLogs("app.services.commands", level="WARNING") as captured:
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=4242, count=3)
        self.assertIn("not outstanding", "\n".join(captured.output))
        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])

    def test_the_log_names_querydata_not_devicecmd(self):
        """Two endpoints conclude commands now. A line that misnames which one
        sends the next reader to the wrong place."""
        with self.assertLogs("app.services.commands", level="WARNING") as captured:
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=4242, count=3)
        joined = "\n".join(captured.output)
        self.assertIn("querydata from", joined)
        self.assertNotIn("devicecmd from", joined)

    def test_a_missing_cmdid_stores_the_payload_and_warns(self):
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            self.query_post(CAPTURED_USER_UPLOAD, cmdid="", count=3)
        self.assertIn("no usable cmdid", "\n".join(captured.output))
        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])


class QueryDataReassemblyTests(QueryDataTestCase):
    """`packcnt`/`packidx`. A fragment parsed as a whole record is the failure
    this class exists to make impossible."""

    def photo_body(self, pin="1", content=REALISTIC_PHOTO_B64):
        return (
            f"biophoto pin={pin}\tfilename={pin}.jpg\ttype=9"
            f"\tsize={len(content)}\tcontent={content}\n"
        )

    def test_nothing_is_stored_until_the_final_packet(self):
        command_id = self.queue_query(command="DATA QUERY tablename=biophoto")
        body = self.photo_body()
        half = len(body) // 2

        self.query_post(body[:half], tablename="biophoto", cmdid=command_id,
                        count=1, packcnt=2, packidx=1)

        self.assertEqual(self.photos(), {})
        self.assertEqual([r.id for r in self.outbox(self.QSN)], [command_id])

    def test_a_photo_split_mid_base64_survives_whole(self):
        """The exact corruption this reassembly exists to prevent. Split inside
        the base64 so packet 1 alone is a syntactically valid record carrying a
        truncated image — which `_store_photo_table` could not tell from a
        small one."""
        command_id = self.queue_query(command="DATA QUERY tablename=biophoto")
        body = self.photo_body()
        cut = body.index("content=") + 8 + 40   # 40 characters into the blob

        self.query_post(body[:cut], tablename="biophoto", cmdid=command_id,
                        count=1, packcnt=2, packidx=1)
        self.assertEqual(self.photos(), {})

        self.query_post(body[cut:], tablename="biophoto", cmdid=command_id,
                        count=1, packcnt=2, packidx=2)

        photos = self.photos()
        self.assertEqual(list(photos), [("1", "biophoto")])
        self.assertEqual(photos[("1", "biophoto")].content, REALISTIC_PHOTO_B64)
        # And it still decodes to the original bytes, which is the only test
        # that a truncation would actually fail.
        self.assertEqual(
            base64.b64decode(photos[("1", "biophoto")].content),
            _REALISTIC_PHOTO_BYTES,
        )

    def test_packets_are_reassembled_in_index_order_not_arrival_order(self):
        command_id = self.queue_query(command="DATA QUERY tablename=biophoto")
        body = self.photo_body()
        cut = body.index("content=") + 8 + 40

        self.query_post(body[cut:], tablename="biophoto", cmdid=command_id,
                        count=1, packcnt=2, packidx=2)
        self.query_post(body[:cut], tablename="biophoto", cmdid=command_id,
                        count=1, packcnt=2, packidx=1)

        self.assertEqual(
            self.photos()[("1", "biophoto")].content, REALISTIC_PHOTO_B64
        )

    def test_a_split_on_a_record_boundary_does_not_glue_two_records(self):
        """The other plausible chunking. If the firmware splits between records
        and drops the trailing newline, plain concatenation would produce
        `…verify=0user uid=2…` — one mangled record instead of two good ones."""
        command_id = self.queue_query()
        first, second, third = CAPTURED_USER_UPLOAD.splitlines()

        self.query_post(first, cmdid=command_id, count=3, packcnt=2, packidx=1)
        self.query_post(f"{second}\n{third}\n", cmdid=command_id, count=3,
                        packcnt=2, packidx=2)

        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])

    def test_a_transfer_that_never_completes_stores_nothing_and_concludes_nothing(self):
        command_id = self.queue_query()
        first = CAPTURED_USER_UPLOAD.splitlines()[0]

        self.query_post(first + "\n", cmdid=command_id, count=3,
                        packcnt=3, packidx=1)
        self.query_post(CAPTURED_USER_UPLOAD.splitlines()[1] + "\n",
                        cmdid=command_id, count=3, packcnt=3, packidx=2)

        self.assertEqual(self.employees(), {})
        self.assertEqual([r.id for r in self.outbox(self.QSN)], [command_id])
        self.assertEqual(self.history(self.QSN), [])

    def test_an_incomplete_packet_is_still_acknowledged(self):
        """Buffering is not a reason to leave the packet unanswered — an
        unanswered packet is a repeated packet."""
        command_id = self.queue_query()
        response = self.query_post(
            CAPTURED_USER_UPLOAD.splitlines()[0] + "\n", cmdid=command_id,
            count=3, packcnt=3, packidx=1,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "user=3")

    def test_repeating_one_packet_cannot_complete_a_transfer(self):
        """Completion counts distinct packets, so a device retrying packet 1
        of 3 forever never tricks the server into parsing a third of an answer."""
        command_id = self.queue_query()
        first = CAPTURED_USER_UPLOAD.splitlines()[0] + "\n"
        for _ in range(5):
            self.query_post(first, cmdid=command_id, count=3, packcnt=3, packidx=1)

        self.assertEqual(self.employees(), {})
        self.assertEqual([r.id for r in self.outbox(self.QSN)], [command_id])

    def test_two_devices_answering_at_once_do_not_mix_payloads(self):
        mine = self.queue_query()
        theirs = self.queue(command=QUERY_COMMAND, sn=self.SN)
        self.poll(sn=self.SN)

        lines = CAPTURED_USER_UPLOAD.splitlines()
        self.query_post(lines[0] + "\n", cmdid=mine, count=2, packcnt=2, packidx=1)
        self.query_post(lines[1] + "\n", sn=self.SN, cmdid=theirs, count=2,
                        packcnt=2, packidx=1)
        # Only this device's transfer completes.
        self.query_post(lines[2] + "\n", cmdid=mine, count=2, packcnt=2, packidx=2)

        self.assertEqual(sorted(self.employees()), ["1", "3"])
        self.assertEqual([r.id for r in self.outbox(self.SN)], [theirs])
        self.assertEqual(self.outbox(self.QSN), [])

    def test_an_abandoned_transfer_is_expired_loudly_and_stores_nothing(self):
        """A device that starts a nine-packet answer and reboots. The buffer
        must not be pinned until the process restarts, and the command must be
        left outstanding so the answer can be asked for again."""
        command_id = self.queue_query()
        self.query_post(CAPTURED_USER_UPLOAD.splitlines()[0] + "\n",
                        cmdid=command_id, count=3, packcnt=9, packidx=1)
        self.assertEqual(len(adms._transfers), 1)

        for entry in adms._transfers.values():
            entry["updated"] -= config.QUERYDATA_TRANSFER_TTL_SECONDS + 1

        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3)

        self.assertIn("abandoning incomplete transfer", "\n".join(captured.output))
        # The stale fragment did not become part of the new answer.
        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])

    def test_an_oversized_transfer_is_discarded_rather_than_stored(self):
        command_id = self.queue_query()
        original = config.QUERYDATA_MAX_TRANSFER_BYTES
        config.QUERYDATA_MAX_TRANSFER_BYTES = 100
        try:
            with self.assertLogs("app.routers.adms", level="ERROR") as captured:
                self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id,
                                count=3, packcnt=2, packidx=1)
        finally:
            config.QUERYDATA_MAX_TRANSFER_BYTES = original

        self.assertIn("QUERYDATA_MAX_TRANSFER_BYTES", "\n".join(captured.output))
        self.assertEqual(self.employees(), {})
        self.assertEqual([r.id for r in self.outbox(self.QSN)], [command_id])
        self.assertEqual(adms._transfers, {})

    def test_the_number_of_open_transfers_is_bounded(self):
        original = config.QUERYDATA_MAX_TRANSFERS
        config.QUERYDATA_MAX_TRANSFERS = 1
        try:
            self.query_post("user pin=1\n", cmdid=1, count=2, packcnt=2, packidx=1)
            with self.assertLogs("app.routers.adms", level="WARNING"):
                self.query_post("user pin=2\n", cmdid=2, count=2,
                                packcnt=2, packidx=1)
        finally:
            config.QUERYDATA_MAX_TRANSFERS = original

        self.assertEqual(len(adms._transfers), 1)
        self.assertEqual(self.employees(), {})

    def test_a_restarted_transfer_does_not_splice_two_answers(self):
        """The device changing its mind about how many packets there are means
        this is a new answer, not a continuation of the old one."""
        command_id = self.queue_query()
        self.query_post("user uid=99\tpin=99\tname=Stale\n", cmdid=command_id,
                        count=1, packcnt=4, packidx=1)

        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3)

        self.assertIn("restarted", "\n".join(captured.output))
        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])


class QueryDataIdempotencyTests(QueryDataTestCase):
    """The device has already retried this upload dozens of times against a
    404, and will retry again after deploy. Re-delivery must converge."""

    def test_redelivering_the_same_answer_does_not_duplicate_employees(self):
        command_id = self.queue_query()
        for _ in range(4):
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3)

        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])
        db = self.Session()
        try:
            self.assertEqual(db.query(Employee).count(), 3)
        finally:
            db.close()

    def test_redelivering_writes_exactly_one_history_row(self):
        command_id = self.queue_query()
        for _ in range(3):
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3)

        self.assertEqual(len(self.history(self.QSN)), 1)
        self.assert_exactly_one_home(QUERY_COMMAND, sn=self.QSN)

    def test_a_redelivered_answer_is_acknowledged_the_same_way_every_time(self):
        command_id = self.queue_query()
        replies = {
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3).text
            for _ in range(3)
        }
        self.assertEqual(replies, {"user=3"})

    def test_a_retried_packet_overwrites_rather_than_appends(self):
        """Re-delivery inside a multi-packet transfer, which is the case a
        naive append would corrupt: the record would be stored twice, glued."""
        command_id = self.queue_query(command="DATA QUERY tablename=biophoto")
        body = (
            f"biophoto pin=1\tfilename=1.jpg\ttype=9"
            f"\tsize={len(REALISTIC_PHOTO_B64)}\tcontent={REALISTIC_PHOTO_B64}\n"
        )
        cut = body.index("content=") + 8 + 40

        self.query_post(body[:cut], tablename="biophoto", cmdid=command_id,
                        count=1, packcnt=2, packidx=1)
        self.query_post(body[:cut], tablename="biophoto", cmdid=command_id,
                        count=1, packcnt=2, packidx=1)
        self.query_post(body[cut:], tablename="biophoto", cmdid=command_id,
                        count=1, packcnt=2, packidx=2)

        self.assertEqual(
            self.photos()[("1", "biophoto")].content, REALISTIC_PHOTO_B64
        )

    def test_leftover_state_does_not_survive_a_completed_transfer(self):
        command_id = self.queue_query()
        self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3)
        self.assertEqual(adms._transfers, {})


class QueryDataAuthorisationTests(QueryDataTestCase):
    """A public endpoint that writes employees, templates and photos. It must
    not become a hole around the controls every other ADMS endpoint has."""

    def test_an_unapproved_serial_is_refused_exactly_like_the_others(self):
        db = self.Session()
        try:
            db.add(Device(serial_number="E9PENDING00001", ip_address="203.0.113.10",
                          port=4370, name="Waiting", status="pending"))
            db.commit()
        finally:
            db.close()

        response = self.query_post(CAPTURED_USER_UPLOAD, sn="E9PENDING00001",
                                   cmdid=1, count=3)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.text, "Unauthorized")
        self.assertEqual(self.employees(), {})

    def test_an_unknown_serial_with_the_pairing_window_shut_is_refused(self):
        response = self.query_post(CAPTURED_USER_UPLOAD, sn="E9STRANGER0001",
                                   cmdid=1, count=3)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.employees(), {})

    def test_a_source_outside_the_device_allowlist_is_refused(self):
        """The per-device CIDR check, which is the control D3 added and which
        this endpoint must not be a way around."""
        response = self.query_post(CAPTURED_USER_UPLOAD, sn=self.CIDR_SN,
                                   cmdid=1, count=3)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.employees(), {})

    def test_a_refused_request_concludes_nothing(self):
        """Otherwise anyone could retire another site's commands by guessing
        an id — no data written, but the queue emptied."""
        command_id = self.queue_query()
        self.query_post(CAPTURED_USER_UPLOAD, sn="E9STRANGER0001",
                        cmdid=command_id, count=3)
        self.assertEqual([r.id for r in self.outbox(self.QSN)], [command_id])

    def test_a_refusal_leaves_no_reassembly_buffer_behind(self):
        """An unauthorised caller must not be able to allocate memory here."""
        self.query_post("user pin=1\n", sn="E9STRANGER0001", cmdid=1,
                        count=2, packcnt=2, packidx=1)
        self.assertEqual(adms._transfers, {})

    def test_the_refusal_is_recorded_for_the_operator(self):
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            self.query_post(CAPTURED_USER_UPLOAD, sn="E9STRANGER0001",
                            cmdid=1, count=3)
        self.assertIn("ADMS refused", "\n".join(captured.output))


class QueryDataTableDispatchTests(QueryDataTestCase):
    """One table, one parser, whichever door the payload came through."""

    def test_biodata_reaches_the_same_parser_as_a_tabledata_push(self):
        command_id = self.queue_query(command="DATA QUERY tablename=biodata")
        self.query_post(CAPTURED_BIODATA_UPLOAD, tablename="biodata",
                        cmdid=command_id, count=2)

        templates = self.templates()
        self.assertEqual(sorted(templates), [("1", 1, 5), ("1", 9, 0)])
        self.assertEqual(templates[("1", 1, 5)].majorver, 13)
        self.assertEqual(templates[("1", 1, 5)].source_device_sn, self.QSN)
        self.assertEqual(self.outbox(self.QSN), [])

    def test_biophoto_reaches_the_same_parser_as_a_tabledata_push(self):
        command_id = self.queue_query(command="DATA QUERY tablename=biophoto")
        self.query_post(
            f"biophoto pin=1\tfilename=1.jpg\ttype=9"
            f"\tsize=104904\tcontent={REALISTIC_PHOTO_B64}\n",
            tablename="biophoto", cmdid=command_id, count=1,
        )
        photos = self.photos()
        self.assertEqual(list(photos), [("1", "biophoto")])
        self.assertEqual(photos[("1", "biophoto")].content, REALISTIC_PHOTO_B64)

    def test_userpic_reaches_the_same_parser_as_a_tabledata_push(self):
        command_id = self.queue_query(command="DATA QUERY tablename=userpic")
        self.query_post(
            f"userpic pin=2\tfilename=2.jpg\tsize=95016"
            f"\tcontent={REALISTIC_PHOTO_B64}\n",
            tablename="userpic", cmdid=command_id, count=1,
        )
        self.assertEqual(list(self.photos()), [("2", "userpic")])

    def test_a_blob_answer_is_summarised_in_the_log_rather_than_dumped(self):
        command_id = self.queue_query(command="DATA QUERY tablename=biophoto")
        with self.assertLogs("app.routers.adms", level="INFO") as captured:
            self.query_post(
                f"biophoto pin=1\tfilename=1.jpg\ttype=9"
                f"\tsize=104904\tcontent={REALISTIC_PHOTO_B64}\n",
                tablename="biophoto", cmdid=command_id, count=1,
            )
        joined = "\n".join(captured.output)
        self.assertIn("not logged", joined)
        self.assertNotIn(REALISTIC_PHOTO_B64, joined)

    def test_a_keyed_answer_is_kept_whole_in_the_log(self):
        with self.assertLogs("app.routers.adms", level="INFO") as captured:
            self.query_post(CAPTURED_USER_UPLOAD, cmdid=1, count=3)
        joined = "\n".join(captured.output)
        for uid in ("uid=1", "uid=2", "uid=3"):
            self.assertIn(uid, joined)

    def test_no_second_parser_was_written_for_this_endpoint(self):
        """E1, E2 and E5 already parse these tables. A second implementation
        is how the same record comes to mean two different things depending on
        which endpoint it arrived at."""
        import inspect as _inspect
        source = _inspect.getsource(adms.adms_querydata)
        self.assertIn("_store_bulk_table", source)
        for parser in ("_store_user_table", "_store_biodata_table",
                       "_store_photo_table", "_tabledata_fields"):
            self.assertNotIn(parser, source)


class QueryDataUnknownTableTests(QueryDataTestCase):
    """The discipline that produced this unit in the first place: log what you
    do not understand, acknowledge it, and never drop it silently."""

    def test_an_unknown_tablename_is_logged_with_its_body(self):
        command_id = self.queue_query(command="DATA QUERY tablename=extuser")
        body = "extuser pin=1\tfunswitch=1\tfirstname=Aisha\tpersonalvs=0\n"

        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.query_post(body, tablename="extuser",
                                       cmdid=command_id, count=1)

        joined = "\n".join(captured.output)
        self.assertEqual(response.status_code, 200)
        self.assertIn("no parser for tablename", joined)
        self.assertIn("firstname=Aisha", joined)

    def test_an_unknown_tablename_is_acknowledged_not_refused(self):
        command_id = self.queue_query(command="DATA QUERY tablename=extuser")
        with self.assertLogs("app.routers.adms", level="WARNING"):
            response = self.query_post("extuser pin=1\n", tablename="extuser",
                                       cmdid=command_id, count=1)
        self.assertEqual(response.text, "extuser=1")

    def test_an_unknown_tablename_still_concludes_the_command(self):
        """The device did answer. Leaving the command outstanding would retry a
        query whose answer we already know we cannot use."""
        command_id = self.queue_query(command="DATA QUERY tablename=extuser")
        with self.assertLogs("app.routers.adms", level="WARNING"):
            self.query_post("extuser pin=1\n", tablename="extuser",
                            cmdid=command_id, count=1)
        self.assertEqual(self.outbox(self.QSN), [])
        self.assertEqual(self.history(self.QSN)[0].outcome, "acknowledged")

    def test_a_request_with_no_tablename_is_logged_and_answered(self):
        with self.assertLogs("app.routers.adms", level="WARNING") as captured:
            response = self.client.post(
                f"/iclock/querydata?SN={self.QSN}&type=tabledata&cmdid=1",
                content="something nobody has seen before\n",
            )
        self.assertEqual(response.text, "OK")
        joined = "\n".join(captured.output)
        self.assertIn("no tablename", joined)
        self.assertIn("something nobody has seen before", joined)

    def test_an_unfamiliar_type_is_still_dispatched_on_its_tablename(self):
        """`type=` is recorded, not obeyed. The body's shape is what decides,
        and a firmware inventing a new `type` must not silently lose a table
        we do know how to parse."""
        command_id = self.queue_query()
        self.query_post(CAPTURED_USER_UPLOAD, cmdid=command_id, count=3,
                        qtype="somethingelse")
        self.assertEqual(sorted(self.employees()), ["1", "2", "3"])


class QueryDataStorageFailureTests(QueryDataTestCase):
    """A storage fault must not become an infinite upload loop."""

    def test_a_failing_parser_still_acknowledges_and_concludes(self):
        def boom(*args, **kwargs):
            raise RuntimeError("simulated storage failure")

        command_id = self.queue_query()
        original = adms._store_user_table
        adms._store_user_table = boom
        try:
            with self.assertLogs("app.routers.adms", level="ERROR"):
                response = self.query_post(CAPTURED_USER_UPLOAD,
                                           cmdid=command_id, count=3)
        finally:
            adms._store_user_table = original

        self.assertEqual(response.text, "user=3")
        self.assertEqual(self.outbox(self.QSN), [])
