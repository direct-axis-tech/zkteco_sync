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
from app.models import AdmsPairing, AttendanceLog, Device      # noqa: E402
from app.routers import adms                                   # noqa: E402


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
