"""Tests for GET /attendance/export.xlsx — the monthly payroll workbook.

Run with the standard library only, alongside the ADMS suite:

    python -m unittest discover -s tests -v

What matters here is not that a file comes back but *what is in it*. Four
things are worth guarding:

  1. The export follows the filter, not the page. The table on screen shows 50
     rows; an operator who picks a month and gets 50 of their 900 punches has
     been handed a wrong timesheet with no error anywhere.
  2. The daily sheet pairs the *first* and *last* punch of a day. It must not
     go by the device's status field: on the live installation 96,002 of
     96,075 records carry status=1, so selecting by status yields a sheet of
     check-outs with no check-ins.
  3. Punch times are not re-zoned. The stored digits are the device's own
     wall-clock, and the workbook must carry those digits with the label next
     to them — the same rule the UI and the HRM push follow.
  4. An export larger than the configured ceiling is refused with a message,
     not built.

Everything runs against a throwaway in-memory SQLite database.
"""

import os
import unittest
from datetime import datetime, time
from io import BytesIO

# Set before importing anything from `app` — see tests/test_adms.py for why.
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "x" * 48)
os.environ.setdefault("DEFAULT_DEVICE_TIMEZONE", "Asia/Dubai")

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402
from openpyxl import load_workbook                             # noqa: E402
from sqlalchemy import create_engine                           # noqa: E402
from sqlalchemy.orm import sessionmaker                        # noqa: E402
from sqlalchemy.pool import StaticPool                         # noqa: E402

from app import config                                         # noqa: E402
from app.database import Base, get_db                          # noqa: E402
from app.deps import require_auth                              # noqa: E402
from app.models import AttendanceLog, AuditLog, Device, Employee, User   # noqa: E402
from app.routers import attendance as attendance_router        # noqa: E402

MAIN_SN = "EXPORTDEV0001"
OTHER_SN = "EXPORTDEV0002"

XLSX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

# The status every punch on the operator's live installation carries, because
# nobody presses the mode key on the terminal. Used throughout so these tests
# exercise the data as it really arrives, not an idealised in/out alternation.
UNPRESSED = 1


class ExportTestCase(unittest.TestCase):
    """A fresh in-memory database, a signed-in operator and a client."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        app = FastAPI()
        app.include_router(attendance_router.router)

        def _override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        # Being signed in is a precondition of this endpoint, not its subject.
        operator = User(id=1, username="tester", role="viewer", password_hash="x")
        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides[require_auth] = lambda: operator
        self.client = TestClient(app, client=("203.0.113.10", 40000))

        db = self.Session()
        try:
            db.add(Device(serial_number=MAIN_SN, ip_address="203.0.113.10", port=4370,
                          name="Main Door", status="approved", timezone="Asia/Dubai"))
            db.add(Device(serial_number=OTHER_SN, ip_address="203.0.113.11", port=4370,
                          name="Warehouse", status="approved", timezone="Europe/London"))
            db.add(Employee(user_id="1001", name="Nguyen Van A"))
            db.add(Employee(user_id="1002", name="Tran Thi B"))
            db.commit()
        finally:
            db.close()

        self.seed()

    def tearDown(self):
        self.client.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    # -- helpers ---------------------------------------------------------

    def seed(self):
        """Per-suite fixture data. Overridden below."""

    def punch(self, moment, user_id="1001", sn=MAIN_SN, status=UNPRESSED,
              punch=1, zone="Asia/Dubai", source="adms_push"):
        db = self.Session()
        try:
            db.add(AttendanceLog(device_sn=sn, user_id=user_id, timestamp=moment,
                                 status=status, punch=punch, source=source,
                                 timezone=zone))
            db.commit()
        finally:
            db.close()

    def export(self, mode, **params):
        return self.client.get("/attendance/export.xlsx",
                               params={"mode": mode, **params})

    def sheet(self, response):
        wb = load_workbook(BytesIO(response.content))
        return wb.worksheets[0]

    def rows(self, response):
        """Data rows only, as lists of values — the header is row 1."""
        ws = self.sheet(response)
        return [list(r) for r in ws.iter_rows(min_row=2, values_only=True)]


class RawExportTests(ExportTestCase):
    """mode=raw — every punch, one per row."""

    def seed(self):
        # Deliberately inserted newest-first, so a workbook that comes back
        # oldest-first proves the export sorted rather than got lucky.
        self.punch(datetime(2026, 9, 2, 8, 1, 0), user_id="1002", sn=OTHER_SN,
                   status=0, punch=15, zone=None)
        self.punch(datetime(2026, 9, 1, 17, 30, 0), status=1)
        self.punch(datetime(2026, 9, 1, 14, 48, 22), status=0)

    def test_returns_an_xlsx_with_a_named_attachment(self):
        res = self.export("raw")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], XLSX_MEDIA_TYPE)
        self.assertIn("attachment;", res.headers["content-disposition"])
        self.assertIn("attendance-punches", res.headers["content-disposition"])
        # A real workbook, not an error page that happens to have the type.
        self.assertTrue(res.content.startswith(b"PK"))

    def test_header_row_is_the_documented_columns(self):
        header = [c.value for c in self.sheet(self.export("raw"))[1]]
        self.assertEqual(header, [
            "Employee ID", "Employee Name", "Timestamp", "Timezone",
            "Status", "Verification", "Device", "Device SN", "Source",
        ])

    def test_sheet_is_usable_as_a_spreadsheet(self):
        """Frozen header, a filter over the data, sized columns.

        Not cosmetics: in write-only mode a freeze set after the rows are
        written is silently dropped, and an auto-filter that covers only the
        header row leaves the recipient unable to filter the month at all.
        """
        ws = self.sheet(self.export("raw"))
        self.assertEqual(ws.freeze_panes, "A2")
        self.assertEqual(ws.auto_filter.ref, "A1:I4")   # header + 3 records
        self.assertEqual(ws.column_dimensions["B"].width, 28)

    def test_exports_every_matching_record_oldest_first(self):
        rows = self.rows(self.export("raw"))
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            [r[2] for r in rows],
            [
                datetime(2026, 9, 1, 14, 48, 22),
                datetime(2026, 9, 1, 17, 30, 0),
                datetime(2026, 9, 2, 8, 1, 0),
            ],
        )

    def test_punch_time_is_written_unconverted_and_labelled(self):
        """The 14:48 punch stays 14:48, next to the label that explains it.

        Written as a real datetime so the recipient can sort and pivot it, and
        as a *naive* one: the column type hands back a UTC-aware value, and
        either converting it or writing the offset would move the hour.
        """
        first = self.rows(self.export("raw"))[0]
        self.assertEqual(first[2], datetime(2026, 9, 1, 14, 48, 22))
        self.assertIsNone(first[2].tzinfo)
        self.assertEqual(first[3], "Asia/Dubai")

    def test_unstamped_row_falls_back_to_its_device_zone(self):
        """A record older than the timezone column is labelled from its device,
        never left blank and never silently assumed to be UTC."""
        rows = self.rows(self.export("raw", device_sn=OTHER_SN))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][3], "Europe/London")

    def test_filters_are_applied(self):
        rows = self.rows(self.export(
            "raw",
            device_sn=MAIN_SN,
            user_id="1001",
            from_date="2026-09-01T00:00:00",
            to_date="2026-09-01T16:00:00",
        ))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "1001")
        self.assertEqual(rows[0][2], datetime(2026, 9, 1, 14, 48, 22))

    def test_names_and_labels_are_resolved(self):
        rows = self.rows(self.export("raw", user_id="1001"))
        self.assertEqual([r[1] for r in rows], ["Nguyen Van A", "Nguyen Van A"])
        self.assertEqual([r[4] for r in rows], ["Check In", "Check Out"])
        self.assertEqual([r[5] for r in rows], ["Fingerprint", "Fingerprint"])
        self.assertEqual([r[6] for r in rows], ["Main Door", "Main Door"])
        self.assertEqual([r[7] for r in rows], [MAIN_SN, MAIN_SN])
        self.assertEqual([r[8] for r in rows], ["adms_push", "adms_push"])

    def test_unknown_person_falls_back_to_the_pin(self):
        """A punch from a PIN the system has no employee row for is still
        exported — with the PIN in the name column, not a blank."""
        self.punch(datetime(2026, 9, 3, 9, 0, 0), user_id="9999", source="sdk_pull")
        rows = self.rows(self.export("raw", user_id="9999"))
        self.assertEqual(rows[0][1], "9999")

    def test_unknown_status_and_punch_codes_are_shown_raw(self):
        self.punch(datetime(2026, 9, 4, 9, 0, 0), status=7, punch=2)
        rows = self.rows(self.export("raw", from_date="2026-09-04T00:00:00"))
        self.assertEqual(rows[0][4], "Status 7")
        self.assertEqual(rows[0][5], "Mode 2")


class DailyExportTests(ExportTestCase):
    """mode=daily — one row per person per day, first punch in, last punch out."""

    def seed(self):
        # A normal day for 1001: in, two trips through the door at lunch, out.
        # Every punch carries the same status, exactly as the live terminals
        # send them — the pairing must come from the clock, not from status.
        for moment in [
            datetime(2026, 9, 1, 8, 2, 11),
            datetime(2026, 9, 1, 12, 0, 0),
            datetime(2026, 9, 1, 13, 1, 0),
            datetime(2026, 9, 1, 17, 30, 45),
        ]:
            self.punch(moment)

        # 1002 the same day, on the other terminal, with no snapshot zone.
        self.punch(datetime(2026, 9, 1, 8, 15, 3), user_id="1002", sn=OTHER_SN, zone=None)
        self.punch(datetime(2026, 9, 1, 17, 2, 20), user_id="1002", sn=OTHER_SN, zone=None)

        # A second day for 1001, to prove days do not bleed into each other.
        self.punch(datetime(2026, 9, 2, 7, 58, 40))
        self.punch(datetime(2026, 9, 2, 18, 5, 12))

    def test_is_the_default_mode(self):
        """No `mode` at all is the timesheet — what the button sends."""
        res = self.client.get("/attendance/export.xlsx")
        self.assertEqual(self.sheet(res).title, "Daily Attendance")
        self.assertIn("attendance-daily", res.headers["content-disposition"])

    def test_header_row_is_the_documented_columns(self):
        header = [c.value for c in self.sheet(self.export("daily"))[1]]
        self.assertEqual(header, [
            "Date", "Employee ID", "Employee Name", "Check In", "Check Out",
            "Hours", "Punches", "Check In Device", "Check Out Device", "Timezone",
        ])

    def test_one_row_per_person_per_day(self):
        rows = self.rows(self.export("daily"))
        self.assertEqual(len(rows), 3)   # 1001 on two days, 1002 on one
        # Read back as midnight datetimes: Excel has no pure date type, so a
        # date cell round-trips as a datetime carrying the yyyy-mm-dd format
        # that makes it display as a date.
        self.assertEqual(
            [(r[0], r[1]) for r in rows],
            [
                (datetime(2026, 9, 1), "1001"),
                (datetime(2026, 9, 1), "1002"),
                (datetime(2026, 9, 2), "1001"),
            ],
        )

    def test_first_punch_is_check_in_and_last_is_check_out(self):
        """The four punches of 2026-09-01 collapse to 08:02 → 17:30.

        The two midday punches are counted, not paired: only the ends of the
        day are the times payroll is given.
        """
        row = self.rows(self.export("daily", user_id="1001"))[0]
        self.assertEqual(row[3], time(8, 2, 11))
        self.assertEqual(row[4], time(17, 30, 45))
        self.assertEqual(row[6], 4)

    def test_hours_is_the_span_between_them(self):
        row = self.rows(self.export("daily", user_id="1001"))[0]
        # 08:02:11 → 17:30:45 is 9h 28m 34s.
        self.assertAlmostEqual(row[5], 9.48, places=2)

    def test_times_are_written_as_real_times_not_text(self):
        """So the recipient can sort, filter and pivot the month in Excel."""
        ws = self.sheet(self.export("daily", user_id="1001"))
        self.assertEqual(ws["A2"].number_format, "yyyy-mm-dd")
        self.assertEqual(ws["D2"].number_format, "hh:mm:ss")
        self.assertEqual(ws["F2"].number_format, "0.00")

    def test_a_single_punch_day_leaves_check_out_empty(self):
        """Somebody who forgot to punch out is not a zero-hour day.

        Repeating the check-in as the check-out would produce a row that reads
        as a worked day of 0.00 hours, which is a wrong number rather than a
        missing one. The Punches column is what says why it is blank.
        """
        self.punch(datetime(2026, 9, 3, 8, 30, 0))
        row = self.rows(self.export("daily", user_id="1001",
                                    from_date="2026-09-03T00:00:00"))[0]
        self.assertEqual(row[3], time(8, 30, 0))
        self.assertIsNone(row[4])
        self.assertIsNone(row[5])
        self.assertEqual(row[6], 1)
        self.assertIsNone(row[8])   # no check-out device either

    def test_status_field_is_not_used_to_pair(self):
        """Every punch here carries status=1 ('Check Out') and the day still
        pairs correctly — the regression that would silently produce a sheet
        of check-outs with no check-ins."""
        rows = self.rows(self.export("daily", user_id="1002"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][3], time(8, 15, 3))
        self.assertEqual(rows[0][4], time(17, 2, 20))

    def test_devices_and_zone_are_named(self):
        row = self.rows(self.export("daily", user_id="1002"))[0]
        self.assertEqual(row[2], "Tran Thi B")
        self.assertEqual(row[7], "Warehouse")
        self.assertEqual(row[8], "Warehouse")
        # No snapshot on these rows: resolved from the device, as everywhere else.
        self.assertEqual(row[9], "Europe/London")

    def test_a_day_split_across_zones_names_both(self):
        """Punching in at one site and out at another in a different zone: the
        two times on that row do not share a meaning, and the sheet says so
        instead of picking one label and hiding it."""
        self.punch(datetime(2026, 9, 4, 8, 0, 0), zone="Asia/Dubai")
        self.punch(datetime(2026, 9, 4, 16, 0, 0), sn=OTHER_SN, zone="Europe/London")
        row = self.rows(self.export("daily", user_id="1001",
                                    from_date="2026-09-04T00:00:00"))[0]
        self.assertEqual(row[7], "Main Door")
        self.assertEqual(row[8], "Warehouse")
        self.assertEqual(row[9], "Asia/Dubai / Europe/London")

    def test_a_midnight_crossing_stays_two_days(self):
        """A night shift is reported as the terminal recorded it: a late
        check-in on one date and an early check-out on the next. Inventing a
        shift boundary here would be guessing at a roster this app does not
        have."""
        self.punch(datetime(2026, 9, 10, 22, 45, 0))
        self.punch(datetime(2026, 9, 11, 6, 15, 0))
        rows = self.rows(self.export("daily", user_id="1001",
                                     from_date="2026-09-10T00:00:00"))
        self.assertEqual([r[0] for r in rows],
                         [datetime(2026, 9, 10), datetime(2026, 9, 11)])
        self.assertEqual([r[6] for r in rows], [1, 1])

    def test_filters_are_applied(self):
        rows = self.rows(self.export(
            "daily",
            device_sn=MAIN_SN,
            from_date="2026-09-02T00:00:00",
            to_date="2026-09-02T23:59:59",
        ))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "1001")
        self.assertEqual(rows[0][3], time(7, 58, 40))

    def test_sheet_is_usable_as_a_spreadsheet(self):
        ws = self.sheet(self.export("daily"))
        self.assertEqual(ws.freeze_panes, "A2")
        self.assertEqual(ws.auto_filter.ref, "A1:J4")   # header + 3 person-days


class ExportGuardTests(ExportTestCase):
    """Refusals, naming, auditing — the parts that are not about cell values."""

    def seed(self):
        self.punch(datetime(2026, 9, 1, 8, 0, 0))
        self.punch(datetime(2026, 9, 1, 17, 0, 0))
        self.punch(datetime(2026, 9, 2, 8, 1, 0), user_id="1002", sn=OTHER_SN, zone=None)

    def test_empty_result_is_an_empty_workbook_not_an_error(self):
        for mode in ("daily", "raw"):
            with self.subTest(mode=mode):
                res = self.export(mode, user_id="does-not-exist")
                self.assertEqual(res.status_code, 200)
                self.assertEqual(self.rows(res), [])

    def test_filename_carries_the_filter(self):
        res = self.export("daily", device_sn=MAIN_SN,
                          from_date="2026-09-01T00:00:00",
                          to_date="2026-09-30T23:59:59")
        disposition = res.headers["content-disposition"]
        self.assertIn(MAIN_SN, disposition)
        self.assertIn("20260901", disposition)
        self.assertIn("20260930", disposition)
        # ASCII only — nothing here needs RFC 5987 encoding to survive.
        disposition.encode("ascii")

    def test_an_unknown_mode_is_rejected(self):
        res = self.export("weekly")
        self.assertEqual(res.status_code, 422)

    def test_too_many_rows_is_refused_with_the_numbers(self):
        """The ceiling counts punches read, in both modes — a daily sheet is
        small but is still built by walking every punch behind it."""
        original = config.ATTENDANCE_EXPORT_MAX_ROWS
        config.ATTENDANCE_EXPORT_MAX_ROWS = 2
        try:
            for mode in ("daily", "raw"):
                with self.subTest(mode=mode):
                    res = self.export(mode)
                    self.assertEqual(res.status_code, 400)
                    detail = res.json()["detail"]
                    self.assertIn("3", detail)      # what matched
                    self.assertIn("2", detail)      # what is allowed
                    self.assertIn("Narrow the date range", detail)
        finally:
            config.ATTENDANCE_EXPORT_MAX_ROWS = original

    def test_export_is_audited(self):
        self.export("daily", device_sn=MAIN_SN)

        db = self.Session()
        try:
            entry = db.query(AuditLog).filter_by(action="attendance_export").one()
        finally:
            db.close()

        self.assertEqual(entry.actor, "tester")
        self.assertEqual(entry.ip, "203.0.113.10")
        self.assertIn("mode=daily", entry.detail)
        self.assertIn("rows=2", entry.detail)
        self.assertIn(f"device={MAIN_SN}", entry.detail)

    def test_refused_export_writes_no_audit_row(self):
        original = config.ATTENDANCE_EXPORT_MAX_ROWS
        config.ATTENDANCE_EXPORT_MAX_ROWS = 1
        try:
            self.export("raw")
        finally:
            config.ATTENDANCE_EXPORT_MAX_ROWS = original

        db = self.Session()
        try:
            self.assertEqual(
                db.query(AuditLog).filter_by(action="attendance_export").count(), 0)
        finally:
            db.close()

    def test_listing_still_answers_alongside_the_export_route(self):
        """`/attendance/export.xlsx` must not shadow the list endpoint."""
        res = self.client.get("/attendance")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["total"], 3)


if __name__ == "__main__":
    unittest.main()
