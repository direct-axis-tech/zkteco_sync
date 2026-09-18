from datetime import datetime
from io import BytesIO
from typing import Literal, Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app.deps import require_auth

from app import audit, config
from app.database import get_db
from app.models import AttendanceLog, Device, Employee, User
from app.net import client_ip
from app.schemas import AttendanceOut

router = APIRouter(prefix="/attendance", tags=["attendance"], dependencies=[Depends(require_auth)])


def _build_query(db, device_sn, user_id, from_date, to_date):
    q = db.query(AttendanceLog)
    if device_sn:
        q = q.filter(AttendanceLog.device_sn == device_sn)
    if user_id:
        q = q.filter(AttendanceLog.user_id == user_id)
    if from_date:
        q = q.filter(AttendanceLog.timestamp >= from_date)
    if to_date:
        q = q.filter(AttendanceLog.timestamp <= to_date)
    return q


@router.get("")
def list_attendance(
    device_sn: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    limit: int = Query(50, le=1000),
    offset: int = Query(0),
    db: Session = Depends(get_db),
):
    q = _build_query(db, device_sn, user_id, from_date, to_date)
    total = q.count()
    rows = q.order_by(AttendanceLog.timestamp.desc()).offset(offset).limit(limit).all()

    # A punch time is the device's own wall-clock with no offset, so it is
    # meaningless without a label. Records stamped at ingest carry their own;
    # rows that predate the column resolve to their device's zone, and then to
    # the configured default. The same order the HRM push uses — the UI must
    # never show a time it cannot say the meaning of, and must never invent
    # one by re-zoning it into the viewer's locale.
    device_zones = dict(db.query(Device.serial_number, Device.timezone).all())

    items = []
    for r in rows:
        item = AttendanceOut.model_validate(r)
        if not item.timezone:
            item.timezone = device_zones.get(r.device_sn) or config.DEFAULT_DEVICE_TIMEZONE
        items.append(item)

    return {"total": total, "items": items}




# ---------------------------------------------------------------------------
# Excel export
# ---------------------------------------------------------------------------
# The monthly "send this to payroll" file, in two shapes.
#
#   daily  (default) — one row per person per day: first punch of the day as
#                      check-in, last punch as check-out. This is the timesheet
#                      ZKTime.Net produced and the one HR actually reads.
#   raw              — every punch, one per row. Kept because the daily sheet
#                      is a summary, and the day somebody disputes is the day
#                      you need the punches behind it.
#
# Why first/last rather than the device's own status field: on this
# installation 96,002 of 96,075 records carry status=1, because nobody presses
# the mode key on the terminal. Selecting rows by status would return a sheet
# of check-outs with no check-ins at all. The clock is the only trustworthy
# signal, so it is the one used.
#
# Either shape covers the whole result of the filter, never the page on
# screen: an operator who picks a month and 900 punches match must get the
# whole month, not the 50 rows the table happens to be showing.

_STATUS_LABELS = {
    0: "Check In",
    1: "Check Out",
    2: "Break Out",
    3: "Break In",
    4: "OT In",
    5: "OT Out",
}

# Verification mode, as the SDK/ATTLOG `punch` field reports it. Unknown
# codes are rendered as the raw number rather than guessed at or blanked —
# the same rule the rest of the app follows for device-reported values.
_PUNCH_LABELS = {
    1: "Fingerprint",
    3: "Password",
    4: "Card",
    15: "Face",
}

_RAW_COLUMNS = [
    ("Employee ID", 16),
    ("Employee Name", 28),
    ("Timestamp", 22),
    ("Timezone", 22),
    ("Status", 14),
    ("Verification", 16),
    ("Device", 26),
    ("Device SN", 20),
    ("Source", 14),
]

_DAILY_COLUMNS = [
    ("Date", 12),
    ("Employee ID", 16),
    ("Employee Name", 28),
    ("Check In", 11),
    ("Check Out", 11),
    ("Hours", 9),
    ("Punches", 9),
    ("Check In Device", 24),
    ("Check Out Device", 24),
    ("Timezone", 22),
]

_DATE_FORMAT = "yyyy-mm-dd"
_TIME_FORMAT = "hh:mm:ss"
_TIMESTAMP_FORMAT = "yyyy-mm-dd hh:mm:ss"
_HOURS_FORMAT = "0.00"

_XLSX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

# Rows are streamed from the database in batches rather than materialised as
# one list — a year-sized export is hundreds of thousands of ORM objects.
_EXPORT_BATCH = 2000


def _export_filename(mode, device_sn, user_id, from_date, to_date) -> str:
    """An ASCII-only, filesystem-safe name that says what is inside.

    Deliberately not derived from the device or employee *name*: those are
    free text and may be non-ASCII, and a Content-Disposition filename that
    needs RFC 5987 encoding is one more thing to get wrong in a browser. The
    serial and the PIN are already safe identifiers, and the file's own
    columns carry the readable names.
    """
    parts = ["attendance-daily" if mode == "daily" else "attendance-punches"]
    if device_sn:
        parts.append(device_sn)
    if user_id:
        parts.append(user_id)
    if from_date:
        parts.append(from_date.strftime("%Y%m%d"))
    if to_date:
        parts.append(to_date.strftime("%Y%m%d"))
    if not from_date and not to_date:
        parts.append(datetime.now().strftime("%Y%m%d-%H%M%S"))

    safe = "_".join(
        "".join(c if c.isalnum() or c in "-." else "-" for c in str(p))
        for p in parts
    )
    return f"{safe}.xlsx"


def _lookups(db):
    """Names and zones, resolved once for the whole export.

    The naive version of this is a SELECT per record, which on a month of
    punches is thousands of round trips for a handful of distinct answers.
    """
    employee_names = dict(db.query(Employee.user_id, Employee.name).all())
    device_zones = dict(db.query(Device.serial_number, Device.timezone).all())
    device_names = {
        sn: (name or sn)
        for sn, name in db.query(Device.serial_number, Device.name).all()
    }
    return employee_names, device_zones, device_names


def _zone_of(row, device_zones):
    """What this record's digits mean.

    Same resolution order as the list endpoint and the HRM push: the record's
    own snapshot, then its device's zone, then the configured default. The
    time itself is never converted — only labelled.
    """
    return row.timezone or device_zones.get(row.device_sn) or config.DEFAULT_DEVICE_TIMEZONE


def _wall_clock(row):
    """The punch as the device's clock showed it, with no offset attached.

    The column type hands back a UTC-aware datetime, but these digits are the
    device's own wall-clock and the `Timezone` column is what says so. tzinfo
    is dropped rather than converted: Excel has no concept of an offset and
    openpyxl refuses an aware datetime outright, and converting would move a
    14:48 punch to some other hour — the exact bug D10 exists to prevent.
    """
    return row.timestamp.replace(tzinfo=None) if row.timestamp else None


def _start_sheet(wb, title, columns):
    """A styled, frozen, sized header row — the sheet ready for data."""
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    ws = wb.create_sheet(title=title)

    # Before the first append, not after: in write-only mode the sheet's view
    # settings are serialised as soon as a row is written, so a freeze set at
    # the end is silently dropped and the recipient scrolls a month of punches
    # with no header in sight.
    ws.freeze_panes = "A2"

    for index, (_, width) in enumerate(columns, start=1):
        ws.column_dimensions[get_column_letter(index)].width = width

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_align = Alignment(horizontal="center")

    header = []
    for title_text, _ in columns:
        cell = WriteOnlyCell(ws, value=title_text)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_align
        header.append(cell)
    ws.append(header)
    return ws


def _finish_sheet(ws, columns, data_rows):
    """Close the sheet off with a filter over the data that is actually in it."""
    from openpyxl.utils import get_column_letter

    last_column = get_column_letter(len(columns))
    # Set explicitly: in write-only mode the sheet has no computed dimensions
    # to read back, and an auto_filter over the header alone would leave the
    # recipient unable to filter the month.
    ws.auto_filter.ref = f"A1:{last_column}{data_rows + 1}"


def _formatted(ws, value, number_format):
    """A cell that carries a real date/time/number, not a rendered string —
    so the recipient can sort, filter and pivot the month in Excel."""
    from openpyxl.cell import WriteOnlyCell

    cell = WriteOnlyCell(ws, value=value)
    cell.number_format = number_format
    return cell


def _build_raw_workbook(db, rows) -> BytesIO:
    """Every punch, one per row, oldest first."""
    from openpyxl import Workbook

    # write_only: cells are streamed to the sheet as they are appended instead
    # of being held as objects until save(). What keeps a large export inside
    # a sane amount of memory.
    wb = Workbook(write_only=True)
    ws = _start_sheet(wb, "Attendance", _RAW_COLUMNS)

    employee_names, device_zones, device_names = _lookups(db)

    count = 0
    for row in rows:
        ws.append([
            row.user_id,
            employee_names.get(row.user_id) or row.user_id,
            _formatted(ws, _wall_clock(row), _TIMESTAMP_FORMAT),
            _zone_of(row, device_zones),
            _STATUS_LABELS.get(row.status, f"Status {row.status}"),
            _PUNCH_LABELS.get(row.punch, f"Mode {row.punch}"),
            device_names.get(row.device_sn, row.device_sn),
            row.device_sn,
            row.source,
        ])
        count += 1

    _finish_sheet(ws, _RAW_COLUMNS, count)

    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    return buffer


def _daily_groups(rows, device_zones):
    """Collapse punches into one entry per (day, person).

    A "day" is the calendar date on the device's own clock — the digits that
    were stored, never re-zoned. A night shift that crosses midnight therefore
    appears as a late check-in on one day and an early check-out on the next,
    which is what the terminal itself recorded and what any shift model would
    have to start from anyway.

    First and last are compared rather than assumed from the query's ORDER BY,
    so this stays correct if it is ever handed rows in another order.

    Memory is one small entry per person per day, not per punch: a month for
    200 people is ~6,000 entries regardless of how many times they punched.
    """
    groups = {}
    for row in rows:
        when = _wall_clock(row)
        if when is None:
            continue

        key = (when.date(), row.user_id)
        zone = _zone_of(row, device_zones)
        entry = groups.get(key)

        if entry is None:
            groups[key] = {
                "first": when, "first_sn": row.device_sn,
                "last": when, "last_sn": row.device_sn,
                "punches": 1, "zones": {zone},
            }
            continue

        entry["punches"] += 1
        entry["zones"].add(zone)
        if when < entry["first"]:
            entry["first"], entry["first_sn"] = when, row.device_sn
        if when > entry["last"]:
            entry["last"], entry["last_sn"] = when, row.device_sn

    return groups


def _build_daily_workbook(db, rows) -> BytesIO:
    """One row per person per day: first punch in, last punch out."""
    from openpyxl import Workbook

    wb = Workbook(write_only=True)
    ws = _start_sheet(wb, "Daily Attendance", _DAILY_COLUMNS)

    employee_names, device_zones, device_names = _lookups(db)
    groups = _daily_groups(rows, device_zones)

    def sort_key(item):
        (day, user_id), _ = item
        return (day, (employee_names.get(user_id) or user_id).lower(), user_id)

    count = 0
    for (day, user_id), entry in sorted(groups.items(), key=sort_key):
        single = entry["punches"] == 1

        # One punch in a day is not a worked day, it is half a record: the
        # person forgot to punch out, or the terminal missed it. Check Out and
        # Hours are left empty rather than filled with the check-in time,
        # which would read as a zero-hour day that somebody actually worked.
        check_out = None if single else _formatted(ws, entry["last"].time(), _TIME_FORMAT)
        hours = None
        if not single:
            span = (entry["last"] - entry["first"]).total_seconds() / 3600
            hours = _formatted(ws, round(span, 2), _HOURS_FORMAT)

        ws.append([
            _formatted(ws, day, _DATE_FORMAT),
            user_id,
            employee_names.get(user_id) or user_id,
            _formatted(ws, entry["first"].time(), _TIME_FORMAT),
            check_out,
            hours,
            entry["punches"],
            device_names.get(entry["first_sn"], entry["first_sn"]),
            None if single else device_names.get(entry["last_sn"], entry["last_sn"]),
            # Normally one zone. Two only when somebody punched on terminals in
            # different zones on the same day, and then both are named rather
            # than one being picked — the two times on that row do not share a
            # meaning, and the sheet must say so instead of hiding it.
            " / ".join(sorted(entry["zones"])),
        ])
        count += 1

    _finish_sheet(ws, _DAILY_COLUMNS, count)

    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    return buffer


@router.get("/export.xlsx")
def export_attendance(
    request: Request,
    mode: Literal["daily", "raw"] = Query("daily"),
    device_sn: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Everything matching the current filter, as one .xlsx workbook.

    ``mode=daily`` (the default) is the timesheet: one row per person per day,
    first punch in and last punch out. ``mode=raw`` is every punch.

    Audited: this hands a copy of the attendance history to whoever asked for
    it, which is exactly the kind of action the trail exists for.
    """
    q = _build_query(db, device_sn, user_id, from_date, to_date)

    total = q.count()
    if total > config.ATTENDANCE_EXPORT_MAX_ROWS:
        # The ceiling is on punches *read*, not rows written, in both modes: a
        # daily sheet is small, but it is still built by walking every punch
        # behind it. Refused up front, with the numbers, rather than
        # half-building a workbook the server cannot hold.
        raise HTTPException(
            status_code=400,
            detail=(
                f"{total:,} records match this filter, and an export is limited "
                f"to {config.ATTENDANCE_EXPORT_MAX_ROWS:,}. Narrow the date "
                "range (one month at a time) and export again."
            ),
        )

    # Ascending, the order a timesheet is read in — the opposite of the table
    # on screen, which shows the newest punch first. `id` breaks ties so two
    # punches on the same second do not come out in an arbitrary order.
    rows = (
        q.order_by(AttendanceLog.timestamp.asc(), AttendanceLog.id.asc())
        .yield_per(_EXPORT_BATCH)
    )

    build = _build_daily_workbook if mode == "daily" else _build_raw_workbook
    payload = build(db, rows).getvalue()
    filename = _export_filename(mode, device_sn, user_id, from_date, to_date)

    audit.record(
        db, user.username, "attendance_export",
        target=filename,
        ip=client_ip(request),
        detail=(
            f"mode={mode}; rows={total}; device={device_sn or 'all'}; "
            f"employee={user_id or 'all'}; "
            f"from={from_date.isoformat() if from_date else 'any'}; "
            f"to={to_date.isoformat() if to_date else 'any'}"
        ),
    )

    return Response(
        content=payload,
        media_type=_XLSX_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
