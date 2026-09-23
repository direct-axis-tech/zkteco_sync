from datetime import datetime, timedelta
from io import BytesIO
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app.deps import require_auth

from app import audit, config
from app.database import get_db
from app.models import AttendanceLog, Device, DeviceEmployee, Employee, User
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
# The monthly "send this to payroll" file: the timesheet, reproducing the
# report ZKTime.Net used to produce column for column. A row for every person
# on every day of the range, with hours worked, hours owed, lateness, early
# departures and absences scored against the shift in app/config.py. HR
# reconciles it against payroll and against older files from the terminal's
# own software, so its fourteen Vietnamese columns are a contract and not a
# preference.
#
# One shape, deliberately. A second "every punch, one per row" workbook was
# built and then removed: it made the operator choose between two files on
# every export, and the punches behind any row of the timesheet are already on
# the screen it is exported from.
#
# Why the day is paired by first/last punch rather than by the device's own
# status field: on this installation 96,002 of 96,075 records carry status=1,
# because nobody presses the mode key on the terminal. Selecting rows by
# status would return a sheet of check-outs with no check-ins at all. The
# clock is the only trustworthy signal, so it is the one used.
#
# The sheet covers the whole result of the filter, never the page on screen:
# an operator who picks a month and 900 punches match must get the whole
# month, not the 50 rows the table happens to be showing.

# The monthly report, column for column as ZKTime.Net wrote it — Vietnamese
# headers, trailing spaces and all. HR reconciles this sheet against payroll
# and against older files from the terminal's own software, so the layout is
# a contract, not a preference: same fourteen columns, same order, same
# wording. The widths are ours (ZKTime.Net left every column at the default,
# which clips the names).
_REPORT_COLUMNS = [
    ("ID nhân viên ", 12),      # employee PIN, as text — "007" is not 7
    ("Họ và tên", 26),
    ("Ngày", 11),               # dd/mm/yyyy
    ("Bảng thời gian", 14),     # timetable name; blank on a rest day
    ("Actual Work", 11),        # hours actually worked, less the break
    ("Require Work", 12),       # the paid length of the shift
    ("Tăng ca loại 1 ", 13),    # overtime tiers 1-3 — see _score_day
    ("Tăng ca loại 2 ", 13),
    ("Tăng ca loại 3 ", 13),
    ("Vô trễ", 9),              # late in
    ("Ra sớm", 9),              # early out
    ("Vắng mặt ", 10),          # absent
    ("Check-In", 10),
    ("Check-Out", 10),
]

# Every cell in the report is text (`@`), including the durations. They are
# H:MM counts of elapsed time, not clock times: written as real values, Excel
# would render 8:14 worked as 08:14 in the morning, and 25 hours of overtime
# would wrap round to 1:00. ZKTime.Net wrote text for the same reason.
_TEXT_FORMAT = "@"
_REPORT_DATE_FORMAT = "%d/%m/%Y"
_REPORT_CLOCK_FORMAT = "%H:%M"

_XLSX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

# Rows are streamed from the database in batches rather than materialised as
# one list — a year-sized export is hundreds of thousands of ORM objects.
_EXPORT_BATCH = 2000


def _export_filename(device_sn, user_id, from_date, to_date) -> str:
    """An ASCII-only, filesystem-safe name that says what is inside.

    Deliberately not derived from the device or employee *name*: those are
    free text and may be non-ASCII, and a Content-Disposition filename that
    needs RFC 5987 encoding is one more thing to get wrong in a browser. The
    serial and the PIN are already safe identifiers, and the file's own
    columns carry the readable names.
    """
    parts = ["attendance-timesheet"]
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


# ---------------------------------------------------------------------------
# Scoring a day against the shift
# ---------------------------------------------------------------------------
# Every number in the report is a pair of punches measured against the shift
# configured in app/config.py. The rules below were not invented: they are the
# ones the operator's own ZKTime.Net export was scored by, recovered by
# reading that file (August 2026, 21 people, 651 rows) and checking each
# formula against every row in it whose value was not zero.


def _clock(value) -> int:
    """A time of day as minutes since midnight."""
    return value.hour * 60 + value.minute


def _overlap(start: int, end: int, window_start: int, window_end: int) -> int:
    """Minutes the span [start, end] spends inside [window_start, window_end]."""
    return max(0, min(end, window_end) - max(start, window_start))


def _paid(start: int, end: int) -> int:
    """Minutes between two points of the day that count as work.

    The break is unpaid, so whatever part of it falls inside the span does not
    count. This is what makes leaving at 12:01 count as 4:30 early rather than
    5:29: the hour that would have gone on lunch was never theirs to work.
    """
    if end <= start:
        return 0
    break_start = _clock(config.WORK_BREAK_START)
    break_end = _clock(config.WORK_BREAK_END)
    return end - start - _overlap(start, end, break_start, break_end)


def _hm(minutes) -> str:
    """Minutes → the report's H:MM, e.g. 0 → "0:00", 494 → "8:14".

    Hours are not zero-padded and not capped at 24: this is a duration, not a
    time of day.
    """
    minutes = max(0, int(minutes))
    return f"{minutes // 60}:{minutes % 60:02d}"


def _score_day(first, last, punches: int, is_work_day: bool) -> dict:
    """The numbers for one person on one day.

    ``first``/``last`` are that day's earliest and latest punch as the
    device's own clock recorded them, or None if the person never punched.

    A day with a single punch is not a short day, it is half a record — the
    person forgot to punch out, or the terminal missed it. ZKTime.Net scored
    those as a whole day absent, with no hours and no lateness, and so does
    this: inventing a check-out would put hours nobody worked onto a payroll
    sheet, and charging lateness for a day already counted absent would take
    the same hour off twice.
    """
    shift_start = _clock(config.WORK_SHIFT_START)
    shift_end = _clock(config.WORK_SHIFT_END)
    break_start = _clock(config.WORK_BREAK_START)
    break_end = _clock(config.WORK_BREAK_END)

    required = _paid(shift_start, shift_end) if is_work_day else 0

    came = _clock(first) if first is not None else None
    went = _clock(last) if last is not None else None

    # Two punches in the same minute are the same broken record as one:
    # somebody touched the terminal twice on their way in. There is no span
    # there to pay, so the day is scored as the absence it is rather than as
    # a worked day of no hours.
    paired = punches >= 2 and came is not None and went is not None and went > came

    if not paired:
        return {
            "paired": False,
            "actual": 0,
            "required": required,
            "late": 0,
            "early": 0,
            "absent": required,
        }

    # Hours worked are the span between the two punches, less the break — and
    # the break only comes off somebody who was here for the whole of it.
    # Leave at 12:01 and the 3:41 already worked stands whole; arrive at 12:04
    # and nothing is deducted either, because the lunch hour was already gone
    # by the time they got here. Counted from the punches themselves, not from
    # the shift: arriving at 08:03 for an 08:30 shift earns those 27 minutes,
    # exactly as the ZKTime.Net sheet paid them.
    #
    # Lateness and early departure below take the opposite view of a part-used
    # break, subtracting whatever slice of it falls in the missing time — so a
    # 12:04 arrival is 3:30 late, not 3:34. Both halves are ZKTime.Net's, read
    # off its own numbers; they are asymmetric because it never pays an hour
    # that was not worked, and never charges one that was not owed.
    actual = went - came
    if came <= break_start and went >= break_end:
        actual -= break_end - break_start

    return {
        "paired": True,
        "actual": actual,
        "required": required,
        "late": _paid(shift_start, came) if is_work_day else 0,
        "early": _paid(went, shift_end) if is_work_day else 0,
        "absent": 0,
    }


# ---------------------------------------------------------------------------
# Who, and which days
# ---------------------------------------------------------------------------
# A timesheet is a grid, not a list of punches: a row for every person on
# every day of the month, whether or not they came in. Somebody who was absent
# all month has no punches at all, and they are exactly who the "Vắng mặt"
# column exists for. So the rows come from the roster and the calendar, and
# the punches are laid on top of them.


def _report_days(db, query, from_date, to_date) -> list:
    """Every calendar day the report has rows for.

    The filter's own dates when it has them. Without them the range comes from
    the punches themselves, so an unfiltered export still produces a bounded
    sheet instead of a grid over all of time.
    """
    from sqlalchemy import func

    start = from_date.date() if from_date else None
    end = to_date.date() if to_date else None

    if start is None or end is None:
        earliest, latest = query.with_entities(
            func.min(AttendanceLog.timestamp), func.max(AttendanceLog.timestamp)
        ).one()
        if start is None and earliest is not None:
            start = earliest.date()
        if end is None and latest is not None:
            end = latest.date()

    if start is None or end is None or end < start:
        return []

    return [start + timedelta(days=n) for n in range((end - start).days + 1)]


def _roster_key(user_id: str):
    """PINs sort as numbers when they are numbers: 2, then 13, then 211."""
    return (0, int(user_id), "") if user_id.isdigit() else (1, 0, user_id)


def _report_people(db, device_sn, user_id, employee_names, seen_user_ids) -> list:
    """``[(pin, name)]`` the report has rows for, in PIN order.

    One person when the filter names one. Otherwise the whole roster, narrowed
    to a device's enrolled users when the filter names a device — but never
    narrowed past somebody who actually punched: anyone present in the
    selected records gets rows whether or not the roster knows their name.
    """
    if user_id:
        ids = {user_id}
    else:
        ids = set(employee_names)
        if device_sn:
            enrolled = {
                row[0]
                for row in db.query(DeviceEmployee.user_id)
                .filter(DeviceEmployee.device_sn == device_sn)
                .all()
            }
            # An empty enrolment table means this device's users have never
            # been synced, not that nobody is enrolled on it. Narrowing by it
            # then would hand back an empty sheet.
            if enrolled:
                ids &= enrolled
        ids |= set(seen_user_ids)

    return sorted(
        ((pin, employee_names.get(pin) or pin) for pin in ids),
        key=lambda person: _roster_key(person[0]),
    )


def _start_report_sheet(wb, title, columns):
    """The header row, styled as ZKTime.Net styled it: Tahoma 8 on grey,
    centred, thin-bordered, and text-formatted like everything below it."""
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Alignment, PatternFill
    from openpyxl.utils import get_column_letter

    ws = wb.create_sheet(title=title)

    # Before the first append, not after: in write-only mode the view settings
    # are serialised as soon as a row is written, so a freeze set at the end
    # is silently dropped and HR scrolls a month with no header in sight.
    ws.freeze_panes = "A2"

    for index, (_, width) in enumerate(columns, start=1):
        ws.column_dimensions[get_column_letter(index)].width = width

    font, border, _ = _report_body_style()
    fill = PatternFill("solid", fgColor="FFD3D3D3")
    align = Alignment(horizontal="center", vertical="center")

    header = []
    for text, _ in columns:
        cell = WriteOnlyCell(ws, value=text)
        cell.font, cell.border, cell.alignment = font, border, align
        cell.fill = fill
        cell.number_format = _TEXT_FORMAT
        header.append(cell)
    ws.append(header)
    return ws


def _report_body_style():
    """One font, one border, one alignment, shared by every data cell.

    Built once and reused: openpyxl folds identical style objects into a
    single entry in the workbook's style table, so a month for 200 people
    costs one style instead of ninety thousand.
    """
    from openpyxl.styles import Alignment, Border, Font, Side

    thin = Side(style="thin", color="FF000000")
    return (
        Font(name="Tahoma", size=8),
        Border(left=thin, right=thin, top=thin, bottom=thin),
        Alignment(horizontal="left", vertical="center"),
    )


def _report_row(ws, style, values) -> list:
    """One row of styled text cells. A None stays empty — and still gets its
    border, so a blank rest day does not tear a hole in the grid."""
    from openpyxl.cell import WriteOnlyCell

    font, border, align = style
    row = []
    for value in values:
        cell = WriteOnlyCell(ws, value=value)
        cell.font, cell.border, cell.alignment = font, border, align
        cell.number_format = _TEXT_FORMAT
        row.append(cell)
    return row


def _build_report_workbook(db, rows, days, people) -> BytesIO:
    """The monthly timesheet: one row per person per day, scored."""
    from openpyxl import Workbook

    wb = Workbook(write_only=True)
    ws = _start_report_sheet(wb, "Attendance report", _REPORT_COLUMNS)

    # Only the zones: the report has no timezone column — it is one site's
    # timesheet, in the site's own hours — but _daily_groups resolves them
    # anyway, and handing it an empty map would make it label every punch
    # with the configured default instead of the device's own.
    device_zones = dict(db.query(Device.serial_number, Device.timezone).all())
    groups = _daily_groups(rows, device_zones)
    style = _report_body_style()

    for pin, name in people:
        for day in days:
            is_work_day = day.isoweekday() in config.WORK_DAYS
            entry = groups.get((day, pin))
            first = entry["first"] if entry else None
            last = entry["last"] if entry else None
            scored = _score_day(
                first, last, entry["punches"] if entry else 0, is_work_day
            )

            ws.append(_report_row(ws, style, [
                pin,
                name,
                day.strftime(_REPORT_DATE_FORMAT),
                config.WORK_TIMETABLE_NAME if is_work_day else None,
                _hm(scored["actual"]),
                _hm(scored["required"]),
                # Overtime, three tiers. ZKTime.Net scored this install's
                # August export as 0:00 in all three on every one of its 651
                # rows, including days that ran past the end of the shift — so
                # no overtime rule can be read out of it. Rather than invent
                # one and put unapproved hours onto a payroll sheet, the
                # columns are kept (the layout is a contract) and left at
                # zero until there is a rule to apply.
                _hm(0),
                _hm(0),
                _hm(0),
                _hm(scored["late"]),
                _hm(scored["early"]),
                _hm(scored["absent"]),
                first.strftime(_REPORT_CLOCK_FORMAT) if first else None,
                last.strftime(_REPORT_CLOCK_FORMAT) if scored["paired"] else None,
            ]))

    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    return buffer


@router.get("/export.xlsx")
def export_attendance(
    request: Request,
    device_sn: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """The timesheet for everything matching the current filter, as one
    .xlsx workbook: a row for every person on every day of the range, in
    ZKTime.Net's own layout, scored against the configured shift.

    Audited: this hands a copy of the attendance history to whoever asked for
    it, which is exactly the kind of action the trail exists for.
    """
    q = _build_query(db, device_sn, user_id, from_date, to_date)

    total = q.count()
    if total > config.ATTENDANCE_EXPORT_MAX_ROWS:
        # The ceiling is on punches *read*, not rows written: the sheet
        # itself is small, but it is built by walking every punch behind it.
        # Refused up front, with the numbers, rather than half-building a
        # workbook the server cannot hold.
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

    days = _report_days(db, q, from_date, to_date)
    # Who punched, straight from the database rather than from the rows:
    # the roster is what the sheet is built from, and somebody who is not
    # on it but is in the records must still get their rows.
    seen = {
        row[0]
        for row in q.with_entities(AttendanceLog.user_id).distinct().all()
    }
    people = _report_people(
        db, device_sn, user_id,
        dict(db.query(Employee.user_id, Employee.name).all()),
        seen,
    )

    # The second ceiling, and the one the timesheet actually runs into: it
    # has a row per person per day whether or not anybody punched, so a
    # year for a large roster is a big sheet built from very few records.
    # Same answer as above — say the numbers, name the fix, build nothing.
    grid = len(people) * len(days)
    if grid > config.ATTENDANCE_EXPORT_MAX_ROWS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"That range is {len(days):,} days for {len(people):,} "
                f"people, which is {grid:,} timesheet rows, and an export "
                f"is limited to {config.ATTENDANCE_EXPORT_MAX_ROWS:,}. "
                "Narrow the date range (one month at a time), or pick a "
                "single employee, and export again."
            ),
        )

    payload = _build_report_workbook(db, rows, days, people).getvalue()
    filename = _export_filename(device_sn, user_id, from_date, to_date)

    audit.record(
        db, user.username, "attendance_export",
        target=filename,
        ip=client_ip(request),
        detail=(
            f"rows={total}; device={device_sn or 'all'}; "
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
