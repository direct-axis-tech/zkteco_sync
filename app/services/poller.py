import json
import logging
import threading
import time
from datetime import datetime, timezone
from zk import ZK
from zk.exception import ZKErrorConnection, ZKErrorResponse, ZKNetworkError

from app import config
from app.database import SessionLocal
from app.models import AttendanceLog, Device, FingerprintTemplate
from app.services import employee_sync

log = logging.getLogger(__name__)


def _connect(device):
    zk = ZK(device.ip_address, port=device.port, timeout=30, password=device.comm_key or 0, verbose=False)
    try:
        return zk.connect()
    except ZKErrorResponse as exc:
        # See app/services/sdk.py:_connect for why this message match is the
        # only reliable way pyzk signals a rejected comm key.
        if str(exc) == "Unauthenticated":
            raise ZKErrorResponse("Device refused the connection — the configured comm key is likely wrong")
        raise


# One re-entrant lock per serial. A ZKTeco terminal serves ONE SDK session at
# a time; a second CONNECT while a pull is reading 96k punches does not queue,
# it times out, and in the field it has been seen to leave the terminal's SDK
# thread wedged for ~8 minutes afterwards. So two pulls on one device never
# overlap: the second is refused at once (see `is_pulling`, which the router
# turns into a 409), and Sync All holds the lock across all three reads so
# nothing slips in between them. Re-entrant so pull_device can nest the
# per-kind pulls; process-local, which is the whole scope of a background
# task under one uvicorn worker.
_device_locks: dict = {}
_device_locks_guard = threading.Lock()


def _lock_for(serial_number: str) -> threading.RLock:
    with _device_locks_guard:
        lock = _device_locks.get(serial_number)
        if lock is None:
            lock = _device_locks[serial_number] = threading.RLock()
        return lock


def is_pulling(serial_number: str) -> bool:
    """True while a pull of any kind holds this device's SDK session."""
    lock = _lock_for(serial_number)
    if lock.acquire(blocking=False):
        lock.release()
        return False
    return True


BUSY_DETAIL = "Another sync is already running on this device — wait for it to finish"

# The pulls below deliberately do NOT call conn.disable_device(). They only
# read, and disabling locks the terminal's keypad and sensor for the whole
# read — minutes, on a device holding a year of punches. Worse, the matching
# enable_device() lives in a `finally`, and a background task that is killed
# mid-read (a dev-server reload, a deploy, an OOM) never reaches it: the
# terminal stays locked until somebody notices. A punch made during a read is
# simply picked up on the next one; the dedup in pull_attendance makes that
# safe. Locking the terminal to read from it was the wrong trade.


def record_pull_outcome(db, device, kind: str, ok: bool, detail: str,
                        seconds: float = None) -> None:
    """Write what a pull of ``kind`` just did onto ``Device.pull_outcomes``.

    Every pull here runs as a FastAPI background task, after the HTTP
    response has already told the operator "started". Its return value is
    dropped on the floor, so without this the only record of "timed out" or
    "comm key refused" is a line in the server log — and the Devices page
    shows a sync that silently never happened. This is the one place the
    outcome is kept, and the UI reads it back from DeviceOut.pull_outcomes.

    Never raises: a failure to record the outcome must not turn a pull that
    worked into one that looks like it crashed.
    """
    try:
        try:
            outcomes = json.loads(device.pull_outcomes) if device.pull_outcomes else {}
        except ValueError:
            outcomes = {}
        if not isinstance(outcomes, dict):
            outcomes = {}
        outcomes[kind] = {
            "at": datetime.now(timezone.utc).isoformat(),
            "ok": bool(ok),
            # A traceback-sized message is a log line's job, not a table cell's.
            "detail": (detail or "")[:500],
            # How long the device was held. The number an operator needs when
            # deciding whether a year of backlog should be cleared off it.
            "seconds": round(seconds, 1) if seconds is not None else None,
        }
        device.pull_outcomes = json.dumps(outcomes)
        db.commit()
    except Exception:
        log.exception("record_pull_outcome: could not store %s outcome for %s",
                      kind, device.serial_number)
        db.rollback()


def _connection_error_detail(device, exc) -> str:
    """pyzk's network errors are terse ("timed out"); say what was dialled."""
    return f"Could not connect to {device.ip_address}:{device.port} — {exc}"


def pull_employees(serial_number: str) -> dict:
    log.info("pull_employees: starting for device %s", serial_number)
    result = {"users_synced": 0, "errors": []}
    lock = _lock_for(serial_number)
    if not lock.acquire(blocking=False):
        log.warning("pull_employees: %s is busy with another pull — refused", serial_number)
        result["errors"].append(BUSY_DETAIL)
        return result
    started = time.monotonic()
    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            log.warning("pull_employees: device %s not found in DB", serial_number)
            result["errors"].append("Device not found")
            return result

        conn = None
        try:
            log.info("pull_employees: connecting to %s (%s:%s)",
                     serial_number, device.ip_address, device.port)
            conn = _connect(device)

            for user in conn.get_users():
                # Deliberately the same writer the ADMS `tabledata&tablename=user`
                # upload uses (app/services/employee_sync.py). A device on the
                # LAN can be reachable over both TCP 4370 and the PUSH channel,
                # and two writers with different ideas of what an empty field
                # means would make the row flip-flop between them. The visible
                # change from the previous inline version: pyzk reports an
                # unnamed user as "" and a card-less user as 0, and neither now
                # overwrites a name or card that is already on the row.
                employee_sync.record_device_user(
                    db,
                    serial_number,
                    user.user_id,
                    uid=user.uid,
                    name=user.name,
                    privilege=user.privilege,
                    card=user.card,
                )
                result["users_synced"] += 1

            db.commit()
            device.last_seen = datetime.now(timezone.utc)
            device.is_online = True
            db.commit()
            log.info("pull_employees: done for %s — %d users synced",
                     serial_number, result["users_synced"])

        except (ZKErrorConnection, ZKNetworkError) as e:
            log.error("pull_employees: connection error for %s — %s", serial_number, e)
            result["errors"].append(_connection_error_detail(device, e))
            device.is_online = False
            db.commit()
        except ZKErrorResponse as e:
            log.error("pull_employees: device %s refused authentication — %s", serial_number, e)
            result["errors"].append(str(e))
            db.rollback()
        except Exception as e:
            log.exception("pull_employees: unexpected error for %s", serial_number)
            result["errors"].append(str(e))
            db.rollback()
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass

        record_pull_outcome(
            db, device, "employees", not result["errors"],
            result["errors"][0] if result["errors"]
            else f"{result['users_synced']} users read from the device",
            seconds=time.monotonic() - started,
        )
    finally:
        db.close()
        lock.release()

    return result


def pull_attendance(serial_number: str) -> dict:
    log.info("pull_attendance: starting for device %s", serial_number)
    result = {"attendance_synced": 0, "errors": []}
    lock = _lock_for(serial_number)
    if not lock.acquire(blocking=False):
        log.warning("pull_attendance: %s is busy with another pull — refused", serial_number)
        result["errors"].append(BUSY_DETAIL)
        return result
    started = time.monotonic()
    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            log.warning("pull_attendance: device %s not found in DB", serial_number)
            result["errors"].append("Device not found")
            return result

        conn = None
        records_read = 0
        try:
            log.info("pull_attendance: connecting to %s (%s:%s)",
                     serial_number, device.ip_address, device.port)
            conn = _connect(device)

            records = conn.get_attendance()
            records_read = len(records)
            log.info("pull_attendance: device %s returned %d records from device",
                     serial_number, records_read)

            # Load the keys already stored for this device in one query, rather
            # than a SELECT per record (20k+ round-trips otherwise).
            #
            # `.replace(tzinfo=None)` is load-bearing, not tidying. Every
            # DateTime column in app/models.py is `UTCDateTime` (models.py:6
            # imports it *as* DateTime), and its process_result_value stamps
            # tzinfo=UTC onto every value read back. pyzk hands back the
            # device's naive wall-clock. An aware datetime never compares equal
            # to a naive one, so without this the set below matches nothing:
            # every record looks new on every pull, and the insert trips
            # uq_attendance on the first punch already stored. The first pull
            # into an empty table succeeds and every pull after it fails —
            # which is exactly how this was found, on PSS7235100187.
            #
            # Naive is the right side to normalise to: a punch IS a naive
            # device wall-clock (D10), labelled by the `timezone` column and
            # never converted. UTCDateTime's label is wrong for this column;
            # correcting that is a wider change than this dedup needs.
            existing = {
                (uid, ts.replace(tzinfo=None) if ts is not None and ts.tzinfo else ts)
                for uid, ts in db.query(
                    AttendanceLog.user_id, AttendanceLog.timestamp
                ).filter_by(device_sn=serial_number)
            }

            # Devices routinely report the same punch more than once in a single
            # pull, so dedupe within the batch too — the session has
            # autoflush=False, so the per-row check below can't see rows added
            # earlier in this loop, and a duplicate would trip uq_attendance and
            # roll back the entire pull.
            seen = set()
            new_rows = []
            for att in records:
                key = (str(att.user_id), att.timestamp)
                if key in existing or key in seen:
                    continue
                seen.add(key)
                new_rows.append(AttendanceLog(
                    device_sn=serial_number,
                    user_id=str(att.user_id),
                    timestamp=att.timestamp,
                    status=att.status,
                    punch=att.punch,
                    source="sdk_pull",
                    # pyzk hands back the device's own naive wall-clock, same
                    # as a PUSH record. Stored as-is and labelled, never
                    # converted (D10).
                    timezone=device.timezone or config.DEFAULT_DEVICE_TIMEZONE,
                ))

            db.bulk_save_objects(new_rows)
            result["attendance_synced"] = len(new_rows)

            db.commit()
            device.last_seen = datetime.now(timezone.utc)
            device.is_online = True
            db.commit()
            log.info("pull_attendance: done for %s — %d new records inserted",
                     serial_number, result["attendance_synced"])

        except (ZKErrorConnection, ZKNetworkError) as e:
            log.error("pull_attendance: connection error for %s — %s", serial_number, e)
            result["errors"].append(_connection_error_detail(device, e))
            device.is_online = False
            db.commit()
        except ZKErrorResponse as e:
            log.error("pull_attendance: device %s refused authentication — %s", serial_number, e)
            result["errors"].append(str(e))
            db.rollback()
        except Exception as e:
            log.exception("pull_attendance: unexpected error for %s", serial_number)
            result["errors"].append(str(e))
            db.rollback()
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass

        record_pull_outcome(
            db, device, "attendance", not result["errors"],
            result["errors"][0] if result["errors"]
            else f"{result['attendance_synced']} new punches stored "
                 f"({records_read} read from the device)",
            seconds=time.monotonic() - started,
        )
    finally:
        db.close()
        lock.release()

    return result


def store_templates(db, serial_number: str, conn) -> list:
    """Read every fingerprint the device holds and upsert it into
    ``fingerprint_templates``. Returns the rows written, in device order.

    The one writer for the SDK-era fingerprint table: the manual
    "Sync Templates" route and the Sync All pull both come through here, so
    a template read by either lands in the same row with the same key
    (``user_id``, ``finger_id``). A finger whose device ``uid`` does not map
    to a known ``user_id`` is skipped — there is no employee to attach it to.

    Does not commit; the caller owns the transaction.
    """
    uid_map = {u.uid: u.user_id for u in conn.get_users()}
    result = []
    for finger in conn.get_templates():
        user_id = uid_map.get(finger.uid)
        if not user_id:
            continue
        packed = finger.json_pack()
        ft = db.query(FingerprintTemplate).filter_by(
            user_id=user_id, finger_id=finger.fid
        ).first()
        if ft:
            ft.valid = finger.valid
            ft.template = packed["template"]
            ft.source_device_sn = serial_number
        else:
            ft = FingerprintTemplate(
                user_id=user_id,
                finger_id=finger.fid,
                valid=finger.valid,
                template=packed["template"],
                source_device_sn=serial_number,
            )
            db.add(ft)
        result.append(ft)
    return result


def pull_templates(serial_number: str) -> dict:
    log.info("pull_templates: starting for device %s", serial_number)
    result = {"templates_synced": 0, "errors": []}
    lock = _lock_for(serial_number)
    if not lock.acquire(blocking=False):
        log.warning("pull_templates: %s is busy with another pull — refused", serial_number)
        result["errors"].append(BUSY_DETAIL)
        return result
    started = time.monotonic()
    db = SessionLocal()
    try:
        device = db.query(Device).filter_by(serial_number=serial_number).first()
        if not device:
            log.warning("pull_templates: device %s not found in DB", serial_number)
            result["errors"].append("Device not found")
            return result

        conn = None
        try:
            log.info("pull_templates: connecting to %s (%s:%s)",
                     serial_number, device.ip_address, device.port)
            conn = _connect(device)

            rows = store_templates(db, serial_number, conn)
            result["templates_synced"] = len(rows)

            db.commit()
            device.last_seen = datetime.now(timezone.utc)
            device.is_online = True
            db.commit()
            log.info("pull_templates: done for %s — %d templates synced",
                     serial_number, result["templates_synced"])

        except (ZKErrorConnection, ZKNetworkError) as e:
            log.error("pull_templates: connection error for %s — %s", serial_number, e)
            result["errors"].append(_connection_error_detail(device, e))
            device.is_online = False
            db.commit()
        except ZKErrorResponse as e:
            log.error("pull_templates: device %s refused authentication — %s", serial_number, e)
            result["errors"].append(str(e))
            db.rollback()
        except Exception as e:
            log.exception("pull_templates: unexpected error for %s", serial_number)
            result["errors"].append(str(e))
            db.rollback()
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass

        record_pull_outcome(
            db, device, "templates", not result["errors"],
            result["errors"][0] if result["errors"]
            else f"{result['templates_synced']} templates read from the device",
            seconds=time.monotonic() - started,
        )
    finally:
        db.close()
        lock.release()

    return result


def pull_device(serial_number: str) -> dict:
    """Sync everything: employees + attendance + fingerprint templates.
    Used by Sync All and auto-registration.

    Templates are pulled last and after employees on purpose: a template
    keys on the ``user_id`` the employee pull just wrote, and a finger for a
    person the server has not heard of yet would be dropped.
    """
    lock = _lock_for(serial_number)
    if not lock.acquire(blocking=False):
        log.warning("pull_device: %s is busy with another pull — refused", serial_number)
        return {"users_synced": 0, "attendance_synced": 0, "templates_synced": 0,
                "errors": [BUSY_DETAIL]}
    try:
        emp_result  = pull_employees(serial_number)
        att_result  = pull_attendance(serial_number)
        tpl_result  = pull_templates(serial_number)
    finally:
        lock.release()
    return {
        "users_synced":      emp_result["users_synced"],
        "attendance_synced": att_result["attendance_synced"],
        "templates_synced":  tpl_result["templates_synced"],
        "errors":            emp_result["errors"] + att_result["errors"] + tpl_result["errors"],
    }
