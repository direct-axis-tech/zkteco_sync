import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import Drawer from './Drawer'
import RevocationCard from './RevocationCard'

const PRESETS = [
  { label: 'Reboot', value: 'REBOOT' },
  { label: 'Sync Time', value: 'DATE' },
  { label: 'Enable', value: 'ENABLE' },
  { label: 'Disable', value: 'DISABLE' },
]

// The two commands E8 sends to revoke one person (`DATA DELETE user` and
// `DATA DELETE userauthorize`) — the exact shape `GET /devices/{sn}/revocations`
// groups server-side (E13), and the two this section pulls out of the plain
// outbox list so they get the grouped, loud treatment instead of sitting in
// "Outstanding" as two unrelated rows. Narrower than "any DATA DELETE" on
// purpose: a hand-typed delete for some other table is a real command this
// drawer has never seen before and should stay visible in "Outstanding"
// rather than silently vanish because it happened to start the same way.
const isGroupedRevocation = (command) =>
  /^DATA DELETE (user|userauthorize)\s+Pin=/i.test(String(command || '').trim())

// For the History Pill and the retry-warning copy below, where "was this a
// revocation" only needs to be roughly right, not grouped.
const isRevocation = (command) => /^DATA DELETE\b/i.test(String(command || '').trim())

// How long ago (past) or how long until (future) a timestamp is, in words an
// operator can act on without doing the arithmetic themselves.
function relativeTime(iso) {
  if (!iso) return null
  // Timestamps come back naive-UTC from the API; anchor them before diffing,
  // or a UTC+4 browser reads a fresh command as hours old (or not-yet-due).
  const stamp = /(Z|[+-]\d\d:?\d\d)$/.test(iso) ? iso : `${iso}Z`
  return Date.now() - new Date(stamp).getTime() // positive = past, negative = future
}

function formatDuration(ms) {
  const seconds = Math.max(0, Math.floor(Math.abs(ms) / 1000))
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

const since = (iso) => {
  const d = relativeTime(iso)
  return d == null ? '' : `${formatDuration(d)} ago`
}

const until = (iso) => {
  const d = relativeTime(iso)
  if (d == null) return ''
  return d > 0 ? 'due now' : `in ${formatDuration(d)}`
}

const PILL_TONES = {
  gray: 'bg-gray-100 text-gray-600',
  blue: 'bg-blue-50 text-blue-700',
  green: 'bg-green-50 text-green-700',
  amber: 'bg-amber-100 text-amber-800',
  red: 'bg-red-100 text-red-700',
}

function Pill({ tone = 'gray', children }) {
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full text-[11px] font-semibold whitespace-nowrap ${PILL_TONES[tone]}`}>
      {children}
    </span>
  )
}

// What a row in device_command_log actually means. `outcome=failed` covers
// three different stories that must not be run together: the device
// understood the command and refused it (return_code set), the operator
// called it off (last_error says so), or nobody ever heard back at all
// (return_code null, no cancellation). Read off the row, never inferred from
// the outbox being empty — an empty outbox means "concluded", not "succeeded"
// (E8's browser gate caught exactly that confusion).
// How a concluded command is labelled. The judgement itself is the server's
// (`row.verdict`, from commands.history_verdict) so that this panel cannot call
// something a refusal that the server does not — the fallback below is only for
// a server too old to send one.
//
// `Unconfirmed` is not a softer word for refused. It means the device answered
// with a code this system cannot read, on firmware that has returned exactly
// such a code on commands that demonstrably WORKED. Saying "Refused — code 3"
// there would be a wrong verdict on a door command, which is the whole reason
// this distinction exists (E11).
function historyOutcome(row) {
  const verdict =
    row.verdict ||
    (row.outcome === 'acknowledged'
      ? 'acknowledged'
      : row.return_code != null
      ? row.return_code < 0
        ? 'refused'
        : 'unconfirmed'
      : (row.last_error || '').startsWith('cancelled by')
      ? 'cancelled'
      : 'abandoned')

  if (verdict === 'acknowledged') {
    // `verdict_detail` is the server's plain-language reading of the device's
    // number — for a DATA QUERY that is a record count, and "no records
    // matched" is a real answer to a real query, not an absence. Showing it is
    // the difference between an operator seeing that a query ran and returned
    // nothing, and them seeing a bare "Acknowledged" and assuming data arrived.
    return {
      label: row.verdict_detail
        ? `Acknowledged — ${row.verdict_detail}`
        : 'Acknowledged',
      tone: 'green',
    }
  }
  if (verdict === 'refused') {
    return { label: `Refused — code ${row.return_code}`, tone: 'red' }
  }
  if (verdict === 'unconfirmed') {
    return { label: `Unconfirmed — code ${row.return_code}`, tone: 'amber' }
  }
  if (verdict === 'cancelled') return { label: 'Cancelled', tone: 'gray' }
  return { label: 'Gave up — no reply', tone: 'amber' }
}

function Section({ title, hint, children }) {
  return (
    <div className="mb-5">
      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">{title}</h3>
      {hint && <p className="text-xs text-gray-400 mb-2">{hint}</p>}
      {children}
    </div>
  )
}

export default function CommandsDrawer({ device, onClose, showToast, onChange }) {
  const sn = device.serial_number

  const [command, setCommand] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState('')

  const [outbox, setOutbox] = useState([])
  const [history, setHistory] = useState([])
  const [revocationGroups, setRevocationGroups] = useState([])
  const [loadingLists, setLoadingLists] = useState(true)

  const [busy, setBusy] = useState({}) // { [key]: true } while an action is in flight
  const [confirmCancelId, setConfirmCancelId] = useState(null) // outbox id awaiting a second click
  const [confirmRetryId, setConfirmRetryId] = useState(null)   // log id awaiting a second click
  // Persistent until dismissed or replaced — a 3.5s toast is not enough time
  // to read the honest wording a cancel or retry can carry.
  const [notice, setNotice] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [ob, hs, rv] = await Promise.all([
        api.devices.listCommands(sn),
        api.devices.commandHistory(sn),
        api.devices.listRevocations(sn),
      ])
      setOutbox(ob)
      setHistory(hs)
      setRevocationGroups(rv)
    } catch {
      showToast('Failed to load the command queue', 'error')
    } finally {
      setLoadingLists(false)
    }
  }, [sn, showToast])

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sn])

  async function handleSend(e) {
    e.preventDefault()
    if (!command.trim()) return
    setError('')
    setSending(true)
    try {
      await api.devices.queueCommand(sn, command.trim())
      showToast('Command queued')
      setCommand('')
      refresh()
      onChange?.()
    } catch (err) {
      setError(err.message)
    } finally {
      setSending(false)
    }
  }

  async function doCancel(row) {
    setConfirmCancelId(null)
    setBusy((b) => ({ ...b, [`out-${row.id}`]: true }))
    try {
      const result = await api.devices.cancelCommand(sn, row.id)
      showToast(result.was_sent ? 'Cancelled — record only' : 'Cancelled before delivery')
      setNotice({ type: result.was_sent ? 'warning' : 'success', text: result.message })
      await refresh()
      onChange?.()
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setBusy((b) => { const n = { ...b }; delete n[`out-${row.id}`]; return n })
    }
  }

  function handleCancelClick(row) {
    // A `pending` command has never left this server — cancelling it is the
    // whole truth, so one click is enough. A `sent` command has already been
    // handed to the device at least once, so cancelling here only edits our
    // own bookkeeping; that needs a second, informed click before it happens,
    // not a toast explaining it after the fact.
    if (row.status === 'sent') {
      setConfirmCancelId(row.id)
      return
    }
    doCancel(row)
  }

  async function doRetry(row) {
    setConfirmRetryId(null)
    setBusy((b) => ({ ...b, [`log-${row.id}`]: true }))
    try {
      const result = await api.devices.retryCommand(sn, row.id)
      showToast('Requeued')
      setNotice({ type: result.was_device_refusal ? 'warning' : 'info', text: result.message })
      await refresh()
      onChange?.()
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setBusy((b) => { const n = { ...b }; delete n[`log-${row.id}`]; return n })
    }
  }

  function handleRetryClick(row) {
    // A device refusal is the device having understood the command and said
    // no. Nothing changed at the device in between, so retrying will very
    // likely earn the identical refusal — that deserves a second click, not
    // a silent requeue of the same rejected bytes.
    if (row.return_code != null) {
      setConfirmRetryId(row.id)
      return
    }
    doRetry(row)
  }

  const otherOutbox = outbox.filter((r) => !isGroupedRevocation(r.command))

  // RevocationCard owns the request and its own busy state — these only
  // react to the outcome. Calls E8's revocation-level DELETE, which cancels
  // BOTH `DATA DELETE` commands atomically — never the per-command cancel
  // above, which could leave one half of a revocation behind (E13).
  function handleRevocationCancelled(res) {
    setNotice({ type: 'success', text: res?.message || 'Revocation cancelled' })
    refresh()
    onChange?.()
  }

  function handleRevocationCancelError(err) {
    showToast(err.message, 'error')
  }

  return (
    <Drawer title="Commands" onClose={onClose} width="max-w-lg">
      {notice && (
        <div
          className={`mb-4 text-xs rounded-lg px-3 py-2 border flex items-start justify-between gap-2 ${
            notice.type === 'warning'
              ? 'border-amber-300 bg-amber-50 text-amber-800'
              : notice.type === 'success'
                ? 'border-green-200 bg-green-50 text-green-800'
                : 'border-blue-200 bg-blue-50 text-blue-800'
          }`}
        >
          <span>{notice.text}</span>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="opacity-60 hover:opacity-100 shrink-0"
          >
            ✕
          </button>
        </div>
      )}

      <Section title="Queue a command" hint="Delivered on the device's next heartbeat poll.">
        <div className="flex flex-wrap gap-2 mb-3">
          {PRESETS.map((p) => (
            <button
              key={p.value}
              type="button"
              onClick={() => setCommand(p.value)}
              className="text-xs border border-gray-300 text-gray-600 hover:bg-gray-50 px-3 py-1 rounded-full transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleSend} className="space-y-3">
          <input
            type="text"
            required
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            placeholder="REBOOT"
            className="input w-full font-mono text-sm"
          />

          {error && (
            <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={sending}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
          >
            {sending ? 'Queuing…' : 'Queue Command'}
          </button>
        </form>
      </Section>

      {/* Revocations pulled out and coloured as the hazard they are — an
          outstanding `DATA DELETE` means somebody may still be able to open
          this door, exactly the distinction E8 exists to keep visible.
          Grouped server-side (E13), one card per person rather than one per
          `DATA DELETE` command — the duplication that used to let an
          operator cancel half a revocation with one click. */}
      {revocationGroups.length > 0 && (
        <Section title="Revocations not yet confirmed at the door">
          <div className="border-2 border-red-300 bg-red-50 rounded-lg p-3 space-y-2">
            <p className="text-xs font-semibold text-red-800">
              The person named below can still open this door until the device
              confirms it collected this. If the device is offline it waits.
            </p>
            {revocationGroups.map((group) => (
              <RevocationCard
                key={`${group.device_sn}:${group.user_id}`}
                group={group}
                title={`Pin ${group.user_id}`}
                cancelLabel={
                  group.still_open
                    ? `Cancel — Pin ${group.user_id} keeps access to this door`
                    : group.user?.outstanding || group.userauthorize?.outstanding
                      ? 'Cancel the leftover delete — door permission record only'
                      : null
                }
                onCancelled={handleRevocationCancelled}
                onError={handleRevocationCancelError}
              />
            ))}
          </div>
        </Section>
      )}

      <Section
        title="Outstanding"
        hint="Pending means the device has not polled yet — normal for an offline terminal, not a failure. Sent means delivered and awaiting confirmation, retrying on backoff."
      >
        {loadingLists ? (
          <p className="text-xs text-gray-400">Loading…</p>
        ) : otherOutbox.length === 0 ? (
          <p className="text-xs text-gray-400">Nothing outstanding. This device owes nothing right now.</p>
        ) : (
          <div className="space-y-2">
            {otherOutbox.map((row) => (
              <div key={row.id} className="bg-gray-50 rounded-lg px-3 py-2.5 text-sm">
                <div className="flex items-center gap-2 mb-1">
                  <Pill tone={row.status === 'sent' ? 'blue' : 'gray'}>
                    {row.status === 'sent' ? 'Sent' : 'Pending'}
                  </Pill>
                  <span className="text-xs text-gray-500 flex-1">
                    {row.status === 'sent'
                      ? `attempt ${row.attempts} · retries ${until(row.next_attempt_at)} · first sent ${since(row.sent_at)}`
                      : `waiting for the device to poll · queued ${since(row.created_at)}`}
                  </span>
                </div>
                <p className="text-xs font-mono text-gray-500 truncate">{row.command}</p>
                {confirmCancelId === row.id ? (
                  <div className="mt-2 text-xs bg-amber-50 border border-amber-200 rounded px-2 py-1.5 text-amber-800">
                    Already sent to the device at least once — cancelling only removes
                    our record, it does not recall it.
                    <div className="flex gap-3 mt-1.5">
                      <button
                        onClick={() => doCancel(row)}
                        className="text-red-700 font-semibold hover:underline"
                      >
                        Cancel our record anyway
                      </button>
                      <button
                        onClick={() => setConfirmCancelId(null)}
                        className="text-gray-500 hover:underline"
                      >
                        Never mind
                      </button>
                    </div>
                  </div>
                ) : (
                  <button
                    onClick={() => handleCancelClick(row)}
                    disabled={!!busy[`out-${row.id}`]}
                    className="mt-1.5 text-xs text-gray-500 hover:text-gray-800 px-2 py-1 rounded hover:bg-gray-100 disabled:opacity-40 transition-colors"
                  >
                    {busy[`out-${row.id}`]
                      ? 'Cancelling…'
                      : row.status === 'sent'
                        ? 'Cancel — will not recall it'
                        : 'Cancel — never sent'}
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section
        title="History"
        hint="What actually happened, read from the outcome — not from the queue being empty."
      >
        {loadingLists ? (
          <p className="text-xs text-gray-400">Loading…</p>
        ) : history.length === 0 ? (
          <p className="text-xs text-gray-400">No concluded commands yet.</p>
        ) : (
          <div className="space-y-2">
            {history.map((row) => {
              const outcome = historyOutcome(row)
              const revocation = isRevocation(row.command)
              const canRetry = row.outcome === 'failed'
              return (
                <div key={row.id} className="bg-gray-50 rounded-lg px-3 py-2.5 text-sm">
                  <div className="flex items-center gap-2 mb-1">
                    <Pill tone={outcome.tone}>{outcome.label}</Pill>
                    {revocation && <Pill tone="red">revocation</Pill>}
                    <span className="text-xs text-gray-400 flex-1 text-right">
                      concluded {since(row.concluded_at)}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-gray-500 truncate">{row.command}</p>
                  {row.last_error && (
                    <p className="text-xs text-gray-500 mt-1">{row.last_error}</p>
                  )}
                  {canRetry && (
                    confirmRetryId === row.id ? (
                      <div className="mt-2 text-xs bg-amber-50 border border-amber-200 rounded px-2 py-1.5 text-amber-800">
                        {outcome.label.startsWith('Refused')
                          ? `The device refused this with Return=${row.return_code} — unless something changed at the device it will very likely refuse again, unchanged.`
                          : `The device answered Return=${row.return_code} last time, which this system cannot read as either success or refusal — so this command may already have worked. Sending it again is safe, but it is not a retry of a known failure.`}
                        <div className="flex gap-3 mt-1.5">
                          <button
                            onClick={() => doRetry(row)}
                            className="text-amber-900 font-semibold hover:underline"
                          >
                            Retry anyway
                          </button>
                          <button
                            onClick={() => setConfirmRetryId(null)}
                            className="text-gray-500 hover:underline"
                          >
                            Never mind
                          </button>
                        </div>
                      </div>
                    ) : (
                      <button
                        onClick={() => handleRetryClick(row)}
                        disabled={!!busy[`log-${row.id}`]}
                        className="mt-1.5 text-xs text-blue-600 hover:text-blue-800 px-2 py-1 rounded hover:bg-blue-50 disabled:opacity-40 transition-colors"
                      >
                        {busy[`log-${row.id}`] ? 'Requeuing…' : 'Retry'}
                      </button>
                    )
                  )}
                </div>
              )
            })}
          </div>
        )}
      </Section>
    </Drawer>
  )
}
