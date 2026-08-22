import { useState, useEffect } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

// Timestamps come back from this API in two shapes depending on the endpoint:
// some carry an explicit offset (`…+00:00`), some are bare naive-UTC. Appending
// a `Z` unconditionally corrupts the first kind into an unparseable string and
// renders "Invalid Date". Same rule, and same reason, as CommandsDrawer's.
const anchorUtc = (iso) =>
  /(Z|[+-]\d\d:?\d\d)$/.test(iso) ? iso : `${iso}Z`

function Row({ label, value }) {
  return (
    <div className="flex justify-between py-2 border-b border-gray-100 last:border-0 text-sm">
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-900 font-mono text-xs text-right max-w-[60%] break-all">{value ?? '—'}</span>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div className="mb-5">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">{title}</p>
      <div className="bg-gray-50 rounded-lg px-3">{children}</div>
    </div>
  )
}

export default function DeviceInfoDrawer({ device, onClose, showToast }) {
  const [info, setInfo] = useState(null)
  const [error, setError] = useState('')
  const [refreshing, setRefreshing] = useState(false)

  // An access-control terminal cannot be dialled for this. What is shown is
  // the parameter line the device itself last sent — real values it reported,
  // but not necessarily current ones — so the drawer says which it is and
  // when they arrived. Presenting stale values as a live reading is the one
  // thing this must not do.
  const lastKnown = info?.source === 'last_known'

  function load() {
    api.devices.info(device.serial_number)
      .then(setInfo)
      .catch((e) => setError(e.message))
  }

  useEffect(load, [device.serial_number])

  async function handleRefresh() {
    setRefreshing(true)
    try {
      const result = await api.devices.refreshInfo(device.serial_number)
      showToast?.(result?.message || 'Refresh queued')
    } catch (err) {
      showToast?.(err.message, 'error')
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <Drawer title="Device Info" onClose={onClose}>
      {error && (
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-4">
          {error}
        </p>
      )}

      {lastKnown && (
        <div className="mb-5 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
          <p className="text-xs font-semibold text-amber-800 uppercase tracking-wide mb-1">
            Last known — not a live reading
          </p>
          <p className="text-xs text-amber-900 leading-snug">{info.message}</p>
          <p className="text-xs text-amber-800 mt-1">
            Reported by the terminal{' '}
            {info.as_of
              ? `at ${new Date(anchorUtc(info.as_of)).toLocaleString()}`
              : '— time not recorded'}
            .
          </p>
          <button
            type="button"
            onClick={handleRefresh}
            disabled={refreshing}
            className="mt-2 text-xs font-medium text-amber-900 underline disabled:opacity-50"
          >
            {refreshing ? 'Queueing…' : 'Refresh from device'}
          </button>
        </div>
      )}
      {!info && !error && (
        <p className="text-sm text-gray-400 text-center py-8">Loading…</p>
      )}
      {info && (
        <>
          <Section title="Identity">
            <Row label="Serial Number" value={info.serial_number} />
            <Row label="Device Name" value={info.device_name} />
            <Row label="Platform" value={info.platform} />
            <Row label="Firmware" value={info.firmware_version} />
            <Row label="MAC" value={info.mac} />
          </Section>
          <Section title="Biometrics">
            <Row label="FP Version" value={info.fp_version} />
            <Row label="Face Version" value={info.face_version} />
            <Row label="PIN Width" value={info.pin_width} />
          </Section>
          <Section title="Network">
            <Row label="IP" value={info.network?.ip} />
            <Row label="Mask" value={info.network?.mask} />
            <Row label="Gateway" value={info.network?.gateway} />
          </Section>

          {/* The two transports genuinely know different things. The SDK reads
              live counts AND capacities; a parameter line carries capacities
              and the door/reader inventory but no current usage, so the
              occupancy figures are absent rather than shown as "undefined of
              50". An access-control terminal also has doors, which is the one
              fact a door command depends on. */}
          {lastKnown ? (
            <Section title="Access Hardware">
              <Row label="Doors" value={info.doors} />
              <Row label="Readers" value={info.readers} />
              <Row label="Aux Outputs" value={info.aux_outputs} />
            </Section>
          ) : null}

          <Section title="Capacity">
            {lastKnown ? (
              <>
                <Row label="Max Users" value={info.sizes?.users_cap} />
                <Row label="Max Records" value={info.sizes?.rec_cap} />
                <Row label="Fingers / User" value={info.sizes?.fingers_cap} />
              </>
            ) : (
              <>
                <Row label="Users" value={`${info.sizes?.users} / ${info.sizes?.users_cap}`} />
                <Row label="Fingers" value={`${info.sizes?.fingers} / ${info.sizes?.fingers_cap}`} />
                <Row label="Records" value={`${info.sizes?.records} / ${info.sizes?.rec_cap}`} />
                <Row label="Cards" value={info.sizes?.cards} />
                <Row label="Faces" value={info.sizes?.faces} />
              </>
            )}
          </Section>
        </>
      )}
    </Drawer>
  )
}
