import { useState, useEffect } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

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

export default function DeviceInfoDrawer({ device, onClose }) {
  const [info, setInfo] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.devices.info(device.serial_number)
      .then(setInfo)
      .catch((e) => setError(e.message))
  }, [device.serial_number])

  return (
    <Drawer title="Device Info" onClose={onClose}>
      {error && (
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-4">
          {error}
        </p>
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
          <Section title="Capacity">
            <Row label="Users" value={`${info.sizes?.users} / ${info.sizes?.users_cap}`} />
            <Row label="Fingers" value={`${info.sizes?.fingers} / ${info.sizes?.fingers_cap}`} />
            <Row label="Records" value={`${info.sizes?.records} / ${info.sizes?.rec_cap}`} />
            <Row label="Cards" value={info.sizes?.cards} />
            <Row label="Faces" value={info.sizes?.faces} />
          </Section>
        </>
      )}
    </Drawer>
  )
}
