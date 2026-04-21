import { useState, useEffect, useRef } from 'react'

function MenuItem({ label, onClick, danger, disabled }) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => {
        if (!disabled) onClick()
      }}
      className={`w-full text-left px-3 py-2 text-sm rounded-md transition-colors disabled:opacity-40 ${
        danger
          ? 'text-red-600 hover:bg-red-50'
          : 'text-gray-700 hover:bg-gray-100'
      }`}
    >
      {label}
    </button>
  )
}

function Divider() {
  return <div className="my-1 border-t border-gray-100" />
}

export default function KebabMenu({ items }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [open])

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="p-1.5 rounded-md text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors"
        aria-label="More actions"
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
          <circle cx="8" cy="3" r="1.5" />
          <circle cx="8" cy="8" r="1.5" />
          <circle cx="8" cy="13" r="1.5" />
        </svg>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 w-52 bg-white rounded-xl shadow-lg border border-gray-200 p-1 z-40">
          {items.map((item, i) =>
            item === 'divider' ? (
              <Divider key={i} />
            ) : (
              <MenuItem
                key={item.label}
                label={item.label}
                danger={item.danger}
                disabled={item.disabled}
                onClick={() => {
                  setOpen(false)
                  item.onClick()
                }}
              />
            )
          )}
        </div>
      )}
    </div>
  )
}
