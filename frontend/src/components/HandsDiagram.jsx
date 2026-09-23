// Two hands, backs up, thumbs to the middle — the way a person lays them on
// a table, and the way ZKTeco's own enrolment screen draws them. A finger is
// coloured when a template for it is stored, so "which fingers does this
// person have on file" is one glance instead of a list to read.
//
// Finger ids follow the device's own numbering, which runs left to right
// across both hands exactly as laid out here:
//
//   0 L little · 1 L ring · 2 L middle · 3 L index · 4 L thumb
//   5 R thumb  · 6 R index · 7 R middle · 8 R ring · 9 R little
//
// The diagram is also the picker: clicking a finger selects it, and the
// parent decides what that means (delete a stored one, enrol an empty one).

import { FINGER_NAMES } from '../fingers'

// One hand, drawn as a left hand with the thumb on the right. The right hand
// is the same shape mirrored. Coordinates are in a 170×200 box.
//                 x    w    top   h
const FINGERS = [
  { key: 'little', x: 14, w: 24, top: 68, h: 66 },
  { key: 'ring',   x: 44, w: 26, top: 44, h: 90 },
  { key: 'middle', x: 75, w: 26, top: 34, h: 100 },
  { key: 'index',  x: 106, w: 26, top: 46, h: 88 },
]
const THUMB = { x: 132, w: 26, top: 100, h: 70, pivotX: 145, pivotY: 135, angle: 42 }
const PALM = 'M 14 128 H 132 V 178 Q 132 198 112 198 H 40 Q 14 198 14 172 Z'

// Which finger id each drawn digit is, on each hand.
const LEFT_IDS  = { little: 0, ring: 1, middle: 2, index: 3, thumb: 4 }
const RIGHT_IDS = { little: 9, ring: 8, middle: 7, index: 6, thumb: 5 }

const STATE_LABEL = { valid: ' — enrolled', invalid: ' — stored, invalid', empty: ' — not enrolled' }

const FILL = {
  valid: 'fill-emerald-400',
  invalid: 'fill-amber-300',
  empty: 'fill-gray-100 hover:fill-gray-200',
}
const STROKE = {
  valid: 'stroke-emerald-600 stroke-[1.5]',
  invalid: 'stroke-amber-500 stroke-[1.5]',
  empty: 'stroke-gray-300 stroke-[1.5]',
}

// The selection outline replaces the state outline rather than stacking on
// it — two stroke classes on one element and the stylesheet order decides.
function fingerClass(state, selected) {
  return `${FILL[state]} ${selected ? 'stroke-blue-500 stroke-[3]' : STROKE[state]}`
}

function Hand({ ids, mirrored, stateOf, selected, onSelect }) {
  const digit = (fid, shape) => (
    <g
      key={fid}
      onClick={() => onSelect?.(fid)}
      className={onSelect ? 'cursor-pointer' : ''}
      role={onSelect ? 'button' : undefined}
      aria-label={FINGER_NAMES[fid]}
    >
      <title>{`${FINGER_NAMES[fid]}${STATE_LABEL[stateOf(fid)]}`}</title>
      {shape}
    </g>
  )

  return (
    <g transform={mirrored ? 'translate(170 0) scale(-1 1)' : undefined}>
      <path d={PALM} className="fill-gray-100 stroke-gray-300 stroke-[1.5]" />
      {FINGERS.map((f) => {
        const fid = ids[f.key]
        return digit(
          fid,
          <rect
            x={f.x} y={f.top} width={f.w} height={f.h} rx={f.w / 2}
            className={fingerClass(stateOf(fid), selected === fid)}
          />
        )
      })}
      {digit(
        ids.thumb,
        <rect
          x={THUMB.x} y={THUMB.top} width={THUMB.w} height={THUMB.h} rx={THUMB.w / 2}
          transform={`rotate(${THUMB.angle} ${THUMB.pivotX} ${THUMB.pivotY})`}
          className={fingerClass(stateOf(ids.thumb), selected === ids.thumb)}
        />
      )}
    </g>
  )
}

/**
 * @param templates  rows from GET /employees/{id}/templates — `finger_id`, `valid`
 * @param selected   finger id currently picked, or null
 * @param onSelect   called with a finger id; omit to render read-only
 */
export default function HandsDiagram({ templates = [], selected = null, onSelect }) {
  const byId = new Map(templates.map((t) => [t.finger_id, t]))
  const stateOf = (fid) => {
    const t = byId.get(fid)
    if (!t) return 'empty'
    return t.valid ? 'valid' : 'invalid'
  }

  return (
    <svg
      viewBox="0 0 370 216"
      className="w-full max-w-sm mx-auto block select-none"
      aria-label="Enrolled fingers"
    >
      <Hand ids={LEFT_IDS} stateOf={stateOf} selected={selected} onSelect={onSelect} />
      <g transform="translate(200 0)">
        <Hand ids={RIGHT_IDS} mirrored stateOf={stateOf} selected={selected} onSelect={onSelect} />
      </g>
      <text x="85" y="212" textAnchor="middle" className="fill-gray-400 text-[11px]">Left</text>
      <text x="285" y="212" textAnchor="middle" className="fill-gray-400 text-[11px]">Right</text>
    </svg>
  )
}
