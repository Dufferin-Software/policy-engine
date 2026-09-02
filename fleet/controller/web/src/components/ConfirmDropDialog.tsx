// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState } from 'react'

export interface DropCriterion {
  label: string
  value: string
}

interface Props {
  criteria: DropCriterion[]
  onConfirm: () => void
  onCancel: () => void
}

export default function ConfirmDropDialog({ criteria, onConfirm, onCancel }: Props) {
  const [checked, setChecked] = useState(false)

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-800 border border-red-700 rounded-lg p-6 max-w-md w-full space-y-4">
        <h3 className="text-lg font-bold text-red-400">Confirm DROP Rule</h3>
        <p className="text-sm text-gray-400">
          Traffic matching <span className="text-gray-50 font-semibold">all</span> of the following criteria will be dropped:
        </p>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm bg-gray-900 rounded p-3 border border-gray-700">
          {criteria.map(({ label, value }) => (
            <div key={label} className="contents">
              <dt className="text-gray-500">{label}</dt>
              <dd className="text-gray-100 font-mono">{value}</dd>
            </div>
          ))}
        </dl>
        <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => setChecked(e.target.checked)}
            className="rounded border-gray-600"
          />
          I understand this will DROP matching traffic
        </label>
        <div className="flex gap-2 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-1.5 rounded text-sm bg-gray-700 hover:bg-gray-600"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={!checked}
            className={`px-4 py-1.5 rounded text-sm text-white ${
              checked
                ? 'bg-red-700 hover:bg-red-600'
                : 'bg-red-900 opacity-50 cursor-not-allowed'
            }`}
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  )
}
