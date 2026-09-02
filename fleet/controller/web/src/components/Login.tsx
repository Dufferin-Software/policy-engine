// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState, FormEvent } from 'react'
import { login } from '../lib/auth'

export default function Login({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const result = await login(username, password)
    setBusy(false)
    if (result.ok) {
      onSuccess()
    } else {
      setError(result.error)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <form
        onSubmit={submit}
        className="w-80 bg-gray-900 border border-gray-700 rounded-lg p-6 space-y-4"
      >
        <h1 className="text-lg font-bold text-blue-400 tracking-wide">Policy Controller</h1>
        <p className="text-xs text-gray-500">Sign in to continue.</p>

        <label className="block">
          <span className="block text-xs text-gray-400 mb-1">Username</span>
          <input
            type="text"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-blue-500"
            required
          />
        </label>

        <label className="block">
          <span className="block text-xs text-gray-400 mb-1">Password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-blue-500"
            required
          />
        </label>

        {error && (
          <div className="text-xs text-red-400 bg-red-950 border border-red-900 rounded px-2 py-1">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={busy}
          className="w-full bg-blue-700 hover:bg-blue-600 disabled:bg-gray-700 disabled:text-gray-400 text-white text-sm rounded px-3 py-1.5 transition-colors"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
