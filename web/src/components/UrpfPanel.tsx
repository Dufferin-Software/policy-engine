// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { gql, useQuery, useMutation } from '@apollo/client'
import { useState } from 'react'

const GET_URPF = gql`
  query GetUrpf {
    urpf {
      interface
      mode
    }
    interfaces {
      interface
      direction
    }
  }
`

const SET_URPF = gql`
  mutation SetUrpf($interface: String!, $mode: UrpfMode!) {
    setUrpf(input: { interface: $interface, mode: $mode }) {
      success
      message
    }
  }
`

type UrpfModeValue = 'OFF' | 'LOOSE' | 'STRICT'

interface UrpfEntry {
  interface: string
  mode: UrpfModeValue
}

interface InterfaceAttachment {
  interface: string
  direction: string
}

interface OperationResult {
  success: boolean
  message: string
}

const MODES: { value: UrpfModeValue; label: string }[] = [
  { value: 'OFF', label: 'Off' },
  { value: 'LOOSE', label: 'Loose' },
  { value: 'STRICT', label: 'Strict' },
]

export function UrpfPanel() {
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  )
  const [pending, setPending] = useState<Set<string>>(new Set())

  const { data, loading } = useQuery<{
    urpf: UrpfEntry[]
    interfaces: InterfaceAttachment[]
  }>(GET_URPF, { pollInterval: 5000 })

  const [setUrpf] = useMutation<{ setUrpf: OperationResult }>(SET_URPF, {
    refetchQueries: [{ query: GET_URPF }],
  })

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message })
    setTimeout(() => setFeedback(null), 5000)
  }

  const handleSetMode = async (iface: string, mode: UrpfModeValue) => {
    setPending((prev) => new Set(prev).add(iface))
    try {
      const result = await setUrpf({ variables: { interface: iface, mode } })
      if (result.data?.setUrpf.success) {
        showFeedback('success', result.data.setUrpf.message)
      } else if (result.data) {
        showFeedback('error', result.data.setUrpf.message)
      }
    } catch (e) {
      showFeedback('error', String(e))
    } finally {
      setPending((prev) => {
        const next = new Set(prev)
        next.delete(iface)
        return next
      })
    }
  }

  const modeMap = new Map<string, UrpfModeValue>(
    (data?.urpf ?? []).map((e) => [e.interface, e.mode])
  )
  const ingressIfaces = Array.from(
    new Set(
      (data?.interfaces ?? [])
        .filter((i) => i.direction.toUpperCase() === 'INGRESS')
        .map((i) => i.interface)
    )
  ).sort()

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
      <div className="flex items-center gap-2 group relative mb-3">
        <h2 className="text-xl font-semibold">uRPF (Reverse Path Filtering)</h2>
        <span className="text-gray-500 cursor-default select-none text-sm">ⓘ</span>
        <div className="absolute left-0 top-full mt-2 w-80 bg-gray-900 border border-gray-600 rounded-lg p-3 text-xs text-gray-300 z-50 shadow-xl hidden group-hover:block">
          Drops source-spoofed packets per <em>ingress</em> interface by checking the FIB for a
          route back to the packet&apos;s source.
          <div className="mt-2">
            <span className="text-blue-300">Loose</span>: drop only if no route to the source
            exists via any interface.
          </div>
          <div className="mt-1">
            <span className="text-blue-300">Strict</span>: drop unless the route back to the source
            exits via the interface the packet arrived on. May drop asymmetrically-routed traffic.
          </div>
          <div className="mt-2 text-amber-300">
            uRPF is ingress-only (XDP); it is never applied on egress.
          </div>
        </div>
      </div>

      {loading && !data ? (
        <div className="text-gray-500 text-sm">Loading…</div>
      ) : ingressIfaces.length === 0 ? (
        <div className="text-gray-500 text-sm">No ingress interfaces attached.</div>
      ) : (
        <div className="space-y-2">
          {ingressIfaces.map((iface) => {
            const mode = modeMap.get(iface) ?? 'OFF'
            const isPending = pending.has(iface)
            return (
              <div
                key={iface}
                className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg"
              >
                <div>
                  <span className="font-mono">{iface}</span>
                  <span className="ml-2 text-xs text-gray-400">
                    {mode === 'OFF' ? 'no reverse-path check' : `uRPF ${mode.toLowerCase()}`}
                  </span>
                </div>
                <div className="inline-flex rounded-md overflow-hidden border border-gray-600">
                  {MODES.map((m) => (
                    <button
                      key={m.value}
                      onClick={() => handleSetMode(iface, m.value)}
                      disabled={isPending || mode === m.value}
                      className={`px-3 py-1 text-xs transition-colors duration-150 focus:outline-none disabled:cursor-default ${
                        mode === m.value
                          ? m.value === 'OFF'
                            ? 'bg-gray-500 text-white'
                            : 'bg-green-500 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50'
                      }`}
                    >
                      {m.label}
                    </button>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {feedback && (
        <div
          className={`mt-3 p-2 rounded text-sm ${
            feedback.type === 'success'
              ? 'bg-green-500/20 text-green-400'
              : 'bg-red-500/20 text-red-400'
          }`}
        >
          {feedback.message}
        </div>
      )}
    </div>
  )
}
