// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { gql, useQuery, useMutation } from '@apollo/client'
import { useState } from 'react'

const GET_FIB_FORWARDING = gql`
  query GetFibForwarding {
    fibForwarding {
      interface
      enabled
    }
    interfaces {
      interface
      direction
    }
  }
`

const SET_FIB_FORWARDING = gql`
  mutation SetFibForwarding($interface: String!, $enabled: Boolean!) {
    setFibForwarding(input: { interface: $interface, enabled: $enabled }) {
      success
      message
    }
  }
`

interface FibEntry {
  interface: string
  enabled: boolean
}

interface InterfaceAttachment {
  interface: string
  direction: string
}

interface OperationResult {
  success: boolean
  message: string
}

export function FibPanel() {
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  )
  const [pending, setPending] = useState<Set<string>>(new Set())

  const { data, loading } = useQuery<{
    fibForwarding: FibEntry[]
    interfaces: InterfaceAttachment[]
  }>(GET_FIB_FORWARDING, { pollInterval: 5000 })

  const [setFibForwarding] = useMutation<{ setFibForwarding: OperationResult }>(
    SET_FIB_FORWARDING,
    { refetchQueries: [{ query: GET_FIB_FORWARDING }] }
  )

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message })
    setTimeout(() => setFeedback(null), 5000)
  }

  const handleToggle = async (iface: string, newValue: boolean) => {
    setPending((prev) => new Set(prev).add(iface))
    try {
      const result = await setFibForwarding({ variables: { interface: iface, enabled: newValue } })
      if (result.data?.setFibForwarding.success) {
        showFeedback('success', result.data.setFibForwarding.message)
      } else if (result.data) {
        showFeedback('error', result.data.setFibForwarding.message)
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

  const enabledMap = new Map<string, boolean>(
    (data?.fibForwarding ?? []).map((e) => [e.interface, e.enabled])
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
        <h2 className="text-xl font-semibold">XDP Forward Mode</h2>
        <span className="text-gray-500 cursor-default select-none text-sm">ⓘ</span>
        <div className="absolute left-0 top-full mt-2 w-80 bg-gray-900 border border-gray-600 rounded-lg p-3 text-xs text-gray-300 z-50 shadow-xl hidden group-hover:block">
          Enable per <em>ingress</em> interface. Transit packets that pass policy are forwarded
          at line rate via <code className="text-blue-300">bpf_fib_lookup()</code> — L2 rewritten,
          TTL decremented, redirected without entering the kernel stack.
          <div className="mt-2 text-amber-300">
            Warning: forwarded packets bypass the kernel stack entirely, so any egress TC
            filtering on the outbound interface is NOT applied.
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
            const enabled = enabledMap.get(iface) ?? false
            const isPending = pending.has(iface)
            return (
              <div
                key={iface}
                className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg"
              >
                <div>
                  <span className="font-mono">{iface}</span>
                  <span className="ml-2 text-xs text-gray-400">
                    {enabled ? 'FIB forwarding on' : 'standard XDP_PASS'}
                  </span>
                </div>
                <button
                  onClick={() => handleToggle(iface, !enabled)}
                  disabled={isPending}
                  title={
                    enabled
                      ? 'Disable FIB forwarding on this interface.'
                      : 'Enable FIB forwarding. Warning: egress TC filtering on the outbound interface is NOT applied to forwarded traffic.'
                  }
                  className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none disabled:opacity-50 ${
                    enabled ? 'bg-green-500' : 'bg-gray-600'
                  }`}
                >
                  <span
                    className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                      enabled ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
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
