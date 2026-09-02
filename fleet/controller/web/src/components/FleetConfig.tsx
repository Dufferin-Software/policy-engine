// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState } from 'react'
import { useMutation, gql } from '@apollo/client'
import { ControlledNode } from './types.ts'
import FleetRuleTab from './FleetRuleCreator.tsx'
import FleetTargetPicker, { Target } from './FleetTargetPicker.tsx'

const SET_FIB_FORWARDING = gql`
  mutation FleetSetFibForwarding($nodeId: ID!, $interfaceName: String!, $enabled: Boolean!) {
    setFibForwarding(nodeId: $nodeId, interfaceName: $interfaceName, enabled: $enabled) {
      success message
    }
  }
`

const SET_URPF = gql`
  mutation FleetSetUrpf($nodeId: ID!, $interfaceName: String!, $mode: String!) {
    setUrpf(nodeId: $nodeId, interfaceName: $interfaceName, mode: $mode) {
      success message
    }
  }
`

type Tab = 'rule' | 'fib' | 'urpf'

const TABS: { id: Tab; label: string }[] = [
  { id: 'rule', label: 'Traffic Rule' },
  { id: 'fib', label: 'FIB Forwarding' },
  { id: 'urpf', label: 'uRPF' },
]

interface Props {
  nodes: ControlledNode[]
  onClose: () => void
  onApplied: (msg: string) => void
}

export default function FleetConfig({ nodes, onClose, onApplied }: Props) {
  const [tab, setTab] = useState<Tab>('rule')

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 rounded-lg border border-gray-600 w-full max-w-2xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 pt-5 pb-3">
          <h3 className="text-base font-bold text-gray-50">Fleet Config</h3>
          <button type="button" onClick={onClose} className="text-sm text-gray-500 hover:text-gray-300">Close</button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 px-5 border-b border-gray-700">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-t border-b-2 -mb-px transition-colors ${
                tab === t.id
                  ? 'border-blue-500 text-blue-300'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Active tab body (each tab owns its own scrollable form + footer) */}
        {tab === 'rule' && <FleetRuleTab nodes={nodes} onClose={onClose} onApplied={onApplied} />}
        {tab === 'fib' && <FleetFibTab nodes={nodes} onClose={onClose} onApplied={onApplied} />}
        {tab === 'urpf' && <FleetUrpfTab nodes={nodes} onClose={onClose} onApplied={onApplied} />}
      </div>
    </div>
  )
}

// ── FIB Forwarding tab ───────────────────────────────────────────────────────
// Fans out the per-node setFibForwarding mutation over every picked ingress
// interface. FIB forwarding is an XDP ingress-only feature.
function FleetFibTab({ nodes, onClose, onApplied }: Props) {
  const [setFibForwarding] = useMutation(SET_FIB_FORWARDING)
  const [targets, setTargets] = useState<Target[]>([])
  const [enabled, setEnabled] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (targets.length === 0) { setError('Add at least one target'); return }
    setError(null)
    setSubmitting(true)
    try {
      for (const t of targets) {
        const res = await setFibForwarding({
          variables: { nodeId: t.nodeId, interfaceName: t.interfaceName, enabled },
        })
        const r = res.data?.setFibForwarding
        if (r && !r.success) throw new Error(r.message ?? 'FIB toggle failed')
      }
      onApplied(
        `FIB forwarding ${enabled ? 'enabled' : 'disabled'} on ${targets.length} interface${targets.length !== 1 ? 's' : ''}.`,
      )
      onClose()
    } catch (err) {
      setError(String(err).replace(/^(ApolloError|Error):\s*/, ''))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex-1 min-h-0 overflow-y-auto p-5 space-y-4">
      {error && <div className="text-xs text-red-400 bg-red-900/30 px-3 py-1.5 rounded">{error}</div>}

      <FleetTargetPicker nodes={nodes} mode="fib" targets={targets} onChange={setTargets} />

      <div className="space-y-2 pt-2 border-t border-gray-700">
        <label className="block text-xs text-gray-400 font-medium uppercase tracking-wide">
          2 · FIB Forwarding
        </label>
        <div className="flex gap-2">
          {[
            { v: true, label: 'Enable' },
            { v: false, label: 'Disable' },
          ].map((o) => (
            <button
              key={o.label}
              type="button"
              onClick={() => setEnabled(o.v)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                enabled === o.v ? 'bg-blue-600 text-white' : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
        <p className="text-[11px] text-gray-500">
          Express FIB forwarding sends allowed transit packets at line rate via
          bpf_fib_lookup, bypassing the kernel stack — which also bypasses any TC egress
          filtering on the outbound interface. Ingress-only.
        </p>
      </div>

      <div className="flex justify-end gap-2 pt-2 border-t border-gray-700">
        <button type="button" onClick={onClose}
          className="px-4 py-1.5 rounded text-sm bg-gray-700 hover:bg-gray-600 text-gray-300"
        >
          Cancel
        </button>
        <button type="submit" disabled={submitting || targets.length === 0}
          className="px-4 py-1.5 rounded text-sm bg-blue-700 hover:bg-blue-600 text-white disabled:opacity-50"
        >
          {submitting
            ? 'Applying...'
            : `${enabled ? 'Enable' : 'Disable'} on ${targets.length} interface${targets.length !== 1 ? 's' : ''}`}
        </button>
      </div>
    </form>
  )
}

// ── uRPF tab ─────────────────────────────────────────────────────────────────
// Fans out the per-node setUrpf mutation over every picked ingress interface.
// uRPF drops source-spoofed ingress traffic; it is XDP ingress-only.
const URPF_MODES: { v: string; label: string }[] = [
  { v: 'off', label: 'Off' },
  { v: 'loose', label: 'Loose' },
  { v: 'strict', label: 'Strict' },
]

function FleetUrpfTab({ nodes, onClose, onApplied }: Props) {
  const [setUrpf] = useMutation(SET_URPF)
  const [targets, setTargets] = useState<Target[]>([])
  const [mode, setMode] = useState('strict')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (targets.length === 0) { setError('Add at least one target'); return }
    setError(null)
    setSubmitting(true)
    try {
      for (const t of targets) {
        const res = await setUrpf({
          variables: { nodeId: t.nodeId, interfaceName: t.interfaceName, mode },
        })
        const r = res.data?.setUrpf
        if (r && !r.success) throw new Error(r.message ?? 'uRPF change failed')
      }
      onApplied(
        `uRPF set to ${mode} on ${targets.length} interface${targets.length !== 1 ? 's' : ''}.`,
      )
      onClose()
    } catch (err) {
      setError(String(err).replace(/^(ApolloError|Error):\s*/, ''))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex-1 min-h-0 overflow-y-auto p-5 space-y-4">
      {error && <div className="text-xs text-red-400 bg-red-900/30 px-3 py-1.5 rounded">{error}</div>}

      <FleetTargetPicker nodes={nodes} mode="urpf" targets={targets} onChange={setTargets} />

      <div className="space-y-2 pt-2 border-t border-gray-700">
        <label className="block text-xs text-gray-400 font-medium uppercase tracking-wide">
          2 · uRPF Mode
        </label>
        <div className="flex gap-2">
          {URPF_MODES.map((o) => (
            <button
              key={o.v}
              type="button"
              onClick={() => setMode(o.v)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                mode === o.v ? 'bg-purple-700 text-white' : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
        <p className="text-[11px] text-gray-500">
          uRPF (unicast Reverse Path Filtering) drops source-spoofed ingress traffic.
          <span className="text-gray-400"> Loose:</span> drop only if no route to the source exists.
          <span className="text-gray-400"> Strict:</span> drop unless the route back to the source
          exits via this interface. Ingress-only; never applied on egress.
        </p>
      </div>

      <div className="flex justify-end gap-2 pt-2 border-t border-gray-700">
        <button type="button" onClick={onClose}
          className="px-4 py-1.5 rounded text-sm bg-gray-700 hover:bg-gray-600 text-gray-300"
        >
          Cancel
        </button>
        <button type="submit" disabled={submitting || targets.length === 0}
          className="px-4 py-1.5 rounded text-sm bg-purple-700 hover:bg-purple-600 text-white disabled:opacity-50"
        >
          {submitting
            ? 'Applying...'
            : `Set ${mode} on ${targets.length} interface${targets.length !== 1 ? 's' : ''}`}
        </button>
      </div>
    </form>
  )
}
