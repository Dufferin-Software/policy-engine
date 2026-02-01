// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import React, { useState, useEffect, useRef } from 'react'
import { useMutation, gql } from '@apollo/client'
import { NodeInterfaceOutput, RuleOutput } from './types.ts'

const TAG_INTERFACE = gql`
  mutation TagInterface($nodeId: ID!, $interfaceName: String!, $tag: String!) {
    tagInterface(nodeId: $nodeId, interfaceName: $interfaceName, tag: $tag) { success message }
  }
`

const UNTAG_INTERFACE = gql`
  mutation UntagInterface($nodeId: ID!, $interfaceName: String!) {
    untagInterface(nodeId: $nodeId, interfaceName: $interfaceName) { success message }
  }
`

const ATTACH_PROGRAM = gql`
  mutation AttachProgram($nodeId: ID!, $interfaceName: String!, $direction: String!, $mode: String) {
    attachProgram(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction, mode: $mode) { success message }
  }
`

const DETACH_PROGRAM = gql`
  mutation DetachProgram($nodeId: ID!, $interfaceName: String!, $direction: String!) {
    detachProgram(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) { success message }
  }
`

const SET_FIB_FORWARDING = gql`
  mutation SetFibForwarding($nodeId: ID!, $interfaceName: String!, $enabled: Boolean!) {
    setFibForwarding(nodeId: $nodeId, interfaceName: $interfaceName, enabled: $enabled) {
      success message
    }
  }
`

interface Props {
  nodeId: string
  interfaces: NodeInterfaceOutput[]
  rules?: RuleOutput[]
  onRefetch: () => void
  onShowStats?: (interfaceName: string) => void
  onPendingChange?: (pending: boolean, opKind?: string) => void
}

function linkStateColor(state: string): string {
  switch (state.toLowerCase()) {
    case 'up':
      return 'text-green-400'
    case 'down':
      return 'text-red-400'
    default:
      return 'text-gray-500'
  }
}

function parseAddresses(json: string): { address: string; prefix_len: number; family: string }[] {
  try {
    return JSON.parse(json)
  } catch {
    return []
  }
}

function Spinner() {
  return (
    <svg className="animate-spin h-3.5 w-3.5 text-blue-400 inline-block" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
    </svg>
  )
}

export default function InterfaceManager({
  nodeId,
  interfaces,
  rules = [],
  onRefetch,
  onShowStats,
  onPendingChange,
}: Props) {
  const [tagInterface] = useMutation(TAG_INTERFACE)
  const [untagInterface] = useMutation(UNTAG_INTERFACE)
  const [attachProgram] = useMutation(ATTACH_PROGRAM)
  const [detachProgram] = useMutation(DETACH_PROGRAM)
  const [setFibForwarding] = useMutation(SET_FIB_FORWARDING)
  const [editingTag, setEditingTag] = useState<{ name: string; value: string } | null>(null)
  // Map key: "ifname:dir", value: expected attached state after op completes
  const [pending, setPending] = useState<Map<string, boolean>>(new Map())
  // Map key: ifname, value: expected fibForwarding state after op completes
  const [fibPending, setFibPending] = useState<Map<string, boolean>>(new Map())
  const [error, setError] = useState<string | null>(null)
  const prevPendingSizeRef = useRef(0)
  const prevFibPendingSizeRef = useRef(0)

  // Clear pending entries once the interface state reflects the expected outcome.
  useEffect(() => {
    if (pending.size === 0 && fibPending.size === 0) return

    let attachChanged = false
    const nextPending = new Map(pending)
    for (const [key, expected] of pending) {
      const [ifaceName, dir] = key.split(':')
      const iface = interfaces.find((i) => i.name === ifaceName)
      if (!iface) continue
      const actual = dir === 'ingress' ? iface.xdpAttached : iface.tcAttached
      if (actual === expected) { nextPending.delete(key); attachChanged = true }
    }
    if (attachChanged) setPending(nextPending)

    let fibChanged = false
    const nextFib = new Map(fibPending)
    for (const [ifaceName, expected] of fibPending) {
      const iface = interfaces.find((i) => i.name === ifaceName)
      if (!iface) continue
      if (iface.fibForwarding === expected) { nextFib.delete(ifaceName); fibChanged = true }
    }
    if (fibChanged) setFibPending(nextFib)
  }, [interfaces])

  // Clear pending-confirm badge when the attach/detach spinner resolves (pending→empty).
  useEffect(() => {
    const prevSize = prevPendingSizeRef.current
    prevPendingSizeRef.current = pending.size
    if (prevSize > 0 && pending.size === 0) {
      onPendingChange?.(false)
    }
  }, [pending])

  // Clear pending-confirm badge when the fib-forwarding spinner resolves.
  useEffect(() => {
    const prevSize = prevFibPendingSizeRef.current
    prevFibPendingSizeRef.current = fibPending.size
    if (prevSize > 0 && fibPending.size === 0) {
      onPendingChange?.(false)
    }
  }, [fibPending])

  async function handleSaveTag(interfaceName: string, tag: string) {
    if (tag.trim()) {
      await tagInterface({ variables: { nodeId, interfaceName, tag: tag.trim() } })
    } else {
      await untagInterface({ variables: { nodeId, interfaceName } })
    }
    setEditingTag(null)
    onRefetch()
  }

  function isPending(ifaceName: string, dir: string): boolean {
    return pending.has(`${ifaceName}:${dir}`)
  }

  function clearError() { setError(null) }

  function hasRules(ifaceName: string, dir: string): boolean {
    return rules.some(
      (r) => r.interfaceName === ifaceName && r.direction.toLowerCase() === dir.toLowerCase(),
    )
  }

  async function handleAttach(ifaceName: string, dir: string) {
    const key = `${ifaceName}:${dir}`
    setError(null)
    onPendingChange?.(true, 'attach_program')
    setPending((prev) => new Map(prev).set(key, true))
    try {
      const res = await attachProgram({ variables: { nodeId, interfaceName: ifaceName, direction: dir, mode: 'auto' } })
      const r = res.data?.attachProgram
      if (!r?.success) {
        setError(r?.message ?? 'Attach failed')
        setPending((prev) => { const next = new Map(prev); next.delete(key); return next })
        onPendingChange?.(false)
      }
      // On success: badge clears via the pending→empty useEffect so spinner and badge vanish together
    } catch (e) {
      setError(String(e).replace(/^ApolloError:\s*/, ''))
      setPending((prev) => { const next = new Map(prev); next.delete(key); return next })
      onPendingChange?.(false)
    }
  }

  async function handleDetach(ifaceName: string, dir: string) {
    const key = `${ifaceName}:${dir}`
    setError(null)
    onPendingChange?.(true, 'detach_program')
    setPending((prev) => new Map(prev).set(key, false))
    try {
      const res = await detachProgram({ variables: { nodeId, interfaceName: ifaceName, direction: dir } })
      const r = res.data?.detachProgram
      if (!r?.success) {
        setError(r?.message ?? 'Detach failed')
        setPending((prev) => { const next = new Map(prev); next.delete(key); return next })
        onPendingChange?.(false)
      }
      // On success: badge clears via the pending→empty useEffect so spinner and badge vanish together
    } catch (e) {
      setError(String(e).replace(/^ApolloError:\s*/, ''))
      setPending((prev) => { const next = new Map(prev); next.delete(key); return next })
      onPendingChange?.(false)
    }
  }

  async function handleToggleFib(ifaceName: string, enabled: boolean) {
    setError(null)
    onPendingChange?.(true, 'set_fib_forwarding')
    setFibPending((prev) => new Map(prev).set(ifaceName, enabled))
    try {
      const res = await setFibForwarding({ variables: { nodeId, interfaceName: ifaceName, enabled } })
      const r = res.data?.setFibForwarding
      if (!r?.success) {
        setError(r?.message ?? 'FIB toggle failed')
        setFibPending((prev) => { const next = new Map(prev); next.delete(ifaceName); return next })
        onPendingChange?.(false)
      }
      // On success: badge clears via the fibPending→empty useEffect so spinner and badge vanish together
    } catch (e) {
      setError(String(e).replace(/^ApolloError:\s*/, ''))
      setFibPending((prev) => { const next = new Map(prev); next.delete(ifaceName); return next })
      onPendingChange?.(false)
    }
  }

  if (interfaces.length === 0) {
    return (
      <div className="text-sm text-gray-600 py-4 px-4">
        No interfaces reported by agent yet.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      {error && (
        <div className="flex items-center gap-2 px-3 py-2 mb-2 bg-red-900/50 border border-red-700 rounded text-xs text-red-300">
          <span className="flex-1">{error}</span>
          <button onClick={clearError} className="text-red-400 hover:text-red-200 font-bold">&times;</button>
        </div>
      )}
      <table className="w-full text-xs">
        <thead className="text-gray-500 uppercase bg-gray-900/50">
          <tr>
            {['Interface', 'Link', 'Addresses', 'Ingress', 'Egress'].map((h) => (
              <th key={h} className="px-3 py-1.5 text-left font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {interfaces.map((iface) => {
            const addrs = parseAddresses(iface.addressesJson)
            const hasIngressRules = hasRules(iface.name, 'ingress')
            const hasEgressRules = hasRules(iface.name, 'egress')
            return (
              <tr key={iface.name} className="border-t border-gray-800">
                <td className="px-3 py-1.5">
                  <span className="font-mono text-gray-200">{iface.name}</span>
                  {iface.tag && (
                    <span
                      className="ml-1.5 text-blue-400 cursor-pointer"
                      onClick={() => setEditingTag({ name: iface.name, value: iface.tag ?? '' })}
                      title="Click to edit tag"
                    >
                      ({iface.tag})
                    </span>
                  )}
                  {!iface.tag && (
                    <button
                      onClick={() => setEditingTag({ name: iface.name, value: '' })}
                      className="ml-1.5 text-gray-600 hover:text-gray-400"
                      title="Set tag"
                    >
                      +tag
                    </button>
                  )}
                  {onShowStats && (
                    <button
                      onClick={() => onShowStats(iface.name)}
                      className="ml-1.5 px-1.5 py-0.5 rounded text-[10px] font-medium border bg-cyan-900/40 border-cyan-700 text-cyan-300 hover:bg-cyan-900/70 hover:text-cyan-200"
                      title="Show interface stats"
                    >
                      stats
                    </button>
                  )}
                  {editingTag?.name === iface.name && (
                    <form
                      onSubmit={(e) => { e.preventDefault(); handleSaveTag(iface.name, editingTag.value) }}
                      className="flex gap-1 mt-1"
                    >
                      <input
                        value={editingTag.value}
                        onChange={(e) => setEditingTag({ name: iface.name, value: e.target.value })}
                        className="bg-gray-700 border border-gray-600 rounded px-1.5 py-0.5 text-xs w-20"
                        autoFocus
                      />
                      <button type="submit" className="text-green-400 hover:text-green-300">Save</button>
                      <button type="button" onClick={() => setEditingTag(null)} className="text-gray-500 hover:text-gray-300">Cancel</button>
                    </form>
                  )}
                </td>
                <td className={`px-3 py-1.5 font-medium ${linkStateColor(iface.linkState)}`}>
                  <span title={`MAC: ${iface.macAddress ?? 'unknown'}`}>{iface.linkState}</span>
                </td>
                <td className="px-3 py-1.5 text-gray-400">
                  {addrs.length === 0
                    ? '—'
                    : addrs.map((a) => `${a.address}/${a.prefix_len}`).join(', ')}
                </td>
                <td className="px-3 py-1.5">
                  <AttachCell
                    attached={iface.xdpAttached}
                    pending={isPending(iface.name, 'ingress')}
                    hasRules={hasIngressRules}
                    labelTitle={
                      iface.fibForwarding && iface.xdpAttached
                        ? 'Ingress enabled with express FIB forwarding. ' +
                          'Allowed transit packets are forwarded at line rate via bpf_fib_lookup — ' +
                          'they bypass the kernel stack entirely, which also means egress filtering ' +
                          'on the outbound interface is NOT applied to forwarded traffic.'
                        : undefined
                    }
                    onAttach={() => handleAttach(iface.name, 'ingress')}
                    onDetach={() => handleDetach(iface.name, 'ingress')}
                    attachTitle="Enable ingress filtering"
                    detachTitle="Disable ingress filtering"
                    extra={
                      iface.xdpAttached ? (
                        <FibToggle
                          enabled={iface.fibForwarding}
                          pending={fibPending.has(iface.name)}
                          onToggle={(v) => handleToggleFib(iface.name, v)}
                        />
                      ) : null
                    }
                  />
                </td>
                <td className="px-3 py-1.5">
                  <AttachCell
                    attached={iface.tcAttached}
                    pending={isPending(iface.name, 'egress')}
                    hasRules={hasEgressRules}
                    onAttach={() => handleAttach(iface.name, 'egress')}
                    onDetach={() => handleDetach(iface.name, 'egress')}
                    attachTitle="Enable egress filtering"
                    detachTitle="Disable egress filtering"
                  />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function AttachCell({
  attached,
  pending,
  hasRules,
  labelTitle,
  onAttach,
  onDetach,
  attachTitle,
  detachTitle,
  extra,
}: {
  attached: boolean
  pending: boolean
  hasRules: boolean
  labelTitle?: string
  onAttach: () => void
  onDetach: () => void
  attachTitle: string
  detachTitle: string
  extra?: React.ReactNode
}) {
  if (pending) {
    return <Spinner />
  }

  if (attached) {
    return (
      <span className="inline-flex items-center gap-1">
        <span className="w-2 h-2 rounded-full bg-green-400 inline-block" title={labelTitle} />
        {hasRules && (
          <span className="text-green-500 text-[10px]" title="Policy rules active">P</span>
        )}
        <button
          onClick={onDetach}
          className="text-red-500 hover:text-red-400"
          title={detachTitle}
        >
          Detach
        </button>
        {extra}
      </span>
    )
  }

  return (
    <span className="inline-flex items-center gap-1">
      <span className="w-2 h-2 rounded-full bg-gray-600 inline-block" title="Not attached" />
      <button
        onClick={onAttach}
        className="text-blue-400 hover:text-blue-300"
        title={attachTitle}
      >
        Attach
      </button>
    </span>
  )
}

function FibToggle({
  enabled,
  pending,
  onToggle,
}: {
  enabled: boolean
  pending: boolean
  onToggle: (v: boolean) => void
}) {
  if (pending) {
    return <Spinner />
  }
  const title = enabled
    ? 'FIB forwarding enabled — transit traffic forwarded via bpf_fib_lookup. ' +
      'Bypasses the kernel stack, so egress filtering on the outbound interface is NOT applied. Click to disable.'
    : 'Enable FIB forwarding on this ingress interface. Allowed transit packets will be ' +
      'forwarded at line rate, bypassing the kernel stack and any egress filtering.'
  return (
    <button
      onClick={() => onToggle(!enabled)}
      className={`ml-1 px-1.5 py-0.5 rounded text-[10px] font-medium border ${
        enabled
          ? 'bg-amber-900/40 border-amber-700 text-amber-300 hover:bg-amber-900/60'
          : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
      }`}
      title={title}
    >
      FWD {enabled ? 'on' : 'off'}
    </button>
  )
}
