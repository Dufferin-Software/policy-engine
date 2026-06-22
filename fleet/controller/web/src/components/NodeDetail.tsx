// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useEffect, useRef, useState } from 'react'
import { flushSync } from 'react-dom'
import { useQuery, useMutation, gql } from '@apollo/client'
import { ControlledNode, NodeInterfaceOutput, RuleOutput, relTime, statusColor, shortId } from './types.ts'
import InterfaceManager from './InterfaceManager.tsx'
import NodeInterfaceStats from './NodeInterfaceStats.tsx'
import InterfaceStatsDetail from './InterfaceStatsDetail.tsx'
import RuleList from './RuleList.tsx'
import RuleCreator from './RuleCreator.tsx'
import RuleLifecycleStream from './RuleLifecycleStream.tsx'
import { wsUrl } from '../lib/auth'

const GET_NODE_DETAIL = gql`
  query GetNodeDetail($id: ID!) {
    node(id: $id) {
      id label hostname status dmiUuid certExpiry lastSeen enrolledAt tpmBacked agentVersion osPrettyName kernelVersion dmiSysVendor dmiProductName tenantId stopBehavior metricsIntervalSecs
    }
    nodeInterfaces(nodeId: $id) {
      nodeId name macAddress linkState addressesJson tag lastReported xdpAttached tcAttached fibForwarding urpfMode ingressDefaultAction egressDefaultAction
    }
    rules(nodeId: $id) {
      id tenantId nodeId interfaceName direction
      srcCidr dstCidr srcPort dstPort protocol
      sniPattern quicVersion srcMac dstMac
      actionsJson createdAt createdBy
      expiresAfterSecs scheduleJson
    }
    pendingGeneration(nodeId: $id) {
      generationId nodeId opKind issuedAt
    }
  }
`

const GET_PENDING_GEN = gql`
  query GetPendingGeneration($id: ID!) {
    pendingGeneration(nodeId: $id) {
      generationId nodeId opKind issuedAt
    }
  }
`

const LOG_AUDIT_ENTRY = gql`
  mutation LogAuditEntry($nodeId: ID, $action: String!, $detail: String) {
    logAuditEntry(nodeId: $nodeId, action: $action, detail: $detail) { success message }
  }
`

const SET_DEFAULT_ACTION = gql`
  mutation SetInterfaceDefaultAction($nodeId: ID!, $interfaceName: String!, $direction: String!, $action: String!) {
    setInterfaceDefaultAction(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction, action: $action) {
      success message
    }
  }
`

const SET_STOP_BEHAVIOR = gql`
  mutation SetNodeStopBehavior($nodeId: ID!, $behavior: String) {
    setNodeStopBehavior(nodeId: $nodeId, behavior: $behavior) {
      success message
    }
  }
`

const CLEAR_ALL_POLICY_STATS = gql`
  mutation ClearAllPolicyStats($nodeId: ID!) {
    clearAllPolicyStats(nodeId: $nodeId) { success message }
  }
`

const SET_METRICS_INTERVAL = gql`
  mutation SetNodeMetricsInterval($nodeId: ID!, $seconds: Int) {
    setNodeMetricsInterval(nodeId: $nodeId, seconds: $seconds) { success message }
  }
`

const ATTACH_PROGRAM = gql`
  mutation AttachProgramPolicy($nodeId: ID!, $interfaceName: String!, $direction: String!, $mode: String) {
    attachProgram(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction, mode: $mode) { success message }
  }
`

const DETACH_PROGRAM = gql`
  mutation DetachProgramPolicy($nodeId: ID!, $interfaceName: String!, $direction: String!) {
    detachProgram(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) { success message }
  }
`

export type NodeTab = 'overview' | 'policy' | 'events' | 'rule-lifecycle'

interface Props {
  nodeId: string
  onBack: () => void
  initialTab?: NodeTab
}

interface Event {
  text: string
  ts: number
}

interface PendingGeneration {
  generationId: string
  nodeId: string
  opKind: string
  issuedAt: string
}

interface NodeDetailData {
  node: ControlledNode | null
  nodeInterfaces: NodeInterfaceOutput[]
  rules: RuleOutput[]
  pendingGeneration: PendingGeneration | null
}

function DefaultActionToggle({
  current,
  onSet,
  disabled,
}: {
  current: string | null
  onSet: (action: string) => void
  disabled?: boolean
}) {
  const value = (current ?? 'pass').toLowerCase()
  return (
    <span className={`inline-flex rounded overflow-hidden text-xs border border-gray-600 ${disabled ? 'opacity-40 pointer-events-none' : ''}`}>
      <button
        onClick={() => onSet('pass')}
        disabled={disabled}
        className={`px-2 py-0.5 ${value === 'pass' ? 'bg-green-700 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
      >
        PASS
      </button>
      <button
        onClick={() => onSet('drop')}
        disabled={disabled}
        className={`px-2 py-0.5 ${value === 'drop' ? 'bg-red-700 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
      >
        DROP
      </button>
    </span>
  )
}

function PolicySpinner() {
  return (
    <svg className="animate-spin h-3.5 w-3.5 text-blue-400 inline-block" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
    </svg>
  )
}

export default function NodeDetail({ nodeId, onBack, initialTab }: Props) {
  const { data, refetch } = useQuery<NodeDetailData>(GET_NODE_DETAIL, {
    variables: { id: nodeId },
    pollInterval: 10_000,
  })
  const { data: pendingPollData, refetch: refetchPending } = useQuery<{ pendingGeneration: PendingGeneration | null }>(
    GET_PENDING_GEN,
    { variables: { id: nodeId }, pollInterval: 1_000, fetchPolicy: 'network-only' },
  )
  const [setInterfaceDefaultAction] = useMutation(SET_DEFAULT_ACTION)
  const [attachProgram] = useMutation(ATTACH_PROGRAM)
  const [detachProgram] = useMutation(DETACH_PROGRAM)
  const [logAuditEntry] = useMutation(LOG_AUDIT_ENTRY)
  const [setNodeStopBehavior] = useMutation(SET_STOP_BEHAVIOR)
  const [stopBehaviorPending, setStopBehaviorPending] = useState(false)
  const [clearAllPolicyStats] = useMutation(CLEAR_ALL_POLICY_STATS)
  const [setNodeMetricsInterval] = useMutation(SET_METRICS_INTERVAL)
  // Mirrors the node's configured interval; empty string means "agent default".
  const [metricsInterval, setMetricsInterval] = useState<string>('')

  // Stats live in the node's engine and are scraped periodically, so cleared
  // counters surface on the next metrics refresh rather than instantly.
  async function handleClearAllPolicyStats() {
    if (!confirm('Clear statistics for every policy rule on this node?')) return
    try {
      const res = await clearAllPolicyStats({ variables: { nodeId } })
      const r = res.data?.clearAllPolicyStats
      // Success is assumed silently; only surface failures.
      if (!r?.success) flash(r?.message ?? 'Failed to clear policy stats')
    } catch (e) {
      flash(String(e).replace(/^ApolloError:\s*/, ''))
    }
  }

  const node = data?.node
  const interfaces = data?.nodeInterfaces ?? []
  const rules = data?.rules ?? []
  // Effective metrics scrape interval; null means the node uses the agent
  // default of 5s. Drives the stats poll cadence and the "Ns refresh" label.
  const refreshSecs = node?.metricsIntervalSecs ?? 5
  const pendingGeneration = pendingPollData?.pendingGeneration ?? data?.pendingGeneration ?? null

  const [tab, setTab] = useState<NodeTab>(initialTab ?? 'overview')
  const [lifecycleEventCount, setLifecycleEventCount] = useState(0)
  const [statsIface, setStatsIface] = useState<string | null>(null)
  const [creatingRule, setCreatingRule] = useState<{ iface: string; dir: string } | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [localPendingOp, setLocalPendingOp] = useState<string | null>(null)
  // key: "ifname:dir", value: expected attached state after op completes
  const [attachPending, setAttachPending] = useState<Map<string, boolean>>(new Map())
  const prevPendingGenRef = useRef<PendingGeneration | null | undefined>(undefined)
  const prevAttachPendingSizeRef = useRef(0)

  const isPending = !!(localPendingOp || pendingGeneration)

  function flash(m: string) {
    setMsg(m)
    setTimeout(() => setMsg(null), 4000)
  }

  // Keep the input in sync with the persisted value as the node refetches.
  useEffect(() => {
    setMetricsInterval(node?.metricsIntervalSecs != null ? String(node.metricsIntervalSecs) : '')
  }, [node?.metricsIntervalSecs])

  async function handleSetMetricsInterval() {
    const trimmed = metricsInterval.trim()
    // Empty clears the override so the agent reverts to its local default.
    const seconds = trimmed === '' ? null : Number(trimmed)
    if (seconds !== null && (!Number.isInteger(seconds) || seconds < 5 || seconds > 3600)) {
      flash('Metrics interval must be a whole number of seconds between 5 and 3600')
      return
    }
    try {
      const res = await setNodeMetricsInterval({ variables: { nodeId, seconds } })
      const r = res.data?.setNodeMetricsInterval
      if (r?.success) {
        flash(r.message ?? (seconds === null ? 'Reverted to default metrics interval' : `Metrics interval set to ${seconds}s`))
        refetch()
      } else {
        flash(r?.message ?? 'Failed to set metrics interval')
      }
    } catch (e) {
      flash(String(e).replace(/^ApolloError:\s*/, ''))
    }
  }

  function handlePendingChange(pending: boolean, opKind?: string) {
    // flushSync forces React to commit the state update synchronously before
    // the mutation's await suspends — without this, React 18 automatic batching
    // can fold the set-true and set-false into one render, hiding the badge.
    flushSync(() => {
      setLocalPendingOp(pending && opKind ? opKind : null)
    })
    if (pending) {
      // After a short delay, hit the server immediately rather than waiting
      // for the next poll tick — by 300ms the pending entry is in the registry.
      setTimeout(() => { refetchPending() }, 300)
    }
  }

  // When the server-side pending generation clears the agent has confirmed — immediately
  // refetch full node data so the attach spinner (driven by interface state) resolves
  // without waiting for the next 10s poll tick.
  useEffect(() => {
    if (prevPendingGenRef.current != null && pendingGeneration == null) {
      refetch()
    }
    prevPendingGenRef.current = pendingGeneration
  }, [pendingGeneration])

  // Clear attach/detach pending entries once interface state reflects the expected outcome.
  useEffect(() => {
    if (attachPending.size === 0) return
    const next = new Map(attachPending)
    let changed = false
    for (const [key, expected] of attachPending) {
      const [ifaceName, dir] = key.split(':')
      const iface = interfaces.find((i) => i.name === ifaceName)
      if (!iface) continue
      const actual = dir === 'ingress' ? iface.xdpAttached : iface.tcAttached
      if (actual === expected) { next.delete(key); changed = true }
    }
    if (changed) setAttachPending(next)
  }, [interfaces])

  // Clear the pending-confirm badge at the same moment the attach spinner clears —
  // when attachPending transitions from non-empty to empty after a successful op.
  useEffect(() => {
    const prevSize = prevAttachPendingSizeRef.current
    prevAttachPendingSizeRef.current = attachPending.size
    if (prevSize > 0 && attachPending.size === 0) {
      handlePendingChange(false)
    }
  }, [attachPending])

  function isAttachPending(ifaceName: string, dir: string): boolean {
    return attachPending.has(`${ifaceName}:${dir}`)
  }

  async function handlePolicyAttach(ifaceName: string, dir: string) {
    const key = `${ifaceName}:${dir}`
    handlePendingChange(true, 'attach_program')
    setAttachPending((prev) => new Map(prev).set(key, true))
    try {
      const res = await attachProgram({ variables: { nodeId, interfaceName: ifaceName, direction: dir, mode: 'auto' } })
      const r = res.data?.attachProgram
      if (!r?.success) {
        flash(r?.message ?? 'Attach failed')
        setAttachPending((prev) => { const next = new Map(prev); next.delete(key); return next })
        handlePendingChange(false)
      }
      // On success: badge clears via the attachPending→empty useEffect so spinner and badge vanish together
    } catch (e) {
      flash(String(e).replace(/^ApolloError:\s*/, ''))
      setAttachPending((prev) => { const next = new Map(prev); next.delete(key); return next })
      handlePendingChange(false)
    }
  }

  async function handlePolicyDetach(ifaceName: string, dir: string) {
    const key = `${ifaceName}:${dir}`
    handlePendingChange(true, 'detach_program')
    setAttachPending((prev) => new Map(prev).set(key, false))
    try {
      const res = await detachProgram({ variables: { nodeId, interfaceName: ifaceName, direction: dir } })
      const r = res.data?.detachProgram
      if (!r?.success) {
        flash(r?.message ?? 'Detach failed')
        setAttachPending((prev) => { const next = new Map(prev); next.delete(key); return next })
        handlePendingChange(false)
      }
      // On success: badge clears via the attachPending→empty useEffect so spinner and badge vanish together
    } catch (e) {
      flash(String(e).replace(/^ApolloError:\s*/, ''))
      setAttachPending((prev) => { const next = new Map(prev); next.delete(key); return next })
      handlePendingChange(false)
    }
  }

  async function handleStopBehaviorChange(behavior: string) {
    setStopBehaviorPending(true)
    try {
      const res = await setNodeStopBehavior({ variables: { nodeId, behavior: behavior || null } })
      const r = res.data?.setNodeStopBehavior
      if (!r?.success) flash(r?.message ?? 'Stop behavior update failed')
      else refetch()
    } catch (e) {
      flash(String(e).replace(/^ApolloError:\s*/, ''))
    } finally {
      setStopBehaviorPending(false)
    }
  }

  // Live event stream via WebSocket
  const [events, setEvents] = useState<Event[]>([])
  const wsRef = useRef<WebSocket | null>(null)
  const bottomRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const ws = new WebSocket(wsUrl('/ws/events', { node: nodeId }))
    wsRef.current = ws
    ws.onmessage = (e: MessageEvent<string>) => {
      setEvents((prev) => [...prev.slice(-499), { text: e.data, ts: Date.now() }])
    }
    return () => ws.close()
  }, [nodeId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events])

  // Group interfaces that have rules
  const interfaceNames = [...new Set([
    ...interfaces.map((i) => i.name),
    ...rules.map((r) => r.interfaceName),
  ])].sort()

  const tabs: { id: NodeTab; label: string; badge?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'policy', label: 'Policy', badge: rules.length },
    { id: 'events', label: 'Events', badge: events.length > 0 ? events.length : undefined },
    { id: 'rule-lifecycle', label: 'Rule Lifecycle', badge: lifecycleEventCount > 0 ? lifecycleEventCount : undefined },
  ]

  const nodeTitle = node?.label ?? node?.hostname ?? (node ? shortId(node.id) : shortId(nodeId))

  return (
    <div className="flex flex-col h-[calc(100vh-80px)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-3 flex-shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="text-sm text-blue-400 hover:text-blue-300"
          >
            ← Fleet
          </button>
          <h2 className="text-lg font-bold text-gray-50">{nodeTitle}</h2>
          {node?.hostname && node.hostname !== nodeTitle && (
            <span className="text-sm text-gray-400 font-mono" title="Hostname">
              {node.hostname}
            </span>
          )}
          {node && (
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor(node.status)}`}>
              {node.status}
            </span>
          )}
          {(pendingGeneration || localPendingOp) && (
            <span
              className="px-2 py-0.5 rounded text-xs font-medium bg-amber-900/70 text-amber-200 border border-amber-700 animate-pulse"
              title={pendingGeneration
                ? `Awaiting agent confirm for generation ${pendingGeneration.generationId} (${pendingGeneration.opKind})`
                : `Sending ${localPendingOp} to agent…`}
            >
              ⏳ pending confirm ({pendingGeneration?.opKind ?? localPendingOp})
            </span>
          )}
        </div>
        <div className="flex gap-2 items-center">
          {msg && <span className="text-sm text-green-400">{msg}</span>}
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 mb-3 flex-shrink-0 border-b border-gray-700 pb-2">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-1.5 rounded-t text-sm transition-colors ${
              tab === t.id
                ? 'bg-gray-800 text-white border-b-2 border-blue-500'
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
            }`}
          >
            {t.label}
            {t.badge !== undefined && (
              <span className="ml-1.5 px-1.5 py-0.5 text-xs bg-gray-700 rounded-full">{t.badge}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto space-y-4">
        {/* ── Overview tab ─────────────────────────────────────────────── */}
        {tab === 'overview' && (
          <>
            <div className="grid grid-cols-2 gap-4">
              {/* Node info card */}
              <div className="self-start bg-gray-800 rounded-lg p-4 border border-gray-700 space-y-2 text-sm">
                <h3 className="text-sm font-semibold text-gray-300 mb-2">Node Info</h3>
                {node && (
                  <>
                    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
                      {([
                        ['Node ID', node.id],
                        ['Hostname', node.hostname ?? '—'],
                        ['DMI UUID', node.dmiUuid ?? '—'],
                        ['TPM backed', node.tpmBacked ? 'Yes' : 'No'],
                        ['Agent version', node.agentVersion ?? '—'],
                        ['Hardware', [node.dmiSysVendor, node.dmiProductName].filter(Boolean).join(' ') || '—'],
                        ['OS', node.osPrettyName ?? '—'],
                        ['Kernel', node.kernelVersion ?? '—'],
                        ['Last seen', relTime(node.lastSeen)],
                        ['Enrolled at', relTime(node.enrolledAt)],
                        ['Cert expiry', node.certExpiry ? new Date(node.certExpiry).toLocaleDateString() : '—', "Expiry of the node's mTLS client certificate. The agent renews it automatically at around two-thirds of its lifetime, so it should not lapse under normal operation."],
                      ] as [string, string, string?][]).map(([k, v, tip]) => (
                        <div key={k} className="contents">
                          <dt className="text-gray-500" title={tip}>{k}</dt>
                          <dd className="text-gray-200 break-all">{v}</dd>
                        </div>
                      ))}
                    </dl>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-500" title="What the engine does with its BPF programs and maps when the daemon stops — controls whether packet filtering keeps running across a restart. See each option for details.">Stop behavior</span>
                      <span className={`inline-flex rounded overflow-hidden text-xs border border-gray-600 ${stopBehaviorPending ? 'opacity-40 pointer-events-none' : ''}`}>
                        <button
                          onClick={() => handleStopBehaviorChange('clear-state')}
                          disabled={stopBehaviorPending}
                          className={`px-2 py-0.5 ${(node.stopBehavior ?? 'clear-state') === 'clear-state' ? 'bg-blue-700 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
                          title="On shutdown: detaches all XDP/TC programs and removes pinned maps. Next start restores from state.json. Enforcement stops until the daemon restarts. (Default)"
                        >
                          clear-state
                        </button>
                        <button
                          onClick={() => handleStopBehaviorChange('preserve-state')}
                          disabled={stopBehaviorPending}
                          className={`px-2 py-0.5 ${node.stopBehavior === 'preserve-state' ? 'bg-yellow-700 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
                          title="On shutdown: leaves XDP/TC programs attached and maps in the kernel. Enforcement continues with zero gap across daemon restarts. Note: a crash (kill -9) always preserves state regardless of this setting."
                        >
                          preserve-state
                        </button>
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-500" title="How often the node's agent scrapes the local engine and forwards metrics to the controller. Empty = agent default.">
                        Metrics interval
                      </span>
                      <span className="inline-flex items-center gap-1 text-xs">
                        <input
                          type="number"
                          min={5}
                          max={3600}
                          value={metricsInterval}
                          onChange={(e) => setMetricsInterval(e.target.value)}
                          placeholder="default"
                          className="w-20 bg-gray-900 border border-gray-600 rounded px-1 py-0.5 text-gray-200 text-right"
                        />
                        <span className="text-gray-500">s</span>
                        <button
                          onClick={handleSetMetricsInterval}
                          className="px-2 py-0.5 bg-gray-700 text-gray-200 rounded hover:bg-blue-700"
                          title="Apply the metrics scrape interval to this node. Empty reverts to the agent default."
                        >
                          Apply
                        </button>
                      </span>
                    </div>
                  </>
                )}
              </div>

              {/* Interfaces with attachment status */}
              <div className="bg-gray-800 rounded-lg border border-gray-700">
                <div className="px-4 py-2 border-b border-gray-700">
                  <h3 className="text-sm font-semibold text-gray-300">Interfaces</h3>
                </div>
                <InterfaceManager
                  nodeId={nodeId}
                  interfaces={interfaces}
                  rules={rules}
                  onRefetch={() => refetch()}
                  onShowStats={(name) => setStatsIface((prev) => (prev === name ? null : name))}
                  onPendingChange={handlePendingChange}
                />
                {statsIface && (
                  <InterfaceStatsDetail
                    nodeId={nodeId}
                    interfaceName={statsIface}
                    refreshSecs={refreshSecs}
                    onClose={() => setStatsIface(null)}
                  />
                )}
              </div>
            </div>

            {/* Interface traffic stats */}
            <NodeInterfaceStats
              nodeId={nodeId}
              interfaces={interfaces}
              refreshSecs={refreshSecs}
              onShowStats={(name) => setStatsIface((prev) => (prev === name ? null : name))}
            />
          </>
        )}

        {/* ── Policy tab ──────────────────────────────────────────────── */}
        {tab === 'policy' && (
          <>
            <div className="flex justify-end gap-2">
              <button
                onClick={handleClearAllPolicyStats}
                className="text-xs px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300 hover:bg-red-700 hover:text-white"
                title="Clear statistics for every policy rule on this node (both directions)"
              >
                Clear all policy stats
              </button>
            </div>
            {interfaceNames.map((ifaceName) => {
              const iface = interfaces.find((i) => i.name === ifaceName)
              const ifaceRules = rules.filter((r) => r.interfaceName === ifaceName)
              return (
                <div key={ifaceName} className="bg-gray-800 rounded-lg border border-gray-700">
                  <div className="px-4 py-2 border-b border-gray-700 flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-gray-200">
                      {ifaceName}
                      {iface?.tag && (
                        <span className="ml-2 text-xs text-blue-400">({iface.tag})</span>
                      )}
                    </h3>
                  </div>

                  {(['ingress', 'egress'] as const).map((dir, idx) => {
                    const isIngress = dir === 'ingress'
                    const attached = iface ? (isIngress ? iface.xdpAttached : iface.tcAttached) : false
                    const hasRulesForDir = ifaceRules.some((r) => r.direction.toLowerCase() === dir)
                    const pendingAttach = isAttachPending(ifaceName, dir)
                    const defaultAction = isIngress
                      ? (iface?.ingressDefaultAction ?? null)
                      : (iface?.egressDefaultAction ?? null)

                    return (
                      <div key={dir} className={`px-4 py-2${idx === 0 ? ' border-b border-gray-800' : ''}`}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`text-xs font-medium uppercase ${attached ? 'text-gray-400' : 'text-gray-600'}`}>
                              {dir}
                            </span>
                            <DefaultActionToggle
                              current={defaultAction}
                              onSet={(action) =>
                                setInterfaceDefaultAction({
                                  variables: { nodeId, interfaceName: ifaceName, direction: dir, action },
                                }).then(() => refetch())
                              }
                              disabled={!attached}
                            />
                            {/* Attach / detach control */}
                            {iface && (
                              pendingAttach ? (
                                <PolicySpinner />
                              ) : attached ? (
                                <span className="inline-flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" />
                                  <button
                                    onClick={() => handlePolicyDetach(ifaceName, dir)}
                                    className="text-red-500 hover:text-red-400 text-xs leading-none"
                                    title={`Disable ${dir} filtering`}
                                  >
                                    Detach
                                  </button>
                                </span>
                              ) : (
                                <button
                                  onClick={() => handlePolicyAttach(ifaceName, dir)}
                                  className="text-xs text-blue-400 hover:text-blue-300"
                                  title={`Enable ${dir} filtering`}
                                >
                                  Attach
                                </button>
                              )
                            )}
                            {/* Inactive warning: rules exist but no program attached */}
                            {!attached && hasRulesForDir && (
                              <span
                                className="text-xs text-amber-400 bg-amber-900/30 border border-amber-700/50 px-1.5 py-0.5 rounded"
                                title="Rules are stored in BPF maps but are not enforced — attach the program to activate them"
                              >
                                ⚠ inactive
                              </span>
                            )}
                          </div>
                          <button
                            onClick={() => setCreatingRule({ iface: ifaceName, dir })}
                            disabled={isPending || !attached}
                            className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-40 disabled:cursor-not-allowed"
                            title={!attached ? `Attach ${dir} program to add rules` : undefined}
                          >
                            + Add Rule
                          </button>
                        </div>
                        <div className={!attached ? 'opacity-50' : ''}>
                          {creatingRule?.iface === ifaceName && creatingRule.dir === dir && (
                            <RuleCreator
                              nodeId={nodeId}
                              interfaceName={ifaceName}
                              direction={dir}
                              onClose={() => setCreatingRule(null)}
                              onCreated={() => { refetch(); flash('Rule created.') }}
                              onPendingChange={handlePendingChange}
                            />
                          )}
                          <RuleList
                            rules={ifaceRules}
                            direction={dir}
                            nodeId={nodeId}
                            interfaceName={ifaceName}
                            onRefetch={() => refetch()}
                            onFlash={flash}
                            onPendingChange={handlePendingChange}
                            isPending={isPending}
                          />
                        </div>
                      </div>
                    )
                  })}
                </div>
              )
            })}

            {interfaceNames.length === 0 && (
              <div className="text-center py-8 text-gray-600 bg-gray-800/50 rounded-lg border border-gray-700">
                No interfaces or rules for this node yet.
              </div>
            )}
          </>
        )}

        {/* ── Rule Lifecycle tab ──────────────────────────────────────── */}
        {/* Always mounted so the WebSocket stays connected across tab switches */}
        <div className={tab === 'rule-lifecycle' ? '' : 'hidden'}>
          <RuleLifecycleStream nodeId={nodeId} onCountChange={setLifecycleEventCount} />
        </div>

        {/* ── Events tab ──────────────────────────────────────────────── */}
        {tab === 'events' && (
          <div className="bg-gray-900 rounded-lg border border-gray-700 flex flex-col h-full">
            <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700 flex-shrink-0">
              <h3 className="text-sm font-semibold text-gray-300">
                Live BPF Events
                {events.length > 0 && (
                  <span className="ml-2 text-xs text-gray-500 font-normal">{events.length}</span>
                )}
              </h3>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    const hostname = node?.hostname ?? null
                    const jsonArr = events.map((ev) => {
                      let parsed: Record<string, unknown>
                      try { parsed = JSON.parse(ev.text) } catch { parsed = { raw: ev.text, client_ts: ev.ts } }
                      return { node_id: nodeId, hostname, ...parsed }
                    })
                    const blob = new Blob([JSON.stringify(jsonArr, null, 2)], { type: 'application/json' })
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = `events-${nodeId.slice(0, 12)}-${Date.now()}.json`
                    a.click()
                    URL.revokeObjectURL(url)
                    logAuditEntry({
                      variables: {
                        nodeId,
                        action: 'events_exported',
                        detail: `${events.length} events exported`,
                      },
                    })
                  }}
                  className="text-xs text-blue-400 hover:text-blue-300"
                  title="Download events as JSON"
                >
                  Export JSON
                </button>
                <button
                  onClick={() => setEvents([])}
                  className="text-xs text-gray-500 hover:text-gray-300"
                >
                  Clear
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto min-h-[400px]">
              {events.length === 0 ? (
                <div className="text-gray-600 text-sm p-4">Waiting for events...</div>
              ) : (
                <table className="w-full text-xs">
                  <thead className="text-gray-500 uppercase bg-gray-900/80 sticky top-0">
                    <tr>
                      {['Time', 'Dir', 'Proto', 'Source', 'Destination', 'Action', 'Verdict', 'Len'].map((h) => (
                        <th key={h} className="px-2 py-1 text-left font-medium whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((ev, i) => {
                      const parsed = tryParseEvent(ev.text)
                      if (!parsed) {
                        return (
                          <tr key={i} className="border-t border-gray-800">
                            <td className="px-2 py-0.5 text-gray-500">{new Date(ev.ts).toLocaleTimeString()}</td>
                            <td colSpan={7} className="px-2 py-0.5 text-gray-400 font-mono">{ev.text}</td>
                          </tr>
                        )
                      }
                      return (
                        <tr key={i} className="border-t border-gray-800 hover:bg-gray-800/50">
                          <td className="px-2 py-0.5 text-gray-500 whitespace-nowrap">{fmtEventTime(parsed.timestamp_ns)}</td>
                          <td className="px-2 py-0.5">
                            <span className={`text-[10px] font-bold ${parsed.direction === 'INGRESS' ? 'text-cyan-400' : 'text-orange-400'}`}>
                              {parsed.direction === 'INGRESS' ? 'IN' : 'OUT'}
                            </span>
                          </td>
                          <td className="px-2 py-0.5 text-gray-300">
                            {parsed.protocol}
                            {parsed.fragment && <span className="ml-0.5 text-orange-400" title="Fragment">F</span>}
                          </td>
                          <td className="px-2 py-0.5 text-gray-300 font-mono">
                            {parsed.src}{parsed.sport ? `:${parsed.sport}` : ''}
                          </td>
                          <td className="px-2 py-0.5 text-gray-300 font-mono">
                            {parsed.dst}{parsed.dport ? `:${parsed.dport}` : ''}
                            {parsed.sni && <span className="ml-1 text-blue-400" title={`SNI: ${parsed.sni}`}>S</span>}
                          </td>
                          <td className="px-2 py-0.5">
                            <ActionBadge value={parsed.action} />
                          </td>
                          <td className="px-2 py-0.5">
                            <ActionBadge value={parsed.verdict} />
                          </td>
                          <td className="px-2 py-0.5 text-gray-500" title={`Rule ${parsed.rule_id}`}>{parsed.pkt_len}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
              <div ref={bottomRef} />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Event parsing helpers ──────────────────────────────────────────────────

interface ParsedEvent {
  timestamp_ns: number
  rule_id: number
  action: string
  src: string
  dst: string
  sport: number
  dport: number
  protocol: string
  pkt_len: number
  verdict: string
  direction: string
  fragment: boolean
  sni?: string
}

function tryParseEvent(text: string): ParsedEvent | null {
  try {
    const obj = JSON.parse(text)
    if (typeof obj.action === 'string' && typeof obj.src === 'string') {
      return obj as ParsedEvent
    }
    return null
  } catch {
    return null
  }
}

function fmtEventTime(ns: number): string {
  const ms = Math.floor(ns / 1_000_000)
  const d = new Date(ms)
  return d.toLocaleTimeString(undefined, { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0')
}

function ActionBadge({ value }: { value: string }) {
  let color = 'text-gray-400'
  if (value === 'DROP') color = 'text-red-400'
  else if (value === 'PASS') color = 'text-green-400'
  else if (value === 'LOG') color = 'text-yellow-400'
  else if (value === 'INSPECT') color = 'text-purple-400'
  return <span className={`font-medium ${color}`}>{value}</span>
}
