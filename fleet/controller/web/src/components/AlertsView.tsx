// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useEffect, useRef, useState } from 'react'
import { gql, useQuery, useMutation } from '@apollo/client'
import { getToken } from '../lib/auth'

const ALERTS_QUERY = gql`
  query SuricataAlerts($filter: SuricataAlertFilterInput, $limit: Int) {
    suricataAlerts(filter: $filter, limit: $limit) {
      id nodeId timestamp srcIp srcPort destIp destPort
      protocol action signatureId signature category severity acked
    }
  }
`

const ACK_ALERTS = gql`
  mutation AckSuricataAlerts($nodeId: ID) {
    ackSuricataAlerts(nodeId: $nodeId) {
      success
      message
    }
  }
`

interface Alert {
  id: string
  nodeId: string
  timestamp: string
  srcIp: string | null
  srcPort: number | null
  destIp: string | null
  destPort: number | null
  protocol: string | null
  action: string | null
  signatureId: number | null
  signature: string | null
  category: string | null
  severity: number | null
  acked: boolean
}

/** Suricata severity: 1 = most urgent. Map to a palette color family. */
function severityClass(sev: number | null): string {
  switch (sev) {
    case 1:
      return 'text-red-400'
    case 2:
      return 'text-orange-400'
    case 3:
      return 'text-yellow-400'
    default:
      return 'text-gray-400'
  }
}

/** Build a live WebSocket alert row from a wire frame (node_id injected server-side). */
function normalizeLive(w: Record<string, unknown>): Alert {
  const info = (w.alert as Record<string, unknown> | undefined) ?? {}
  return {
    id: `live-${Math.random().toString(36).slice(2)}`,
    nodeId: String(w.node_id ?? ''),
    timestamp: String(w.timestamp ?? ''),
    srcIp: (w.src_ip as string) ?? null,
    srcPort: (w.src_port as number) ?? null,
    destIp: (w.dest_ip as string) ?? null,
    destPort: (w.dest_port as number) ?? null,
    protocol: (w.proto as string) ?? null,
    action: (info.action as string) ?? null,
    signatureId: (info.signature_id as number) ?? null,
    signature: (info.signature as string) ?? null,
    category: (info.category as string) ?? null,
    severity: (info.severity as number) ?? null,
    acked: false,
  }
}

export default function AlertsView() {
  const [nodeFilter, setNodeFilter] = useState('')
  const [minSeverity, setMinSeverity] = useState('')
  const [showAcked, setShowAcked] = useState(false)
  const [live, setLive] = useState<Alert[]>([])
  const [connected, setConnected] = useState(false)

  const filter: Record<string, unknown> = {}
  if (nodeFilter.trim()) filter.nodeId = nodeFilter.trim()
  if (minSeverity.trim()) filter.minSeverity = parseInt(minSeverity, 10)
  if (showAcked) filter.includeAcked = true

  const { data, refetch } = useQuery<{ suricataAlerts: Alert[] }>(ALERTS_QUERY, {
    variables: { filter, limit: 200 },
    fetchPolicy: 'cache-and-network',
  })
  const [ackAlerts] = useMutation(ACK_ALERTS)

  // "Clear" acknowledges (hides) alerts; nothing is deleted, and the
  // retention sweep removes stored alerts on its own schedule.
  const onClear = async () => {
    const node = nodeFilter.trim()
    await ackAlerts({ variables: { nodeId: node || null } })
    setLive([])
    refetch()
  }

  // Live tail over the raw /ws/alerts WebSocket.
  const wsRef = useRef<WebSocket | null>(null)
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const token = getToken()
    const url = `${proto}://${window.location.host}/ws/alerts${token ? `?token=${encodeURIComponent(token)}` : ''}`
    const ws = new WebSocket(url)
    wsRef.current = ws
    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onmessage = (ev) => {
      try {
        const w = JSON.parse(ev.data)
        const row = normalizeLive(w)
        if (nodeFilter.trim() && row.nodeId !== nodeFilter.trim()) return
        if (minSeverity.trim() && (row.severity ?? 99) > parseInt(minSeverity, 10)) return
        setLive((prev) => [row, ...prev].slice(0, 200))
      } catch {
        /* ignore malformed frames */
      }
    }
    return () => ws.close()
  }, [nodeFilter, minSeverity])

  const historical = data?.suricataAlerts ?? []
  // Live rows first, then history; de-dup is unnecessary (live ids are synthetic).
  const rows = [...live, ...historical].slice(0, 400)

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs">
        <span className="text-gray-500">IDS Alerts</span>
        <span
          className={`inline-flex items-center gap-1 ${connected ? 'text-green-400' : 'text-gray-600'}`}
          title={connected ? 'Live stream connected' : 'Live stream disconnected'}
        >
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400' : 'bg-gray-600'}`} />
          {connected ? 'live' : 'offline'}
        </span>
        <input
          value={nodeFilter}
          onChange={(e) => setNodeFilter(e.target.value)}
          placeholder="node id"
          className="ml-auto w-40 bg-gray-900 border border-gray-600 rounded px-2 py-0.5 text-gray-200 font-mono"
        />
        <select
          value={minSeverity}
          onChange={(e) => setMinSeverity(e.target.value)}
          className="bg-gray-900 border border-gray-600 rounded px-1 py-0.5 text-gray-200"
        >
          <option value="">any severity</option>
          <option value="1">sev ≤ 1 (critical)</option>
          <option value="2">sev ≤ 2 (high)</option>
          <option value="3">sev ≤ 3 (medium)</option>
        </select>
        <button
          onClick={() => {
            setLive([])
            refetch()
          }}
          className="px-2 py-0.5 rounded bg-gray-700 text-gray-200 hover:bg-blue-700"
        >
          Refresh
        </button>
        <button
          onClick={onClear}
          title={
            nodeFilter.trim()
              ? 'Acknowledge all alerts for the filtered node (kept in history)'
              : 'Acknowledge all alerts (kept in history)'
          }
          className="px-2 py-0.5 rounded bg-gray-700 text-gray-200 hover:bg-blue-700"
        >
          Clear
        </button>
        <label className="flex items-center gap-1 text-gray-500 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showAcked}
            onChange={(e) => setShowAcked(e.target.checked)}
          />
          show acked
        </label>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="text-gray-500 uppercase bg-gray-900/50">
            <tr>
              {['Time', 'Sev', 'SID', 'Signature', 'Flow', 'Proto', 'Action', 'Node'].map((h) => (
                <th key={h} className="px-2 py-1 text-left font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="px-2 py-6 text-center text-gray-600">
                  No alerts.
                </td>
              </tr>
            )}
            {rows.map((a) => (
              <tr key={a.id} className={`border-t border-gray-800 ${a.acked ? 'opacity-50' : ''}`}>
                <td className="px-2 py-1 font-mono text-gray-400 whitespace-nowrap">
                  {a.timestamp}
                </td>
                <td className={`px-2 py-1 font-bold ${severityClass(a.severity)}`}>
                  {a.severity ?? '—'}
                </td>
                <td className="px-2 py-1 font-mono text-gray-400">{a.signatureId ?? '—'}</td>
                <td className="px-2 py-1 text-gray-200">{a.signature ?? '—'}</td>
                <td className="px-2 py-1 font-mono text-gray-400 whitespace-nowrap">
                  {a.srcIp ?? '?'}:{a.srcPort ?? 0} → {a.destIp ?? '?'}:{a.destPort ?? 0}
                </td>
                <td className="px-2 py-1 text-gray-400">{a.protocol ?? '—'}</td>
                <td className="px-2 py-1">
                  {a.action ? (
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        a.action === 'blocked'
                          ? 'bg-red-900/60 text-red-300'
                          : 'bg-gray-700 text-gray-300'
                      }`}
                    >
                      {a.action}
                    </span>
                  ) : (
                    <span className="text-gray-400">—</span>
                  )}
                </td>
                <td className="px-2 py-1 font-mono text-gray-500">{a.nodeId.slice(0, 12)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
