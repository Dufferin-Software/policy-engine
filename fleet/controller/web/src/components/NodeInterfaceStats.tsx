// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState } from 'react'
import { useQuery, useMutation, gql } from '@apollo/client'
import { NodeInterfaceOutput, fmtBytes, fmtCount } from './types.ts'

const CLEAR_ALL_INTERFACE_STATS = gql`
  mutation ClearAllInterfaceStats($nodeId: ID!) {
    clearAllInterfaceStats(nodeId: $nodeId) {
      success
      message
    }
  }
`

const GET_INTERFACE_STATS = gql`
  query NodeInterfaceStats($nodeId: ID!, $interfaceName: String!, $direction: String!) {
    nodeInterfaceStats(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) {
      packets bytes policyDrops
    }
  }
`

interface StatsResult {
  packets: number
  bytes: number
  policyDrops: number
}

function StatRow({
  nodeId,
  interfaceName,
  direction,
  refreshSecs,
  onShowStats,
}: {
  nodeId: string
  interfaceName: string
  direction: 'ingress' | 'egress'
  refreshSecs: number
  onShowStats?: (interfaceName: string) => void
}) {
  const { data, loading } = useQuery<{ nodeInterfaceStats: StatsResult | null }>(
    GET_INTERFACE_STATS,
    { variables: { nodeId, interfaceName, direction }, pollInterval: refreshSecs * 1_000 },
  )
  const s = data?.nodeInterfaceStats

  return (
    <tr className="border-t border-gray-800">
      <td className="px-3 py-1 font-mono text-xs">
        {onShowStats ? (
          <button
            onClick={() => onShowStats(interfaceName)}
            className="text-cyan-400 hover:text-cyan-200 hover:underline"
            title="Show detailed stats"
          >
            {interfaceName}
          </button>
        ) : (
          <span className="text-gray-300">{interfaceName}</span>
        )}
      </td>
      {loading && !s ? (
        <td colSpan={3} className="px-3 py-1 text-xs text-gray-600">…</td>
      ) : !s ? (
        <td colSpan={3} className="px-3 py-1 text-xs text-gray-600">no data</td>
      ) : (
        <>
          <td className="px-3 py-1 text-xs text-gray-300">{fmtCount(s.packets)}</td>
          <td className="px-3 py-1 text-xs text-gray-300">{fmtBytes(s.bytes)}</td>
          <td className={`px-3 py-1 text-xs ${s.policyDrops > 0 ? 'text-red-400' : 'text-gray-600'}`}>
            {fmtCount(s.policyDrops)}
          </td>
        </>
      )}
    </tr>
  )
}

interface Props {
  nodeId: string
  interfaces: NodeInterfaceOutput[]
  refreshSecs: number
  onShowStats?: (interfaceName: string) => void
}

export default function NodeInterfaceStats({ nodeId, interfaces, refreshSecs, onShowStats }: Props) {
  const [clearAllInterfaceStats, { loading: clearing }] = useMutation(CLEAR_ALL_INTERFACE_STATS, {
    refetchQueries: ['NodeInterfaceStats', 'NodeInterfaceStatsDetail', 'NodeEthertypeStats'],
  })
  const [feedback, setFeedback] = useState<string | null>(null)

  if (interfaces.length === 0) return null

  const handleClearAll = async () => {
    if (!window.confirm('Clear interface statistics for every attached interface on this node?')) return
    try {
      const res = await clearAllInterfaceStats({ variables: { nodeId } })
      const r = res.data?.clearAllInterfaceStats
      // Success is assumed silently; only surface failures.
      setFeedback(r?.success ? null : (r?.message ?? 'Failed to clear stats'))
    } catch (e) {
      setFeedback(e instanceof Error ? e.message : 'Failed to clear stats')
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-end gap-3">
        {feedback && <span className="text-xs text-gray-400">{feedback}</span>}
        <button
          onClick={handleClearAll}
          disabled={clearing}
          className="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300 hover:bg-red-700 hover:text-white disabled:opacity-50"
          title="Clear interface statistics for every attached interface on this node"
        >
          {clearing ? 'Clearing…' : 'Clear all interface stats'}
        </button>
      </div>
      <div className="grid grid-cols-2 gap-4">
      {(['ingress', 'egress'] as const).map((dir) => (
        <div key={dir} className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="px-4 py-2 border-b border-gray-700 flex items-center justify-between">
            <h3 className={`text-sm font-semibold ${dir === 'ingress' ? 'text-cyan-400' : 'text-orange-400'}`}>
              {dir === 'ingress' ? 'Ingress Traffic' : 'Egress Traffic'}
            </h3>
            <span className="text-xs text-gray-600">{refreshSecs}s refresh</span>
          </div>
          <table className="w-full">
            <thead className="text-gray-500 uppercase bg-gray-900/50">
              <tr>
                {['Interface', dir === 'ingress' ? 'RX Packets' : 'TX Packets', dir === 'ingress' ? 'RX Bytes' : 'TX Bytes', 'Drops'].map((h) => (
                  <th key={h} className="px-3 py-1 text-left text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {interfaces.map((iface) => (
                <StatRow
                  key={iface.name}
                  nodeId={nodeId}
                  interfaceName={iface.name}
                  direction={dir}
                  refreshSecs={refreshSecs}
                  onShowStats={onShowStats}
                />
              ))}
            </tbody>
          </table>
        </div>
      ))}
      </div>
    </div>
  )
}
