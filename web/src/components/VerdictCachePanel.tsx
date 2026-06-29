// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useState } from 'react'
import { gql, useQuery, useMutation } from '@apollo/client'
import { getProtocolName } from './protocolMappings'

/** Format a byte count as a human-readable string (e.g. 1.2 MB). */
function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

const VERDICT_STATS = gql`
  query FlowVerdictStats {
    ingress: flowVerdicts(direction: INGRESS) {
      activeVerdicts
    }
    egress: flowVerdicts(direction: EGRESS) {
      activeVerdicts
    }
  }
`

const LIST_FLOW_VERDICTS = gql`
  query ListFlowVerdicts($direction: GqlDirection!) {
    flowVerdictList(direction: $direction) {
      srcIp
      dstIp
      srcPort
      dstPort
      protocol
      action
      expiresNs
      expired
      packets
      bytes
    }
  }
`

const CLEAR_FLOW_VERDICTS = gql`
  mutation ClearFlowVerdicts($direction: GqlDirection!) {
    clearFlowVerdicts(direction: $direction) {
      success
      message
    }
  }
`

type Direction = 'INGRESS' | 'EGRESS'

interface OperationResult {
  success: boolean
  message: string
}

interface FlowVerdictEntry {
  srcIp: string
  dstIp: string
  srcPort: number
  dstPort: number
  protocol: string
  action: string
  expiresNs: string
  expired: boolean
  packets: number
  bytes: number
}

interface FlowVerdictListData {
  flowVerdictList: FlowVerdictEntry[]
}

interface FlowVerdictStatsData {
  ingress: { activeVerdicts: number }
  egress: { activeVerdicts: number }
}

/**
 * Standalone view of the L4 flow verdict cache. The cache is seeded by the plain
 * policy datapath (not just IPS/IDS), so this panel is shown on every build
 * regardless of whether the inspection feature is compiled in.
 */
export function VerdictCachePanel() {
  const [direction, setDirection] = useState<Direction>('INGRESS')
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  )

  const { data: statsData, refetch: refetchStats } = useQuery<FlowVerdictStatsData>(VERDICT_STATS, {
    pollInterval: 3000,
  })

  const { data: verdictData, refetch: refetchVerdicts } = useQuery<FlowVerdictListData>(
    LIST_FLOW_VERDICTS,
    { variables: { direction }, pollInterval: 3000 }
  )

  const [clearFlowVerdicts, { loading: clearing }] = useMutation<{
    clearFlowVerdicts: OperationResult
  }>(CLEAR_FLOW_VERDICTS)

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message })
    setTimeout(() => setFeedback(null), 5000)
  }

  const handleClear = async (dir: Direction) => {
    try {
      const { data: r } = await clearFlowVerdicts({ variables: { direction: dir } })
      const result = r?.clearFlowVerdicts
      if (result?.success) {
        showFeedback('success', result.message)
      } else {
        showFeedback('error', result?.message ?? 'Failed to clear verdicts')
      }
      refetchStats()
      refetchVerdicts()
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const verdicts = verdictData?.flowVerdictList ?? []
  const ingressCount = statsData?.ingress.activeVerdicts ?? 0
  const egressCount = statsData?.egress.activeVerdicts ?? 0

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Flow Verdict Cache</h2>
        <div className="flex gap-4 text-sm">
          <span>
            <span className="text-gray-400">Ingress: </span>
            <span className="font-semibold text-blue-400">{ingressCount.toLocaleString()}</span>
          </span>
          <span>
            <span className="text-gray-400">Egress: </span>
            <span className="font-semibold text-blue-400">{egressCount.toLocaleString()}</span>
          </span>
        </div>
      </div>

      {/* Feedback banner */}
      {feedback && (
        <div
          className={`p-3 rounded text-sm ${
            feedback.type === 'success'
              ? 'bg-green-500/20 text-green-400'
              : 'bg-red-500/20 text-red-400'
          }`}
        >
          {feedback.message}
        </div>
      )}

      {/* Direction selector */}
      <div className="flex gap-2">
        {(['INGRESS', 'EGRESS'] as Direction[]).map((dir) => (
          <button
            key={dir}
            onClick={() => setDirection(dir)}
            className={`px-3 py-1 rounded text-sm font-medium transition ${
              direction === dir
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            {dir === 'INGRESS' ? 'Ingress' : 'Egress'}
          </button>
        ))}
      </div>

      {/* Verdict list */}
      {verdicts.length === 0 ? (
        <p className="text-sm text-gray-500">No cached verdicts.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-gray-400 border-b border-gray-700">
                <th className="text-left py-1 pr-3">Src IP</th>
                <th className="text-left py-1 pr-3">Dst IP</th>
                <th className="text-left py-1 pr-3">Sport</th>
                <th className="text-left py-1 pr-3">Dport</th>
                <th className="text-left py-1 pr-3">Proto</th>
                <th className="text-left py-1 pr-3">Action</th>
                <th className="text-right py-1 pr-3">Packets</th>
                <th className="text-right py-1 pr-3">Bytes</th>
                <th className="text-left py-1">Status</th>
              </tr>
            </thead>
            <tbody>
              {verdicts.map((v, i) => (
                <tr
                  key={i}
                  className={`border-b border-gray-700/50 ${v.expired ? 'opacity-40' : ''}`}
                >
                  <td className="py-1 pr-3 text-blue-300">{v.srcIp}</td>
                  <td className="py-1 pr-3 text-blue-300">{v.dstIp}</td>
                  <td className="py-1 pr-3 text-gray-300">{v.srcPort}</td>
                  <td className="py-1 pr-3 text-gray-300">{v.dstPort}</td>
                  <td className="py-1 pr-3 text-gray-300">{getProtocolName(v.protocol)}</td>
                  <td className="py-1 pr-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-xs font-semibold ${
                        v.action === 'DROP'
                          ? 'bg-red-500/20 text-red-400'
                          : v.action === 'PASS'
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-gray-500/20 text-gray-400'
                      }`}
                    >
                      {v.action}
                    </span>
                  </td>
                  <td className="py-1 pr-3 text-right text-gray-300">
                    {v.packets.toLocaleString()}
                  </td>
                  <td className="py-1 pr-3 text-right text-gray-300">{fmtBytes(v.bytes)}</td>
                  <td className="py-1">
                    <span className={v.expired ? 'text-gray-500' : 'text-green-400'}>
                      {v.expired ? 'expired' : 'active'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-xs text-gray-500">
        Clear to force re-evaluation of cached flows against current policy.
      </p>
      <div className="flex gap-3">
        <button
          onClick={() => handleClear('INGRESS')}
          disabled={clearing}
          className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded text-sm font-medium transition"
        >
          {clearing ? 'Clearing...' : 'Clear Ingress'}
        </button>
        <button
          onClick={() => handleClear('EGRESS')}
          disabled={clearing}
          className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded text-sm font-medium transition"
        >
          {clearing ? 'Clearing...' : 'Clear Egress'}
        </button>
      </div>
    </div>
  )
}
