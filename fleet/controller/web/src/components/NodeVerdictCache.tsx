// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState } from 'react'
import { useQuery, gql } from '@apollo/client'
import { fmtBytes, fmtCount } from './types.ts'
import { getProtocolName } from './protocolMappings.ts'

// The flow verdict cache is live BPF state, so this query triggers an on-demand
// request to the node's agent (not a read of the periodic metrics snapshot).
const GET_FLOW_VERDICTS = gql`
  query NodeFlowVerdicts($nodeId: ID!, $direction: String!, $limit: Int) {
    nodeFlowVerdicts(nodeId: $nodeId, direction: $direction, limit: $limit) {
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

interface FlowVerdict {
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

const DEFAULT_LIMIT = 1000

interface Props {
  nodeId: string
}

export default function NodeVerdictCache({ nodeId }: Props) {
  const [direction, setDirection] = useState<'ingress' | 'egress'>('ingress')

  const { data, loading, error, refetch } = useQuery<{ nodeFlowVerdicts: FlowVerdict[] }>(
    GET_FLOW_VERDICTS,
    {
      variables: { nodeId, direction, limit: DEFAULT_LIMIT },
      fetchPolicy: 'network-only',
      notifyOnNetworkStatusChange: true,
    },
  )

  const verdicts = data?.nodeFlowVerdicts ?? []

  return (
    <div className="space-y-3">
      {/* Controls */}
      <div className="flex items-center justify-between">
        <div className="flex gap-1 rounded-lg bg-gray-800 border border-gray-700 p-0.5">
          {(['ingress', 'egress'] as const).map((dir) => (
            <button
              key={dir}
              onClick={() => setDirection(dir)}
              className={`px-3 py-1 rounded text-sm transition-colors ${
                direction === dir
                  ? dir === 'ingress'
                    ? 'bg-cyan-900/60 text-cyan-300'
                    : 'bg-orange-900/60 text-orange-300'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {dir === 'ingress' ? 'Ingress' : 'Egress'}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500">
            {verdicts.length}
            {verdicts.length >= DEFAULT_LIMIT ? `+ (capped at ${DEFAULT_LIMIT})` : ''} entries
          </span>
          <button
            onClick={() => refetch()}
            disabled={loading}
            className="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50"
          >
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {error && (
        <div className="text-sm text-red-400 bg-red-900/30 border border-red-800 rounded-lg px-4 py-2">
          {error.message}
        </div>
      )}

      <div className="bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
        {loading && verdicts.length === 0 ? (
          <div className="text-gray-600 text-sm p-4">Loading verdict cache…</div>
        ) : verdicts.length === 0 && !error ? (
          <div className="text-gray-600 text-sm p-4">Cache is empty.</div>
        ) : (
          <table className="w-full text-xs">
            <thead className="text-gray-500 uppercase bg-gray-900/80 sticky top-0">
              <tr>
                {['Source', 'Destination', 'Proto', 'Action', 'State', 'Packets', 'Bytes'].map((h) => (
                  <th key={h} className="px-3 py-1.5 text-left font-medium whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {verdicts.map((v, i) => (
                <tr
                  key={i}
                  className={`border-t border-gray-800 hover:bg-gray-800/50 ${v.expired ? 'opacity-40' : ''}`}
                >
                  <td className="px-3 py-0.5 text-gray-300 font-mono">{v.srcIp}:{v.srcPort}</td>
                  <td className="px-3 py-0.5 text-gray-300 font-mono">{v.dstIp}:{v.dstPort}</td>
                  <td className="px-3 py-0.5 text-gray-400 uppercase">{getProtocolName(v.protocol)}</td>
                  <td className="px-3 py-0.5">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        v.action === 'DROP'
                          ? 'bg-red-900/60 text-red-300'
                          : v.action === 'PASS'
                            ? 'bg-green-900/60 text-green-300'
                            : 'bg-gray-700 text-gray-300'
                      }`}
                    >
                      {v.action}
                    </span>
                  </td>
                  <td className={`px-3 py-0.5 ${v.expired ? 'text-gray-500' : 'text-green-400'}`}>
                    {v.expired ? 'expired' : 'active'}
                  </td>
                  <td className="px-3 py-0.5 text-gray-300">{fmtCount(v.packets)}</td>
                  <td className="px-3 py-0.5 text-gray-300">{fmtBytes(v.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
