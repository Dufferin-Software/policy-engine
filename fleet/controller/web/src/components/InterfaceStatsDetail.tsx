// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useState } from 'react'
import { useQuery, useMutation, gql } from '@apollo/client'
import { fmtBytes, fmtCount } from './types.ts'

const CLEAR_INTERFACE_STATS = gql`
  mutation ClearInterfaceStats($nodeId: ID!, $interfaceName: String!) {
    clearInterfaceStats(nodeId: $nodeId, interfaceName: $interfaceName) {
      success
      message
    }
  }
`

const GET_INTERFACE_STATS = gql`
  query NodeInterfaceStatsDetail($nodeId: ID!, $interfaceName: String!, $direction: String!) {
    nodeInterfaceStats(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) {
      interface direction
      packets bytes txPackets txBytes
      policyMatches policyDrops policyPass policyRedirects
      bumPackets nonIpUnicast fragments parseErrors tailCalls inspectRedirects
      verdictPassPackets verdictPassBytes verdictDropPackets verdictDropBytes
      fibForwardedPackets fibForwardedBytes fibFallbackPackets
    }
  }
`

const GET_ETHERTYPE_STATS = gql`
  query NodeEthertypeStats($nodeId: ID!, $interfaceName: String!, $direction: String!) {
    nodeEthertypeStats(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) {
      ethertype name packets
    }
  }
`

interface FullStats {
  interface: string
  direction: string
  packets: number
  bytes: number
  txPackets: number
  txBytes: number
  policyMatches: number
  policyDrops: number
  policyPass: number
  policyRedirects: number
  bumPackets: number
  nonIpUnicast: number
  fragments: number
  parseErrors: number
  tailCalls: number
  inspectRedirects: number
  verdictPassPackets: number
  verdictPassBytes: number
  verdictDropPackets: number
  verdictDropBytes: number
  fibForwardedPackets: number
  fibForwardedBytes: number
  fibFallbackPackets: number
}

interface EthertypeStat {
  ethertype: number
  name: string
  packets: number
}

function StatSection({ title, rows }: { title: string; rows: [string, string][] }) {
  const hasData = rows.some(([, v]) => v !== '0' && v !== '0B')
  return (
    <div className="mb-3">
      <div className={`text-[10px] font-semibold uppercase tracking-wider mb-1 ${hasData ? 'text-gray-400' : 'text-gray-600'}`}>
        {title}
      </div>
      <table className="w-full">
        <tbody>
          {rows.map(([label, value]) => (
            <tr key={label}>
              <td className="text-gray-500 text-xs py-0.5 pr-2 whitespace-nowrap">{label}</td>
              <td className={`text-xs py-0.5 font-mono ${value === '0' || value === '0B' ? 'text-gray-700' : 'text-gray-200'}`}>
                {value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function DirectionPanel({
  nodeId,
  interfaceName,
  direction,
}: {
  nodeId: string
  interfaceName: string
  direction: 'ingress' | 'egress'
}) {
  const isIngress = direction === 'ingress'
  const { data: statsData, loading: statsLoading } = useQuery<{ nodeInterfaceStats: FullStats | null }>(
    GET_INTERFACE_STATS,
    { variables: { nodeId, interfaceName, direction }, pollInterval: 30_000 },
  )
  const { data: etData } = useQuery<{ nodeEthertypeStats: EthertypeStat[] }>(
    GET_ETHERTYPE_STATS,
    { variables: { nodeId, interfaceName, direction }, pollInterval: 30_000 },
  )

  const s = statsData?.nodeInterfaceStats
  const ethertypes = etData?.nodeEthertypeStats ?? []

  const dirColor = isIngress ? 'text-cyan-400' : 'text-orange-400'

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-3">
      <div className={`text-xs font-semibold uppercase mb-3 ${dirColor}`}>
        {isIngress ? 'Ingress' : 'Egress'}
        <span className="ml-2 text-gray-600 font-normal normal-case">30s refresh</span>
      </div>

      {statsLoading && !s ? (
        <div className="text-xs text-gray-600">Loading…</div>
      ) : !s ? (
        <div className="text-xs text-gray-600">No metrics data yet</div>
      ) : (
        <>
          <StatSection
            title="Traffic"
            rows={[
              [isIngress ? 'RX Packets' : 'TX Packets', fmtCount(isIngress ? s.packets : s.txPackets)],
              [isIngress ? 'RX Bytes' : 'TX Bytes', fmtBytes(isIngress ? s.bytes : s.txBytes)],
            ]}
          />
          <StatSection
            title="Policy"
            rows={[
              ['Pass', fmtCount(s.policyPass)],
              ['Drops', fmtCount(s.policyDrops)],
              ['Matches', fmtCount(s.policyMatches)],
              ['Redirects', fmtCount(s.policyRedirects)],
            ]}
          />
          <StatSection
            title="Processing"
            rows={[
              ['BUM Packets', fmtCount(s.bumPackets)],
              ['Non-IP Unicast', fmtCount(s.nonIpUnicast)],
              ['Fragments', fmtCount(s.fragments)],
              ['Parse Errors', fmtCount(s.parseErrors)],
              ['Tail Calls', fmtCount(s.tailCalls)],
              ...(s.inspectRedirects > 0 ? [['Inspect Redirects', fmtCount(s.inspectRedirects)] as [string, string]] : []),
            ]}
          />
          {(s.verdictPassPackets > 0 || s.verdictDropPackets > 0) && (
            <StatSection
              title="Verdicts"
              rows={[
                ['Pass Pkts', fmtCount(s.verdictPassPackets)],
                ['Pass Bytes', fmtBytes(s.verdictPassBytes)],
                ['Drop Pkts', fmtCount(s.verdictDropPackets)],
                ['Drop Bytes', fmtBytes(s.verdictDropBytes)],
              ]}
            />
          )}
          {(s.fibForwardedPackets > 0 || s.fibFallbackPackets > 0) && (
            <StatSection
              title="FIB"
              rows={[
                ['Forwarded Pkts', fmtCount(s.fibForwardedPackets)],
                ['Forwarded Bytes', fmtBytes(s.fibForwardedBytes)],
                ['Fallback Pkts', fmtCount(s.fibFallbackPackets)],
              ]}
            />
          )}
        </>
      )}

      {ethertypes.length > 0 && (
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-1">
            Ethertype Breakdown
          </div>
          <table className="w-full">
            <thead>
              <tr>
                <th className="text-left text-[10px] text-gray-600 font-medium pb-0.5">Type</th>
                <th className="text-right text-[10px] text-gray-600 font-medium pb-0.5">Packets</th>
              </tr>
            </thead>
            <tbody>
              {ethertypes.map((et) => (
                <tr key={et.ethertype}>
                  <td className="text-xs text-gray-300 py-0.5">
                    {et.name}
                    <span className="ml-1 text-gray-600 text-[10px]">{et.ethertype}</span>
                  </td>
                  <td className="text-xs text-gray-300 py-0.5 text-right font-mono">{fmtCount(et.packets)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

interface Props {
  nodeId: string
  interfaceName: string
  onClose: () => void
}

export default function InterfaceStatsDetail({ nodeId, interfaceName, onClose }: Props) {
  // Stats are scraped from the node's engine, so cleared counters appear on the
  // next metrics refresh rather than instantly. We refetch the stats queries to
  // pick up the update as soon as the agent's next scrape lands.
  const [clearInterfaceStats, { loading: clearing }] = useMutation(CLEAR_INTERFACE_STATS, {
    refetchQueries: ['NodeInterfaceStatsDetail', 'NodeEthertypeStats', 'NodeInterfaceStats'],
  })
  const [feedback, setFeedback] = useState<string | null>(null)

  const handleClear = async () => {
    if (!window.confirm(`Clear all statistics for ${interfaceName} (both directions)?`)) return
    try {
      const res = await clearInterfaceStats({ variables: { nodeId, interfaceName } })
      const r = res.data?.clearInterfaceStats
      setFeedback(r?.success ? 'Cleared — updating on next refresh' : (r?.message ?? 'Failed to clear stats'))
    } catch (e) {
      setFeedback(e instanceof Error ? e.message : 'Failed to clear stats')
    }
  }

  return (
    <div className="mt-3 bg-gray-900 border border-gray-700 rounded-lg">
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700">
        <h3 className="text-sm font-semibold text-gray-200">
          Stats: <span className="font-mono text-gray-100">{interfaceName}</span>
        </h3>
        <div className="flex items-center gap-3">
          {feedback && <span className="text-xs text-gray-400">{feedback}</span>}
          <button
            onClick={handleClear}
            disabled={clearing}
            className="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300 hover:bg-red-700 hover:text-white disabled:opacity-50"
            title="Clear all statistics (global + ethertype) for this interface, both directions"
          >
            {clearing ? 'Clearing…' : 'Clear stats'}
          </button>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-sm">&times;</button>
        </div>
      </div>
      <div className="p-3 grid grid-cols-2 gap-3">
        <DirectionPanel nodeId={nodeId} interfaceName={interfaceName} direction="ingress" />
        <DirectionPanel nodeId={nodeId} interfaceName={interfaceName} direction="egress" />
      </div>
    </div>
  )
}
