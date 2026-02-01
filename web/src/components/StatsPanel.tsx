// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { gql, useQuery, useMutation } from '@apollo/client'
import { useState, useEffect } from 'react'

const GET_STATS = gql`
  query GetStats($interface: String!, $direction: GqlDirection!) {
    stats(interface: $interface, direction: $direction) {
      rxPackets
      rxBytes
      txPackets
      txBytes
      policyMatches
      policyDrops
      policyPass
      policyRedirects
      inspectRedirects
      parseErrors
      tailCalls
      bumPackets
      nonIpUnicast
      verdictPassPackets
      verdictPassBytes
      verdictDropPackets
      verdictDropBytes
      fibForwardedPackets
      fibForwardedBytes
      fibFallbackPackets
    }
  }
`

const GET_ETHERTYPE_STATS = gql`
  query GetEthertypeStatsPanel($interface: String!, $direction: GqlDirection!) {
    ethertypeStats(interface: $interface, direction: $direction) {
      ethertype
      name
      packets
    }
  }
`

const GET_NONIP_SENDERS = gql`
  query GetNonIpSenders($interface: String!) {
    nonipSenders(interface: $interface) {
      mac
      ethertype
      name
      packets
    }
  }
`

const GET_INTERFACES = gql`
  query GetInterfacesForStats {
    interfaces {
      interface
      mode
      direction
    }
  }
`

const CLEAR_INTERFACE_STATS = gql`
  mutation ClearInterfaceStats($interface: String!, $direction: GqlDirection!) {
    clearInterfaceStats(interface: $interface, direction: $direction) {
      success
      message
    }
  }
`

const CLEAR_ETHERTYPE_STATS = gql`
  mutation ClearEthertypeStats($interface: String!, $direction: GqlDirection!) {
    clearEthertypeStats(interface: $interface, direction: $direction) {
      success
      message
    }
  }
`

interface GlobalStats {
  rxPackets: number
  rxBytes: number
  txPackets: number
  txBytes: number
  policyMatches: number
  policyDrops: number
  policyPass: number
  policyRedirects: number
  inspectRedirects: number
  parseErrors: number
  tailCalls: number
  bumPackets: number
  nonIpUnicast: number
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

interface NonIpSender {
  mac: string
  ethertype: number
  name: string
  packets: number
}

interface StatsData {
  stats: GlobalStats
}

interface EthertypeStatsData {
  ethertypeStats: EthertypeStat[]
}

interface NonIpSendersData {
  nonipSenders: NonIpSender[]
}

interface InterfacesData {
  interfaces: { interface: string; mode: string; direction: string }[]
}

interface OperationResult {
  success: boolean
  message: string
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function formatNumber(num: number): string {
  return num.toLocaleString()
}

function toHex(ethertype: number): string {
  return '0x' + ethertype.toString(16).toUpperCase().padStart(4, '0')
}

function DirectionStatsPane({
  iface,
  direction,
  accent,
}: {
  iface: string
  direction: 'INGRESS' | 'EGRESS'
  accent: 'blue' | 'purple'
}) {
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  )
  const [view, setView] = useState<'stats' | 'l2'>('stats')
  const isEgress = direction === 'EGRESS'

  const { loading, error, data } = useQuery<StatsData>(GET_STATS, {
    variables: { interface: iface, direction },
    pollInterval: 2000,
  })

  const { data: ethData } = useQuery<EthertypeStatsData>(GET_ETHERTYPE_STATS, {
    variables: { interface: iface, direction },
    pollInterval: 2000,
    skip: isEgress,
  })

  const { data: sendersData } = useQuery<NonIpSendersData>(GET_NONIP_SENDERS, {
    variables: { interface: iface },
    pollInterval: 2000,
    skip: isEgress,
  })

  const [clearStats] = useMutation<{ clearInterfaceStats: OperationResult }>(CLEAR_INTERFACE_STATS)
  const [clearEthStats] = useMutation<{ clearEthertypeStats: OperationResult }>(
    CLEAR_ETHERTYPE_STATS
  )

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message })
    setTimeout(() => setFeedback(null), 5000)
  }

  const handleClear = async () => {
    try {
      const result = await clearStats({ variables: { interface: iface, direction } })
      if (result.data?.clearInterfaceStats.success) {
        showFeedback('success', result.data.clearInterfaceStats.message)
      }
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const handleClearEth = async () => {
    try {
      const result = await clearEthStats({ variables: { interface: iface, direction } })
      if (result.data?.clearEthertypeStats.success) {
        showFeedback('success', result.data.clearEthertypeStats.message)
      }
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const accentClasses = {
    blue: { header: 'text-blue-400', border: 'border-blue-500/30', bg: 'bg-blue-500/10' },
    purple: { header: 'text-purple-400', border: 'border-purple-500/30', bg: 'bg-purple-500/10' },
  }

  const colors = accentClasses[accent]

  const ethRows = [...(ethData?.ethertypeStats ?? [])]
    .filter((e) => e.packets > 0)
    .sort((a, b) => b.packets - a.packets)

  const senderRows = [...(sendersData?.nonipSenders ?? [])].sort((a, b) => b.packets - a.packets)

  return (
    <div className={`rounded-lg border ${colors.border} ${colors.bg} p-4 space-y-4`}>
      {/* Direction header + view toggle + clear */}
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-3">
          <h3 className={`text-lg font-semibold ${colors.header}`}>{direction}</h3>
          {!isEgress && (
            <div className="flex rounded overflow-hidden border border-gray-600 text-xs">
              <button
                onClick={() => setView('stats')}
                className={`px-2 py-0.5 transition ${view === 'stats' ? 'bg-gray-600 text-white' : 'text-gray-400 hover:text-white'}`}
              >
                Stats
              </button>
              <button
                onClick={() => setView('l2')}
                className={`px-2 py-0.5 transition ${view === 'l2' ? 'bg-gray-600 text-white' : 'text-gray-400 hover:text-white'}`}
              >
                L2
              </button>
            </div>
          )}
        </div>
        <button
          onClick={handleClear}
          className="px-2 py-1 text-xs bg-yellow-500/20 text-yellow-400 rounded hover:bg-yellow-500/30 transition"
        >
          Clear stats
        </button>
      </div>

      {feedback && (
        <div
          className={`p-2 rounded text-sm ${
            feedback.type === 'success'
              ? 'bg-green-500/20 text-green-400'
              : 'bg-red-500/20 text-red-400'
          }`}
        >
          {feedback.message}
        </div>
      )}

      {loading && !data ? (
        <div className="animate-pulse grid grid-cols-2 gap-2">
          {Array(6)
            .fill(0)
            .map((_, i) => (
              <div key={i} className="h-14 bg-gray-700/50 rounded"></div>
            ))}
        </div>
      ) : error ? (
        <p className="text-red-400 text-sm">Error: {error.message}</p>
      ) : data?.stats ? (
        <>
          {/* L2 view — ingress only */}
          {!isEgress && view === 'l2' && (
            <NonIpSection ethRows={ethRows} senderRows={senderRows} onClear={handleClearEth} />
          )}

          {/* Stats view */}
          {(isEgress || view === 'stats') && <>
          {/* Traffic */}
          <div>
            <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">Traffic</p>
            <div className="grid grid-cols-2 gap-2">
              <StatCard label="RX Packets" value={formatNumber(data.stats.rxPackets)} />
              <StatCard label="RX Bytes" value={formatBytes(data.stats.rxBytes)} />
              <StatCard label="TX Packets" value={formatNumber(data.stats.txPackets)} />
              <StatCard label="TX Bytes" value={formatBytes(data.stats.txBytes)} />
            </div>
          </div>

          {/* Policy */}
          <div>
            <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">Policy</p>
            <div className="grid grid-cols-2 gap-2">
              <StatCard label="Matches" value={formatNumber(data.stats.policyMatches)} color="blue" />
              <StatCard label="Drops" value={formatNumber(data.stats.policyDrops)} color="red" />
              <StatCard label="Pass" value={formatNumber(data.stats.policyPass)} color="green" />
              <StatCard
                label="Redirects"
                value={formatNumber(data.stats.policyRedirects)}
                color="yellow"
              />
              <StatCard
                label="Inspect Redirects"
                value={formatNumber(data.stats.inspectRedirects)}
                color="yellow"
              />
            </div>
          </div>

          {/* Flow Verdict Cache */}
          {(data.stats.verdictPassPackets > 0 || data.stats.verdictDropPackets > 0) && (
            <div>
              <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">
                Flow Verdict Cache
              </p>
              <div className="grid grid-cols-2 gap-2">
                <StatCard
                  label="Verdict Pass Pkts"
                  value={formatNumber(data.stats.verdictPassPackets)}
                  color="green"
                />
                <StatCard
                  label="Verdict Pass Bytes"
                  value={formatBytes(data.stats.verdictPassBytes)}
                  color="green"
                />
                <StatCard
                  label="Verdict Drop Pkts"
                  value={formatNumber(data.stats.verdictDropPackets)}
                  color="red"
                />
                <StatCard
                  label="Verdict Drop Bytes"
                  value={formatBytes(data.stats.verdictDropBytes)}
                  color="red"
                />
              </div>
            </div>
          )}

          {/* FIB Forwarding — ingress only, only shown when non-zero */}
          {!isEgress &&
            (data.stats.fibForwardedPackets > 0 || data.stats.fibFallbackPackets > 0) && (
              <div>
                <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">
                  FIB Forwarding
                </p>
                <div className="grid grid-cols-2 gap-2">
                  <StatCard
                    label="FIB Forwarded Pkts"
                    value={formatNumber(data.stats.fibForwardedPackets)}
                    color="green"
                  />
                  <StatCard
                    label="FIB Forwarded Bytes"
                    value={formatBytes(data.stats.fibForwardedBytes)}
                    color="green"
                  />
                  <StatCard
                    label="FIB Fallback Pkts"
                    value={formatNumber(data.stats.fibFallbackPackets)}
                    color="yellow"
                  />
                </div>
              </div>
            )}

          {/* Diagnostics */}
          <div>
            <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">Diagnostics</p>
            <div className="grid grid-cols-2 gap-2">
              <StatCard
                label="Parse Errors"
                value={formatNumber(data.stats.parseErrors)}
                color={data.stats.parseErrors > 0 ? 'red' : undefined}
                highlight={data.stats.parseErrors > 0}
              />
              <StatCard label="Tail Calls" value={formatNumber(data.stats.tailCalls)} />
              {!isEgress && (
                <>
                  <StatCard label="BUM Packets" value={formatNumber(data.stats.bumPackets)} />
                  <StatCard label="Non-IP Unicast" value={formatNumber(data.stats.nonIpUnicast)} />
                </>
              )}
            </div>
          </div>

          </>}
        </>
      ) : null}
    </div>
  )
}

/** Renders the two non-IP tables: ethertype overview + per-MAC sender breakdown. */
function NonIpSection({
  ethRows,
  senderRows,
  onClear,
}: {
  ethRows: EthertypeStat[]
  senderRows: NonIpSender[]
  onClear: () => void
}) {
  if (ethRows.length === 0 && senderRows.length === 0) {
    return (
      <div>
        <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">Non-IP Traffic</p>
        <p className="text-xs text-gray-600 italic">No non-IP traffic recorded.</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {/* ── Ethertype overview ── */}
      <div>
        <div className="flex justify-between items-center mb-2">
          <p className="text-xs uppercase tracking-wider text-gray-500">Non-IP by Ethertype</p>
          <button
            onClick={onClear}
            className="px-2 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 rounded hover:bg-yellow-500/30 transition"
          >
            Clear
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-gray-500 border-b border-gray-700">
              <th className="pb-1 pr-3 font-medium">Ethertype</th>
              <th className="pb-1 pr-3 font-medium">Name</th>
              <th className="pb-1 text-right font-medium">Packets</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700/40">
            {ethRows.map((e) => (
              <tr key={e.ethertype} className="text-gray-300">
                <td className="py-1 pr-3 font-mono text-xs text-gray-400">{toHex(e.ethertype)}</td>
                <td className="py-1 pr-3 text-xs">{e.name}</td>
                <td className="py-1 text-right font-mono text-xs">{formatNumber(e.packets)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Per-MAC sender breakdown ── */}
      {senderRows.length > 0 && (
        <div>
          <p className="text-xs uppercase tracking-wider text-gray-500 mb-2">
            Non-IP by Sender MAC
          </p>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-gray-500 border-b border-gray-700">
                <th className="pb-1 pr-3 font-medium">MAC</th>
                <th className="pb-1 pr-3 font-medium">Ethertype</th>
                <th className="pb-1 pr-3 font-medium">Name</th>
                <th className="pb-1 text-right font-medium">Packets</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/40">
              {senderRows.map((s) => (
                <tr key={`${s.mac}-${s.ethertype}`} className="text-gray-300">
                  <td className="py-1 pr-3 font-mono text-xs">{s.mac}</td>
                  <td className="py-1 pr-3 font-mono text-xs text-gray-400">
                    {toHex(s.ethertype)}
                  </td>
                  <td className="py-1 pr-3 text-xs">{s.name}</td>
                  <td className="py-1 text-right font-mono text-xs">{formatNumber(s.packets)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export function StatsPanel() {
  const [selectedInterface, setSelectedInterface] = useState<string>('')

  const { data: interfacesData } = useQuery<InterfacesData>(GET_INTERFACES, {
    pollInterval: 5000,
  })

  const interfaces = interfacesData?.interfaces || []
  const uniqueInterfaces = [...new Set(interfaces.map((i) => i.interface))]

  // Auto-select first interface when data loads
  useEffect(() => {
    if (!selectedInterface && uniqueInterfaces.length > 0) {
      setSelectedInterface(uniqueInterfaces[0])
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [uniqueInterfaces.length])

  // Determine which directions are attached for the selected interface
  const attachedDirections = interfaces
    .filter((i) => i.interface === selectedInterface)
    .map((i) => i.direction.toUpperCase())
  const hasIngress = attachedDirections.includes('INGRESS')
  const hasEgress = attachedDirections.includes('EGRESS')

  if (uniqueInterfaces.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4">Statistics</h2>
        <p className="text-gray-400 text-center py-8">
          No interfaces attached. Attach an interface first.
        </p>
      </div>
    )
  }

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold">Statistics</h2>
        <select
          value={selectedInterface}
          onChange={(e) => setSelectedInterface(e.target.value)}
          className="px-3 py-1 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
        >
          {uniqueInterfaces.map((iface) => (
            <option key={iface} value={iface}>
              {iface}
            </option>
          ))}
        </select>
      </div>

      <div
        className={`grid gap-4 ${hasIngress && hasEgress ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}
      >
        {hasIngress && (
          <DirectionStatsPane iface={selectedInterface} direction="INGRESS" accent="blue" />
        )}
        {hasEgress && (
          <DirectionStatsPane iface={selectedInterface} direction="EGRESS" accent="purple" />
        )}
        {!hasIngress && !hasEgress && selectedInterface && (
          <p className="text-gray-400 text-center py-8">
            No programs attached to {selectedInterface}.
          </p>
        )}
      </div>
    </div>
  )
}

function StatCard({
  label,
  value,
  color,
  highlight,
}: {
  label: string
  value: string
  color?: 'red' | 'green' | 'blue' | 'yellow'
  highlight?: boolean
}) {
  const colorClasses = {
    red: 'text-red-400',
    green: 'text-green-400',
    blue: 'text-blue-400',
    yellow: 'text-yellow-400',
  }

  return (
    <div
      className={`rounded-lg p-3 ${highlight ? 'bg-red-900/30 ring-1 ring-red-500/40' : 'bg-gray-700/50'}`}
    >
      <div className="text-xs text-gray-400 mb-1">{label}</div>
      <div className={`text-lg font-semibold ${color ? colorClasses[color] : ''}`}>{value}</div>
    </div>
  )
}
