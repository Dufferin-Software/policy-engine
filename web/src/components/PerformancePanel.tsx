// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useState, useEffect } from 'react'
import { gql, useQuery } from '@apollo/client'

const GET_INTERFACES = gql`
  query GetInterfacesForPerf {
    interfaces {
      interface
      direction
    }
  }
`

const GET_PERFORMANCE_STATS = gql`
  query GetPerformanceStats($interface: String!, $direction: GqlDirection!) {
    performanceStats(interface: $interface, direction: $direction) {
      timing {
        p50Ns
        p95Ns
        p99Ns
        p999Ns
        totalSamples
        buckets
      }
      protoStats {
        protocol
        name
        packets
        bytes
      }
      l3Stats {
        protocol
        name
        packets
        bytes
      }
      rxBytesPerSec
      txBytesPerSec
    }
  }
`

interface TimingStats {
  p50Ns: number
  p95Ns: number
  p99Ns: number
  p999Ns: number
  totalSamples: number
  buckets: number[]
}

interface ProtoStat {
  protocol: number
  name: string
  packets: number
  bytes: number
}

interface PerformanceStats {
  timing: TimingStats
  protoStats: ProtoStat[]
  l3Stats: ProtoStat[]
  rxBytesPerSec: number
  txBytesPerSec: number
}

interface PerfData {
  performanceStats: PerformanceStats
}

interface InterfacesData {
  interfaces: { interface: string; direction: string }[]
}

function fmtNs(ns: number): string {
  if (ns === 0) return '—'
  if (ns < 1_000) return `${ns} ns`
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)} µs`
  return `${(ns / 1_000_000).toFixed(2)} ms`
}

function fmtBps(bps: number): string {
  if (bps === 0) return '0 B/s'
  const k = 1024
  const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s']
  const i = Math.floor(Math.log(bps) / Math.log(k))
  return (bps / Math.pow(k, i)).toFixed(1) + ' ' + sizes[Math.min(i, sizes.length - 1)]
}

function fmtBytes(b: number): string {
  if (b === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(b) / Math.log(k))
  return (b / Math.pow(k, i)).toFixed(1) + ' ' + sizes[Math.min(i, sizes.length - 1)]
}

function fmtNum(n: number): string {
  return n.toLocaleString()
}

export function PerformancePanel() {
  const [selectedInterface, setSelectedInterface] = useState<string>('')
  const [direction, setDirection] = useState<'INGRESS' | 'EGRESS'>('INGRESS')

  const { data: ifData } = useQuery<InterfacesData>(GET_INTERFACES, { pollInterval: 5000 })
  const interfaces = ifData?.interfaces ?? []
  const uniqueInterfaces = [...new Set(interfaces.map((i) => i.interface))]

  useEffect(() => {
    if (!selectedInterface && uniqueInterfaces.length > 0) {
      setSelectedInterface(uniqueInterfaces[0])
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [uniqueInterfaces.length])

  const { data, loading } = useQuery<PerfData>(GET_PERFORMANCE_STATS, {
    variables: { interface: selectedInterface, direction },
    skip: !selectedInterface,
    pollInterval: 2000,
  })

  const perf = data?.performanceStats
  const timing = perf?.timing
  const proto = (perf?.protoStats ?? [])
    .filter((p) => p.packets > 0)
    .sort((a, b) => b.packets - a.packets)
  const l3 = (perf?.l3Stats ?? [])
    .filter((p) => p.packets > 0)
    .sort((a, b) => b.packets - a.packets)

  const totalPackets = proto.reduce((s, p) => s + p.packets, 0)
  const totalL3Packets = l3.reduce((s, p) => s + p.packets, 0)

  if (uniqueInterfaces.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4">Performance</h2>
        <p className="text-gray-400 text-center py-8">
          No interfaces attached. Attach an interface first.
        </p>
      </div>
    )
  }

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg space-y-6">
      {/* Header + controls */}
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-xl font-semibold mr-2">Performance</h2>
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
        <div className="flex rounded overflow-hidden border border-gray-600">
          {(['INGRESS', 'EGRESS'] as const).map((d) => (
            <button
              key={d}
              onClick={() => setDirection(d)}
              className={`px-3 py-1 text-sm transition ${
                direction === d
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-gray-400 hover:text-white'
              }`}
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {loading && !data ? (
        <div className="animate-pulse space-y-4">
          {Array(3).fill(0).map((_, i) => (
            <div key={i} className="h-20 bg-gray-700/50 rounded" />
          ))}
        </div>
      ) : (
        <>
          {/* Bandwidth */}
          <div>
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">Bandwidth</h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-gray-700/50 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">RX</div>
                <div className="text-lg font-semibold text-blue-400">
                  {fmtBps(perf?.rxBytesPerSec ?? 0)}
                </div>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">TX</div>
                <div className="text-lg font-semibold text-purple-400">
                  {fmtBps(perf?.txBytesPerSec ?? 0)}
                </div>
              </div>
            </div>
          </div>

          {/* Processing time */}
          <div>
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">
              BPF Processing Time
              {timing && timing.totalSamples > 0 && (
                <span className="ml-2 text-gray-600 normal-case">
                  ({fmtNum(timing.totalSamples)} samples)
                </span>
              )}
            </h3>
            {!timing || timing.totalSamples === 0 ? (
              <p className="text-sm text-gray-500">No timing data yet.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-gray-500 border-b border-gray-700">
                    <th className="pb-1 pr-4 font-medium">Percentile</th>
                    <th className="pb-1 text-right font-medium">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/40">
                  {[
                    { label: 'p50', ns: timing.p50Ns },
                    { label: 'p95', ns: timing.p95Ns },
                    { label: 'p99', ns: timing.p99Ns },
                    { label: 'p99.9', ns: timing.p999Ns },
                  ].map(({ label, ns }) => (
                    <tr key={label} className="text-gray-300">
                      <td className="py-1.5 pr-4 font-mono text-xs text-gray-400">{label}</td>
                      <td className="py-1.5 text-right font-mono text-xs">{fmtNs(ns)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* L3 protocol breakdown */}
          <div>
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">
              L3 Protocol Breakdown
            </h3>
            {l3.length === 0 ? (
              <p className="text-sm text-gray-500">No traffic recorded.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-gray-500 border-b border-gray-700">
                    <th className="pb-1 pr-4 font-medium">Protocol</th>
                    <th className="pb-1 pr-4 text-right font-medium">Packets</th>
                    <th className="pb-1 pr-4 text-right font-medium">Bytes</th>
                    <th className="pb-1 text-right font-medium">%</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/40">
                  {l3.map((p) => (
                    <tr key={p.protocol} className="text-gray-300">
                      <td className="py-1.5 pr-4">
                        <span className="font-semibold text-green-300">{p.name}</span>
                        {p.protocol !== 0 && (
                          <span className="ml-1.5 text-xs text-gray-500">
                            (0x{p.protocol.toString(16).toUpperCase().padStart(4, '0')})
                          </span>
                        )}
                      </td>
                      <td className="py-1.5 pr-4 text-right font-mono text-xs">
                        {fmtNum(p.packets)}
                      </td>
                      <td className="py-1.5 pr-4 text-right font-mono text-xs">
                        {fmtBytes(p.bytes)}
                      </td>
                      <td className="py-1.5 text-right font-mono text-xs text-gray-400">
                        {totalL3Packets > 0
                          ? ((p.packets / totalL3Packets) * 100).toFixed(1) + '%'
                          : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* L4 per-protocol breakdown */}
          <div>
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-3">
              L4 Protocol Breakdown
            </h3>
            {proto.length === 0 ? (
              <p className="text-sm text-gray-500">No traffic recorded.</p>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-gray-500 border-b border-gray-700">
                    <th className="pb-1 pr-4 font-medium">Protocol</th>
                    <th className="pb-1 pr-4 text-right font-medium">Packets</th>
                    <th className="pb-1 pr-4 text-right font-medium">Bytes</th>
                    <th className="pb-1 text-right font-medium">%</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/40">
                  {proto.map((p) => (
                    <tr key={p.protocol} className="text-gray-300">
                      <td className="py-1.5 pr-4">
                        <span className="font-semibold text-blue-300">{p.name}</span>
                        <span className="ml-1.5 text-xs text-gray-500">({p.protocol})</span>
                      </td>
                      <td className="py-1.5 pr-4 text-right font-mono text-xs">
                        {fmtNum(p.packets)}
                      </td>
                      <td className="py-1.5 pr-4 text-right font-mono text-xs">
                        {fmtBytes(p.bytes)}
                      </td>
                      <td className="py-1.5 text-right font-mono text-xs text-gray-400">
                        {totalPackets > 0
                          ? ((p.packets / totalPackets) * 100).toFixed(1) + '%'
                          : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  )
}
