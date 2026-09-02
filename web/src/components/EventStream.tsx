// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { gql, useQuery } from '@apollo/client'
import { getPortName } from './portMappings'
import { isMulticast } from './netUtils'
import { getIcmpTypeName, getIcmpCodeName } from './icmpMappings'

const GET_INTERFACE_NAMES = gql`
  query GetInterfaceNames {
    interfaces {
      interface
      ifindex
    }
  }
`

interface InterfaceNameRow {
  interface: string
  ifindex: number
}

interface InterfaceNamesData {
  interfaces: InterfaceNameRow[]
}

interface PolicyEvent {
  timestamp_ns: number
  rule_id: number
  action: string
  ifindex: number
  src: string
  dst: string
  sport: number
  dport: number
  protocol: string
  af: number
  pkt_len: number
  verdict: string
  direction: string
  fragment: boolean
  sni?: string           /* SNI value if captured from SNI inspection rule */
  quic_version?: string  /* "v1", "v2", or "any" when QUIC-flagged */
}

const MAX_EVENTS = 500
const RECONNECT_BASE_DELAY = 1000
const RECONNECT_MAX_DELAY = 30000

export function EventStream() {
  const [events, setEvents] = useState<PolicyEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [enabled, setEnabled] = useState(true)
  const [autoScroll, setAutoScroll] = useState(true)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectDelay = useRef(RECONNECT_BASE_DELAY)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const tableEndRef = useRef<HTMLDivElement>(null)
  const enabledRef = useRef(enabled)

  enabledRef.current = enabled

  const { data: ifaceData } = useQuery<InterfaceNamesData>(GET_INTERFACE_NAMES, {
    fetchPolicy: 'cache-first',
  })

  const ifaceNameByIndex = useMemo(() => {
    const map = new Map<number, string>()
    for (const row of ifaceData?.interfaces ?? []) {
      if (row.ifindex > 0) map.set(row.ifindex, row.interface)
    }
    return map
  }, [ifaceData])

  const formatIface = (ifindex: number) => {
    if (!ifindex) return '—'
    return ifaceNameByIndex.get(ifindex) ?? `if${ifindex}`
  }

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN || wsRef.current?.readyState === WebSocket.CONNECTING) {
      return
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws/events`

    setConnecting(true)
    const ws = new WebSocket(wsUrl)

    ws.onopen = () => {
      setConnected(true)
      setConnecting(false)
      reconnectDelay.current = RECONNECT_BASE_DELAY
    }

    ws.onmessage = (e) => {
      if (!enabledRef.current) return
      try {
        const event: PolicyEvent = JSON.parse(e.data)
        setEvents((prev) => {
          const next = [...prev, event]
          return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next
        })
      } catch {
        // ignore malformed messages
      }
    }

    ws.onclose = () => {
      setConnected(false)
      setConnecting(false)
      // Guard against stale onclose: in React StrictMode the effect cleanup
      // runs ws1.close() and immediately remounts with ws2. If ws1.onclose
      // fires after ws2 has been assigned, it must not null out wsRef or
      // schedule a reconnect — those belong to ws2 now.
      if (wsRef.current === ws) {
        wsRef.current = null
        if (enabledRef.current) {
          reconnectTimer.current = setTimeout(() => {
            reconnectDelay.current = Math.min(reconnectDelay.current * 2, RECONNECT_MAX_DELAY)
            connect()
          }, reconnectDelay.current)
        }
      }
    }

    ws.onerror = () => {
      ws.close()
    }

    wsRef.current = ws
  }, [])

  const disconnect = useCallback(() => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current)
      reconnectTimer.current = null
    }
    wsRef.current?.close()
    wsRef.current = null
    setConnected(false)
    setConnecting(false)
  }, [])

  useEffect(() => {
    if (enabled) {
      connect()
    } else {
      disconnect()
    }
    return () => {
      disconnect()
    }
  }, [enabled, connect, disconnect])

  useEffect(() => {
    if (autoScroll && tableEndRef.current) {
      tableEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, autoScroll])

  const formatTime = (ns: number) => {
    if (ns === 0) return '--'
    const ms = ns / 1_000_000
    const date = new Date(ms)
    return date.toLocaleTimeString([], { timeZone: 'UTC', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
      '.' + String(date.getUTCMilliseconds()).padStart(3, '0')
  }

  const verdictColor = (verdict: string) => {
    const v = verdict.toLowerCase()
    if (v === 'pass' || v === 'tx') return 'text-green-400'
    if (v === 'drop') return 'text-red-400'
    if (v === 'log') return 'text-yellow-400'
    return 'text-gray-300'
  }

  const actionColor = (action: string) => {
    const a = action.toLowerCase()
    if (a === 'pass' || a === 'tx') return 'bg-green-500/20 text-green-400'
    if (a === 'drop') return 'bg-red-500/20 text-red-400'
    if (a === 'log') return 'bg-yellow-500/20 text-yellow-400'
    return 'bg-gray-500/20 text-gray-400'
  }

  const directionColor = (dir: string) => {
    return dir === 'INGRESS' ? 'text-blue-400' : 'text-purple-400'
  }

  const isIcmp = (protocol: string) => {
    const p = protocol.toLowerCase()
    return p === 'icmp' || p === 'icmpv6'
  }

  return (
    <div className="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <h2 className="text-lg font-semibold text-white">Event Stream</h2>
          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
            connected ? 'bg-green-500/20 text-green-400' :
            connecting ? 'bg-yellow-500/20 text-yellow-400' :
            'bg-gray-500/20 text-gray-400'
          }`}>
            {connected ? 'Connected' : connecting ? 'Connecting...' : 'Disconnected'}
          </span>
          {events.length > 0 && (
            <span className="text-xs text-gray-500">{events.length} events</span>
          )}
        </div>
        <div className="flex items-center space-x-2">
          <label className="flex items-center space-x-1.5 text-sm text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
            />
            <span>Auto-scroll</span>
          </label>
          <button
            onClick={() => setEvents([])}
            className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition"
          >
            Clear
          </button>
          <button
            onClick={() => setEnabled(!enabled)}
            className={`px-3 py-1 text-xs rounded transition ${
              enabled
                ? 'bg-red-500/20 hover:bg-red-500/30 text-red-400'
                : 'bg-green-500/20 hover:bg-green-500/30 text-green-400'
            }`}
          >
            {enabled ? 'Stop' : 'Start'}
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto max-h-96 overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-700/50 sticky top-0">
            <tr className="text-gray-400 text-left text-xs uppercase tracking-wider">
              <th className="py-2 px-3">Time</th>
              <th className="py-2 px-3">Dir</th>
              <th className="py-2 px-3">Iface</th>
              <th className="py-2 px-3">Source</th>
              <th className="py-2 px-3">Destination</th>
              <th className="py-2 px-3">Proto</th>
              <th className="py-2 px-3">Rule</th>
              <th className="py-2 px-3">Action</th>
              <th className="py-2 px-3">Verdict</th>
              <th className="py-2 px-3">Size</th>
              <th className="py-2 px-3">SNI</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700/30">
            {events.length === 0 ? (
              <tr>
                <td colSpan={11} className="py-8 text-center text-gray-500">
                  {connected
                    ? 'Waiting for events... (ensure rules have Log action)'
                    : 'Not connected'}
                </td>
              </tr>
            ) : (
              events.map((ev, i) => (
                <tr key={i} className="hover:bg-gray-700/30 transition-colors">
                  <td className="py-1.5 px-3 font-mono text-xs text-gray-400 whitespace-nowrap">
                    {formatTime(ev.timestamp_ns)}
                  </td>
                  <td className={`py-1.5 px-3 text-xs font-medium ${directionColor(ev.direction)}`}>
                    {ev.direction === 'INGRESS' ? 'IN' : 'OUT'}
                    {ev.fragment && <span title="IP fragment" className="ml-1 text-xs text-orange-400 font-bold">F</span>}
                    {ev.quic_version && (
                      <span title={`QUIC ${ev.quic_version}`} className="ml-1 text-xs text-cyan-400 font-bold">
                        {ev.quic_version === 'v1' ? 'Q1' : ev.quic_version === 'v2' ? 'Q2' : 'Q'}
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 px-3 font-mono text-xs text-gray-300 whitespace-nowrap" title={ev.ifindex ? `ifindex ${ev.ifindex}` : ''}>
                    {formatIface(ev.ifindex)}
                  </td>
                  <td className="py-1.5 px-3 font-mono text-xs whitespace-nowrap">
                    {isIcmp(ev.protocol)
                      ? <>
                          {ev.src}
                          {isMulticast(ev.src) && <span title="Multicast" className="ml-1 text-xs text-yellow-400 font-bold">M</span>}
                        </>
                      : <>
                          {ev.src}:{ev.sport}
                          {['tcp','udp'].includes(ev.protocol.toLowerCase()) && ev.sport != null && (
                            <span className="ml-1 text-xs text-gray-400">[{getPortName(ev.protocol.toLowerCase() as 'tcp' | 'udp', ev.sport) ?? 'unknown'}]</span>
                          )}
                          {isMulticast(ev.src) && <span title="Multicast" className="ml-1 text-xs text-yellow-400 font-bold">M</span>}
                        </>
                    }
                  </td>
                  <td className="py-1.5 px-3 font-mono text-xs whitespace-nowrap">
                    {isIcmp(ev.protocol)
                      ? <>
                          {ev.dst}
                          {isMulticast(ev.dst) && <span title="Multicast" className="ml-1 text-xs text-yellow-400 font-bold">M</span>}
                        </>
                      : <>
                          {ev.dst}:{ev.dport}
                          {['tcp','udp'].includes(ev.protocol.toLowerCase()) && ev.dport != null && (
                            <span className="ml-1 text-xs text-gray-400">[{getPortName(ev.protocol.toLowerCase() as 'tcp' | 'udp', ev.dport) ?? 'unknown'}]</span>
                          )}
                          {isMulticast(ev.dst) && <span title="Multicast" className="ml-1 text-xs text-yellow-400 font-bold">M</span>}
                        </>
                    }
                  </td>
                  <td className="py-1.5 px-3 text-xs text-gray-300">
                    {isIcmp(ev.protocol)
                      ? (
                          <>
                            {ev.protocol} type={ev.sport}
                            {ev.sport != null && (
                              <span className="ml-1 text-xs text-gray-400">[{getIcmpTypeName(ev.sport, ev.protocol === 'icmpv6') ?? 'unknown'}]</span>
                            )}
                            {' '}code={ev.dport}
                            {ev.sport != null && ev.dport != null && (
                              <span className="ml-1 text-xs text-gray-400">[{getIcmpCodeName(ev.sport, ev.dport, ev.protocol === 'icmpv6') ?? 'unknown'}]</span>
                            )}
                          </>
                        )
                      : ev.protocol}
                  </td>
                  <td className="py-1.5 px-3 font-mono text-xs text-gray-300">{ev.rule_id}</td>
                  <td className="py-1.5 px-3">
                    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${actionColor(ev.action)}`}>
                      {ev.action}
                    </span>
                  </td>
                  <td className={`py-1.5 px-3 text-xs font-medium ${verdictColor(ev.verdict)}`}>
                    {ev.verdict}
                  </td>
                  <td className="py-1.5 px-3 font-mono text-xs text-gray-400">{ev.pkt_len}</td>
                  <td className="py-1.5 px-3 font-mono text-xs text-gray-300 max-w-48 truncate" title={ev.sni || ''}>
                    {ev.sni ? ev.sni : '--'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        <div ref={tableEndRef} />
      </div>
    </div>
  )
}
