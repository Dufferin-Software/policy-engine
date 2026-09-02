// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState, useEffect, useRef, useCallback } from 'react'
import { wsUrl } from '../lib/auth'

interface RuleLifecycleEvent {
  event_type: string      // "created" | "deleted" | "expired"
  rule_id: string
  node_id: string
  interface_name: string
  direction: string       // "INGRESS" | "EGRESS"
  timestamp_ms: number
  reason?: string
}

const MAX_EVENTS = 500
const RECONNECT_BASE_DELAY = 1000
const RECONNECT_MAX_DELAY = 30000

const EVENT_COLORS: Record<string, string> = {
  created: 'text-blue-400',
  deleted: 'text-red-400',
  expired: 'text-orange-400',
}

function formatTime(ts_ms: number): string {
  const d = new Date(ts_ms)
  return d.toISOString().replace('T', ' ').slice(0, 23) + ' UTC'
}

interface Props {
  nodeId: string
  onCountChange?: (count: number) => void
}

export default function RuleLifecycleStream({ nodeId, onCountChange }: Props) {
  const [events, setEvents] = useState<RuleLifecycleEvent[]>([])
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

  const connect = useCallback(() => {
    if (
      wsRef.current?.readyState === WebSocket.OPEN ||
      wsRef.current?.readyState === WebSocket.CONNECTING
    ) {
      return
    }

    setConnecting(true)
    const ws = new WebSocket(wsUrl('/ws/rule-events', { node: nodeId }))

    ws.onopen = () => {
      setConnected(true)
      setConnecting(false)
      reconnectDelay.current = RECONNECT_BASE_DELAY
    }

    ws.onmessage = (e) => {
      if (!enabledRef.current) return
      try {
        const event: RuleLifecycleEvent = JSON.parse(e.data)
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
      if (wsRef.current === ws) {
        wsRef.current = null
        if (enabledRef.current) {
          reconnectTimer.current = setTimeout(() => {
            reconnectDelay.current = Math.min(
              reconnectDelay.current * 2,
              RECONNECT_MAX_DELAY,
            )
            connect()
          }, reconnectDelay.current)
        }
      }
    }

    ws.onerror = () => ws.close()
    wsRef.current = ws
  }, [nodeId])

  useEffect(() => {
    if (enabled) {
      connect()
    } else {
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
      wsRef.current?.close()
      wsRef.current = null
      setConnected(false)
      setConnecting(false)
    }
  }, [enabled, connect])

  useEffect(() => {
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [])

  useEffect(() => {
    if (autoScroll && tableEndRef.current) {
      tableEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, autoScroll])

  useEffect(() => {
    onCountChange?.(events.length)
  }, [events.length, onCountChange])

  const statusDot = connected
    ? 'bg-green-500'
    : connecting
      ? 'bg-yellow-500 animate-pulse'
      : 'bg-red-500'

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700 flex-shrink-0">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-gray-300">Rule Lifecycle Events</h3>
          {events.length > 0 && (
            <span className="text-xs text-gray-500 font-normal">{events.length}</span>
          )}
          <div className={`w-2 h-2 rounded-full ${statusDot}`} title={connected ? 'Connected' : 'Disconnected'} />
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setEnabled(!enabled)}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              enabled
                ? 'bg-blue-600 hover:bg-blue-700 text-white'
                : 'bg-gray-600 hover:bg-gray-500 text-gray-200'
            }`}
          >
            {enabled ? 'Streaming' : 'Paused'}
          </button>
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              autoScroll
                ? 'bg-green-700 hover:bg-green-600 text-white'
                : 'bg-gray-600 hover:bg-gray-500 text-gray-200'
            }`}
          >
            Auto-scroll {autoScroll ? 'On' : 'Off'}
          </button>
          <button
            onClick={() => setEvents([])}
            className="px-3 py-1 rounded text-xs font-medium bg-gray-600 hover:bg-gray-500 text-gray-200 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto min-h-[400px]">
        {events.length === 0 ? (
          <div className="text-gray-600 text-sm p-4">
            {connected ? 'Waiting for rule lifecycle events…' : 'Not connected to /ws/rule-events'}
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="text-gray-500 uppercase bg-gray-900/80 sticky top-0">
              <tr>
                {['Time (UTC)', 'Event', 'Rule ID', 'Interface', 'Direction', 'Reason'].map((h) => (
                  <th key={h} className="px-3 py-1 text-left font-medium whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((ev, i) => (
                <tr key={i} className="border-t border-gray-800 hover:bg-gray-800/50">
                  <td className="px-3 py-1 text-gray-400 whitespace-nowrap font-mono">
                    {formatTime(ev.timestamp_ms)}
                  </td>
                  <td className={`px-3 py-1 font-semibold uppercase ${EVENT_COLORS[ev.event_type] ?? 'text-gray-300'}`}>
                    {ev.event_type}
                  </td>
                  <td className="px-3 py-1 text-gray-300 font-mono">{ev.rule_id}</td>
                  <td className="px-3 py-1 text-gray-300">{ev.interface_name}</td>
                  <td className="px-3 py-1 text-gray-400">{ev.direction}</td>
                  <td className="px-3 py-1 text-gray-500">{ev.reason ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div ref={tableEndRef} />
      </div>
    </div>
  )
}
