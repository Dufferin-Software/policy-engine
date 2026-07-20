// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useQuery, useMutation, gql } from '@apollo/client'
import { shortId } from './types.ts'

// ── GraphQL ────────────────────────────────────────────────────────────────

const EVENTS_QUERY = gql`
  query Events($filter: EventFilterInput, $limit: Int, $cursor: String) {
    events(filter: $filter, limit: $limit, cursor: $cursor) {
      items {
        id
        timestamp
        receivedAt
        nodeId
        ruleId
        action
        verdict
        direction
        ifindex
        proto
        srcIp
        dstIp
        sport
        dport
        pktLen
        sni
      }
      nextCursor
    }
  }
`

const NODES_INDEX_QUERY = gql`
  query NodesIndex {
    nodes { id hostname label }
  }
`

const INTERFACES_INDEX_QUERY = gql`
  query AllInterfacesIndex {
    allNodeInterfaces { nodeId name ifindex }
  }
`

interface NodeIndexEntry {
  id: string
  hostname: string | null
  label: string | null
}

interface NodesIndexResp {
  nodes: NodeIndexEntry[]
}

interface InterfaceIndexEntry {
  nodeId: string
  name: string
  ifindex: number
}

interface InterfacesIndexResp {
  allNodeInterfaces: InterfaceIndexEntry[]
}

const CLEAR_EVENTS = gql`
  mutation ClearEvents {
    clearEvents { success message }
  }
`

const AGGREGATE_QUERY = gql`
  query EventAggregate(
    $filter: EventFilterInput
    $groupBy: EventGroupBy!
    $since: DateTime!
    $until: DateTime!
  ) {
    eventAggregate(filter: $filter, groupBy: $groupBy, since: $since, until: $until) {
      key
      count
    }
  }
`

interface EventRow {
  id: string
  timestamp: string
  receivedAt: string
  nodeId: string
  ruleId: string
  action: string
  verdict: string
  direction: string
  ifindex: number
  proto: number
  srcIp: string
  dstIp: string
  sport: number
  dport: number
  pktLen: number
  sni?: string | null
  live?: boolean
}

interface EventsResp {
  events: {
    items: EventRow[]
    nextCursor: string | null
  }
}

interface AggregateResp {
  eventAggregate: { key: string; count: number }[]
}

// ── Filter form state ──────────────────────────────────────────────────────

type ActionFilter = '' | 'DROP' | 'LOG'

interface FilterForm {
  since: string // datetime-local input value (UTC ISO without Z)
  until: string
  action: ActionFilter
  nodeId: string
  ruleId: string
  srcIp: string
  dstIp: string
  sport: string
  dport: string
  proto: string
  sniLike: string
}

const EMPTY_FORM: FilterForm = {
  since: '',
  until: '',
  action: '',
  nodeId: '',
  ruleId: '',
  srcIp: '',
  dstIp: '',
  sport: '',
  dport: '',
  proto: '',
  sniLike: '',
}

function toIsoZ(local: string): string | undefined {
  if (!local) return undefined
  // datetime-local lacks timezone — treat as UTC.
  const d = new Date(local + 'Z')
  if (isNaN(d.getTime())) return undefined
  return d.toISOString()
}

function localFromIso(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    d.getUTCFullYear() +
    '-' +
    pad(d.getUTCMonth() + 1) +
    '-' +
    pad(d.getUTCDate()) +
    'T' +
    pad(d.getUTCHours()) +
    ':' +
    pad(d.getUTCMinutes())
  )
}

function buildFilter(f: FilterForm) {
  const out: Record<string, unknown> = {}
  const since = toIsoZ(f.since)
  const until = toIsoZ(f.until)
  if (since) out.since = since
  if (until) out.until = until
  if (f.action) out.action = f.action
  if (f.nodeId.trim()) out.nodeId = f.nodeId.trim()
  if (f.ruleId.trim()) out.ruleId = f.ruleId.trim()
  if (f.srcIp.trim()) out.srcIp = f.srcIp.trim()
  if (f.dstIp.trim()) out.dstIp = f.dstIp.trim()
  if (f.sport.trim()) out.sport = parseInt(f.sport, 10)
  if (f.dport.trim()) out.dport = parseInt(f.dport, 10)
  if (f.proto.trim()) out.proto = parseInt(f.proto, 10)
  if (f.sniLike.trim()) out.sniLike = f.sniLike.trim()
  return Object.keys(out).length === 0 ? undefined : out
}

const PAGE_SIZE = 100
const LIVE_BUFFER_MAX = 200

// ── Live WS event normalization ────────────────────────────────────────────

interface WireEvent {
  timestamp_ns: number
  rule_id: number
  action: string
  ifindex: number
  src: string
  dst: string
  sport: number
  dport: number
  protocol: string
  pkt_len: number
  verdict: string
  direction: string
  sni?: string
  /// Injected server-side by /ws/events (the agent's JSON doesn't carry it).
  node_id?: string
}

const PROTO_NUM: Record<string, number> = {
  icmp: 1,
  igmp: 2,
  tcp: 6,
  udp: 17,
  gre: 47,
  icmpv6: 58,
}

function normalizeLive(w: WireEvent): EventRow | null {
  const action = w.action.toLowerCase()
  if (action !== 'drop' && action !== 'log') return null
  return {
    id: `live-${w.timestamp_ns}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date(w.timestamp_ns / 1_000_000).toISOString(),
    receivedAt: new Date().toISOString(),
    nodeId: w.node_id ?? '',
    ruleId: String(w.rule_id),
    action,
    verdict: w.verdict.toLowerCase(),
    direction: w.direction.toLowerCase(),
    ifindex: w.ifindex,
    proto: PROTO_NUM[w.protocol.toLowerCase()] ?? 0,
    srcIp: w.src,
    dstIp: w.dst,
    sport: w.sport,
    dport: w.dport,
    pktLen: w.pkt_len,
    sni: w.sni ?? null,
    live: true,
  }
}

// ── Bar chart ──────────────────────────────────────────────────────────────

interface ChartProps {
  buckets: { key: string; count: number }[]
  sinceMs: number
  untilMs: number
  onClickBucket: (sinceIso: string, untilIso: string) => void
}

function MinuteBarChart({ buckets, sinceMs, untilMs, onClickBucket }: ChartProps) {
  // Build a dense array covering [sinceMin .. untilMin) keyed by minute index.
  const startMin = Math.floor(sinceMs / 60_000)
  const endMin = Math.ceil(untilMs / 60_000)
  const n = Math.max(1, endMin - startMin)
  const counts = new Array<number>(n).fill(0)
  for (const b of buckets) {
    const m = parseInt(b.key, 10)
    const idx = m - startMin
    if (idx >= 0 && idx < n) counts[idx] = b.count
  }
  const max = Math.max(1, ...counts)

  const width = 720
  const height = 120
  const barW = width / n

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className="w-full h-32 bg-gray-900 rounded border border-gray-700"
    >
      {counts.map((c, i) => {
        const h = (c / max) * (height - 16)
        const x = i * barW
        const y = height - h
        const minuteMs = (startMin + i) * 60_000
        const sinceIso = new Date(minuteMs).toISOString()
        const untilIso = new Date(minuteMs + 60_000).toISOString()
        return (
          <g key={i}>
            <rect
              x={x}
              y={0}
              width={barW}
              height={height}
              fill="transparent"
              className="cursor-pointer"
              onClick={() => onClickBucket(sinceIso, untilIso)}
            >
              <title>
                {new Date(minuteMs).toISOString().slice(11, 16)} UTC — {c}
              </title>
            </rect>
            {c > 0 && (
              <rect
                x={x + 0.5}
                y={y}
                width={Math.max(0.5, barW - 1)}
                height={h}
                fill="#3b82f6"
                pointerEvents="none"
              />
            )}
          </g>
        )
      })}
    </svg>
  )
}

// ── Main view ──────────────────────────────────────────────────────────────

const ACTION_COLOR: Record<string, string> = {
  drop: 'text-red-400',
  log: 'text-blue-400',
}

function formatTs(iso: string): string {
  return iso.replace('T', ' ').slice(0, 19) + 'Z'
}

type NodeTab = 'overview' | 'policy' | 'events' | 'rule-lifecycle'

interface EventsViewProps {
  onNavigateToNode?: (target: { nodeId: string; initialTab?: NodeTab }) => void
}

export default function EventsView({ onNavigateToNode }: EventsViewProps = {}) {
  const [form, setForm] = useState<FilterForm>(EMPTY_FORM)
  // `applied` is what actually drives the queries; form is the editing buffer.
  const [applied, setApplied] = useState<FilterForm>(EMPTY_FORM)
  const [items, setItems] = useState<EventRow[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [liveEnabled, setLiveEnabled] = useState(false)
  const [liveBuf, setLiveBuf] = useState<EventRow[]>([])

  const filterVar = useMemo(() => buildFilter(applied), [applied])

  // ── Node id → display name index (one-shot, no polling) ──
  const { data: nodesIdx } = useQuery<NodesIndexResp>(NODES_INDEX_QUERY, {
    fetchPolicy: 'cache-first',
  })
  const nodeLabel = useMemo(() => {
    const m = new Map<string, string>()
    for (const n of nodesIdx?.nodes ?? []) {
      m.set(n.id, n.hostname ?? n.label ?? shortId(n.id))
    }
    return (id: string) => m.get(id) ?? shortId(id)
  }, [nodesIdx])

  // ── (nodeId, ifindex) → interface name index (one-shot, no polling) ──
  const { data: ifacesIdx } = useQuery<InterfacesIndexResp>(INTERFACES_INDEX_QUERY, {
    fetchPolicy: 'cache-first',
  })
  const ifaceName = useMemo(() => {
    const m = new Map<string, string>()
    for (const i of ifacesIdx?.allNodeInterfaces ?? []) {
      if (i.ifindex > 0) m.set(`${i.nodeId}:${i.ifindex}`, i.name)
    }
    return (nodeId: string, ifindex: number) => {
      if (!ifindex) return '—'
      return m.get(`${nodeId}:${ifindex}`) ?? `if${ifindex}`
    }
  }, [ifacesIdx])

  // ── Historical page query ──
  const {
    data: page,
    loading: loadingPage,
    error: pageError,
    refetch: refetchPage,
    fetchMore,
  } = useQuery<EventsResp>(EVENTS_QUERY, {
    variables: { filter: filterVar, limit: PAGE_SIZE, cursor: null },
    fetchPolicy: 'network-only',
    notifyOnNetworkStatusChange: true,
  })

  // Reset accumulated rows when a fresh page arrives at cursor=null.
  useEffect(() => {
    if (page?.events) {
      setItems(page.events.items)
      setCursor(page.events.nextCursor)
    }
  }, [page])

  const loadMore = useCallback(async () => {
    if (!cursor) return
    const res = await fetchMore({
      variables: { filter: filterVar, limit: PAGE_SIZE, cursor },
    })
    const more = res.data?.events
    if (more) {
      setItems((prev) => [...prev, ...more.items])
      setCursor(more.nextCursor)
    }
  }, [cursor, fetchMore, filterVar])

  // ── Aggregate (bar chart) ──
  // Default window: last 60 minutes when no explicit since/until.
  const [chartWindow, setChartWindow] = useState<{ sinceMs: number; untilMs: number }>(() => {
    const now = Date.now()
    return { sinceMs: now - 60 * 60_000, untilMs: now }
  })

  // When applied filter has its own since/until, use that for the chart too.
  useEffect(() => {
    const since = toIsoZ(applied.since)
    const until = toIsoZ(applied.until)
    if (since && until) {
      setChartWindow({ sinceMs: Date.parse(since), untilMs: Date.parse(until) })
    } else if (since) {
      setChartWindow({ sinceMs: Date.parse(since), untilMs: Date.now() })
    } else {
      const now = Date.now()
      setChartWindow({ sinceMs: now - 60 * 60_000, untilMs: now })
    }
  }, [applied.since, applied.until])

  // Aggregate filter strips since/until (set by chart window separately).
  const aggregateFilter = useMemo(() => {
    if (!filterVar) return undefined
    const { since: _s, until: _u, ...rest } = filterVar as Record<string, unknown>
    return Object.keys(rest).length === 0 ? undefined : rest
  }, [filterVar])

  const { data: agg, refetch: refetchAgg } = useQuery<AggregateResp>(AGGREGATE_QUERY, {
    variables: {
      filter: aggregateFilter,
      groupBy: 'MINUTE',
      since: new Date(chartWindow.sinceMs).toISOString(),
      until: new Date(chartWindow.untilMs).toISOString(),
    },
    fetchPolicy: 'network-only',
  })

  // ── Clear (server-side buffer purge) ──
  const [clearEvents, { loading: clearing }] = useMutation<{
    clearEvents: { success: boolean; message: string | null }
  }>(CLEAR_EVENTS)

  const onClear = useCallback(async () => {
    if (!confirm('Clear all buffered events across the fleet? This cannot be undone.')) return
    try {
      await clearEvents()
      setItems([])
      setLiveBuf([])
      setCursor(null)
      await Promise.all([
        refetchPage({ filter: filterVar, limit: PAGE_SIZE, cursor: null }),
        refetchAgg(),
      ])
    } catch {
      // surfaced via pageError on the next refetch; nothing else to do
    }
  }, [clearEvents, refetchPage, refetchAgg, filterVar])

  // ── Live WS feed ──
  const wsRef = useRef<WebSocket | null>(null)
  useEffect(() => {
    if (!liveEnabled) {
      wsRef.current?.close()
      wsRef.current = null
      return
    }
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/ws/events`)
    wsRef.current = ws
    ws.onmessage = (e) => {
      try {
        const w = JSON.parse(e.data) as WireEvent
        const row = normalizeLive(w)
        if (!row) return
        setLiveBuf((prev) => {
          const next = [row, ...prev]
          return next.length > LIVE_BUFFER_MAX ? next.slice(0, LIVE_BUFFER_MAX) : next
        })
      } catch {
        // ignore
      }
    }
    ws.onerror = () => ws.close()
    return () => {
      ws.close()
      if (wsRef.current === ws) wsRef.current = null
    }
  }, [liveEnabled])

  // ── Handlers ──
  const onApply = (e: React.FormEvent) => {
    e.preventDefault()
    setApplied(form)
    setItems([])
    setCursor(null)
    refetchPage({ filter: buildFilter(form), limit: PAGE_SIZE, cursor: null })
  }

  const onReset = () => {
    setForm(EMPTY_FORM)
    setApplied(EMPTY_FORM)
    setItems([])
    setCursor(null)
    refetchPage({ filter: undefined, limit: PAGE_SIZE, cursor: null })
  }

  const onBucketClick = useCallback((sinceIso: string, untilIso: string) => {
    const sinceLocal = localFromIso(sinceIso)
    const untilLocal = localFromIso(untilIso)
    const next: FilterForm = { ...applied, since: sinceLocal, until: untilLocal }
    setForm(next)
    setApplied(next)
    setItems([])
    setCursor(null)
    refetchPage({ filter: buildFilter(next), limit: PAGE_SIZE, cursor: null })
  }, [applied, refetchPage])

  // Apply a partial filter patch (merged onto the currently applied filter)
  // and refetch. Drives click-to-filter on table cells.
  const applyPatch = useCallback((patch: Partial<FilterForm>) => {
    const next: FilterForm = { ...applied, ...patch }
    setForm(next)
    setApplied(next)
    setItems([])
    setCursor(null)
    refetchPage({ filter: buildFilter(next), limit: PAGE_SIZE, cursor: null })
  }, [applied, refetchPage])

  const rows = useMemo(() => {
    if (!liveEnabled) return items
    // Show live events at the top, then the historical page.
    return [...liveBuf, ...items]
  }, [liveEnabled, liveBuf, items])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-200">Events</h2>
        <div className="flex items-center gap-2">
          <button
            onClick={onClear}
            disabled={clearing}
            className="px-3 py-1.5 rounded text-sm font-medium bg-gray-700 hover:bg-red-800 text-gray-200 disabled:opacity-40"
            title="Clear all buffered events across the fleet"
          >
            Clear
          </button>
          <button
            onClick={() => setLiveEnabled((v) => !v)}
            className={`px-3 py-1.5 rounded text-sm font-medium ${
              liveEnabled
                ? 'bg-green-700 hover:bg-green-600 text-white'
                : 'bg-gray-700 hover:bg-gray-600 text-gray-200'
            }`}
          >
            {liveEnabled ? '● Live' : '○ Live'}
          </button>
        </div>
      </div>

      {/* Time-bucketed bar chart */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <div className="text-xs text-gray-500 font-mono">
            {new Date(chartWindow.sinceMs).toISOString().slice(0, 16)}Z →{' '}
            {new Date(chartWindow.untilMs).toISOString().slice(0, 16)}Z
          </div>
          <div className="text-xs text-gray-500">click a bar to drill in</div>
        </div>
        <MinuteBarChart
          buckets={agg?.eventAggregate ?? []}
          sinceMs={chartWindow.sinceMs}
          untilMs={chartWindow.untilMs}
          onClickBucket={onBucketClick}
        />
      </div>

      {/* Filter form */}
      <form
        onSubmit={onApply}
        className="grid grid-cols-2 md:grid-cols-4 gap-2 bg-gray-900 border border-gray-700 rounded-lg p-3 text-xs"
      >
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Since (UTC)</span>
          <input
            type="datetime-local"
            value={form.since}
            onChange={(e) => setForm({ ...form, since: e.target.value })}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Until (UTC)</span>
          <input
            type="datetime-local"
            value={form.until}
            onChange={(e) => setForm({ ...form, until: e.target.value })}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Action</span>
          <select
            value={form.action}
            onChange={(e) => setForm({ ...form, action: e.target.value as ActionFilter })}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
          >
            <option value="">any</option>
            <option value="DROP">drop</option>
            <option value="LOG">log</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Node ID</span>
          <input
            value={form.nodeId}
            onChange={(e) => setForm({ ...form, nodeId: e.target.value })}
            placeholder="(any)"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Rule ID</span>
          <input
            value={form.ruleId}
            onChange={(e) => setForm({ ...form, ruleId: e.target.value })}
            placeholder="(any)"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Src IP</span>
          <input
            value={form.srcIp}
            onChange={(e) => setForm({ ...form, srcIp: e.target.value })}
            placeholder="(any)"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Dst IP</span>
          <input
            value={form.dstIp}
            onChange={(e) => setForm({ ...form, dstIp: e.target.value })}
            placeholder="(any)"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Proto (num)</span>
          <input
            value={form.proto}
            onChange={(e) => setForm({ ...form, proto: e.target.value })}
            placeholder="6, 17, …"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Sport</span>
          <input
            value={form.sport}
            onChange={(e) => setForm({ ...form, sport: e.target.value })}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-gray-500">Dport</span>
          <input
            value={form.dport}
            onChange={(e) => setForm({ ...form, dport: e.target.value })}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label className="flex flex-col gap-1 md:col-span-2">
          <span className="text-gray-500">SNI LIKE</span>
          <input
            value={form.sniLike}
            onChange={(e) => setForm({ ...form, sniLike: e.target.value })}
            placeholder="%example.com"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <div className="flex items-end gap-2 md:col-span-2">
          <button
            type="submit"
            className="bg-blue-700 hover:bg-blue-600 text-white px-3 py-1.5 rounded"
          >
            Apply
          </button>
          <button
            type="button"
            onClick={onReset}
            className="bg-gray-700 hover:bg-gray-600 text-gray-200 px-3 py-1.5 rounded"
          >
            Reset
          </button>
        </div>
      </form>

      {pageError && <div className="text-red-400">Error: {pageError.message}</div>}

      {/* Table */}
      <div className="rounded-lg border border-gray-700 overflow-hidden">
        <table className="w-full text-xs font-mono">
          <thead className="bg-gray-800 text-gray-400">
            <tr>
              {['Time (UTC)', 'Action', 'Dir', 'Iface', 'Proto', 'Src', 'Dst', 'Rule', 'Node', 'SNI'].map((h) => (
                <th key={h} className="px-3 py-2 text-left">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.id}
                className={`border-t border-gray-800 hover:bg-gray-800/40 ${
                  r.live ? 'bg-green-900/10' : ''
                }`}
              >
                <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">
                  {formatTs(r.timestamp)}
                  {(() => {
                    const skewMs = (new Date(r.receivedAt).getTime() - new Date(r.timestamp).getTime())
                    if (Math.abs(skewMs) < 1000) return null
                    const s = (skewMs / 1000).toFixed(1)
                    return (
                      <span
                        className="ml-1.5 text-xs text-orange-400"
                        title={`Clock skew: agent timestamp vs controller receipt time (${s}s)`}
                      >
                        {skewMs > 0 ? `+${s}s` : `${s}s`}
                      </span>
                    )
                  })()}
                </td>
                <td className={`px-3 py-1.5 font-semibold ${ACTION_COLOR[r.action] ?? 'text-gray-300'}`}>
                  {r.action}
                </td>
                <td className="px-3 py-1.5 text-gray-400">{r.direction}</td>
                <td
                  className="px-3 py-1.5 text-gray-300"
                  title={r.ifindex ? `ifindex ${r.ifindex}` : undefined}
                >
                  {r.nodeId ? ifaceName(r.nodeId, r.ifindex) : r.ifindex ? `if${r.ifindex}` : '—'}
                </td>
                <td className="px-3 py-1.5 text-gray-400">{r.proto}</td>
                <td className="px-3 py-1.5">
                  <button
                    onClick={() => applyPatch({ srcIp: r.srcIp })}
                    className="text-blue-400 hover:text-blue-300 hover:underline focus:outline-none"
                    title="Filter by this source IP"
                  >
                    {r.srcIp}
                  </button>
                  {r.sport ? (
                    <>
                      <span className="text-gray-500">:</span>
                      <button
                        onClick={() => applyPatch({ sport: String(r.sport) })}
                        className="text-blue-400 hover:text-blue-300 hover:underline focus:outline-none"
                        title="Filter by this source port"
                      >
                        {r.sport}
                      </button>
                    </>
                  ) : null}
                </td>
                <td className="px-3 py-1.5">
                  <button
                    onClick={() => applyPatch({ dstIp: r.dstIp })}
                    className="text-blue-400 hover:text-blue-300 hover:underline focus:outline-none"
                    title="Filter by this destination IP"
                  >
                    {r.dstIp}
                  </button>
                  {r.dport ? (
                    <>
                      <span className="text-gray-500">:</span>
                      <button
                        onClick={() => applyPatch({ dport: String(r.dport) })}
                        className="text-blue-400 hover:text-blue-300 hover:underline focus:outline-none"
                        title="Filter by this destination port"
                      >
                        {r.dport}
                      </button>
                    </>
                  ) : null}
                </td>
                <td className="px-3 py-1.5">
                  {r.ruleId && r.nodeId && onNavigateToNode ? (
                    <button
                      onClick={() => onNavigateToNode({ nodeId: r.nodeId, initialTab: 'policy' })}
                      className="text-blue-400 hover:text-blue-300 hover:underline focus:outline-none focus:text-blue-300"
                      title={`Go to policy for node ${r.nodeId}`}
                    >
                      {r.ruleId}
                    </button>
                  ) : (
                    <span className="text-gray-400">{r.ruleId}</span>
                  )}
                </td>
                <td className="px-3 py-1.5" title={r.nodeId || undefined}>
                  {r.nodeId ? (
                    onNavigateToNode ? (
                      <button
                        onClick={() => onNavigateToNode({ nodeId: r.nodeId })}
                        className="text-blue-400 hover:text-blue-300 hover:underline focus:outline-none focus:text-blue-300"
                      >
                        {nodeLabel(r.nodeId)}
                      </button>
                    ) : (
                      <span className="text-gray-300">{nodeLabel(r.nodeId)}</span>
                    )
                  ) : (
                    <span className="text-gray-500">—</span>
                  )}
                </td>
                <td className="px-3 py-1.5 text-gray-400 max-w-xs truncate">
                  {r.sni ?? '—'}
                </td>
              </tr>
            ))}
            {!loadingPage && rows.length === 0 && (
              <tr>
                <td colSpan={10} className="px-4 py-8 text-center text-gray-600">
                  No events match the current filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-500">
          {loadingPage ? 'Loading…' : `${rows.length} row${rows.length === 1 ? '' : 's'}`}
        </span>
        <button
          disabled={!cursor || loadingPage}
          onClick={loadMore}
          className="px-3 py-1 rounded bg-gray-700 hover:bg-gray-600 disabled:opacity-40"
        >
          Load more
        </button>
      </div>
    </div>
  )
}
