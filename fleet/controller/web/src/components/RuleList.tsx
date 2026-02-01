// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useMutation, useQuery, gql } from '@apollo/client'
import { RuleOutput, fmtBytes, fmtCount } from './types.ts'

const DELETE_RULE = gql`
  mutation DeleteRule($ruleId: ID!) {
    deleteRule(ruleId: $ruleId) { success message }
  }
`

const FLUSH_RULES = gql`
  mutation FlushRules($nodeId: ID!, $interfaceName: String!, $direction: String!) {
    flushRules(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) {
      success
      message
    }
  }
`

const GET_RULE_STATS = gql`
  query NodeRuleStats($nodeId: ID!, $ruleId: ID!, $direction: String!) {
    nodeRuleStats(nodeId: $nodeId, ruleId: $ruleId, direction: $direction) {
      packets bytes
    }
  }
`

interface Props {
  rules: RuleOutput[]
  direction: string
  nodeId?: string
  interfaceName?: string
  onRefetch: () => void
  onFlash?: (msg: string) => void
  onPendingChange?: (pending: boolean, opKind?: string) => void
  isPending?: boolean
}

function RuleStatCell({ nodeId, ruleId, direction }: { nodeId: string; ruleId: string; direction: string }) {
  const { data, loading } = useQuery<{ nodeRuleStats: { packets: number; bytes: number } | null }>(
    GET_RULE_STATS,
    { variables: { nodeId, ruleId, direction }, pollInterval: 30_000 },
  )
  const s = data?.nodeRuleStats
  if (loading && !s) return <td className="px-2 py-1 text-gray-600 text-xs">…</td>
  if (!s) return <td className="px-2 py-1 text-gray-600 text-xs">—</td>
  return (
    <td className="px-2 py-1 text-xs whitespace-nowrap">
      <span className={s.packets > 0 ? 'text-blue-300' : 'text-gray-600'}>{fmtCount(s.packets)}</span>
      <span className="text-gray-600 mx-0.5">/</span>
      <span className={s.packets > 0 ? 'text-gray-300' : 'text-gray-600'}>{fmtBytes(s.bytes)}</span>
    </td>
  )
}

const DAY_ABBR = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

interface ScheduleWindow {
  start: { dayOfWeek: number; hour: number; minute: number }
  end: { dayOfWeek: number; hour: number; minute: number }
}

interface ParsedSchedule {
  timezone: string
  windows: ScheduleWindow[]
}

function hhmm(h: number, m: number): string {
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`
}

function formatWindow(w: ScheduleWindow): string {
  const sDay = DAY_ABBR[w.start.dayOfWeek] ?? `D${w.start.dayOfWeek}`
  const eDay = DAY_ABBR[w.end.dayOfWeek] ?? `D${w.end.dayOfWeek}`
  const sTime = hhmm(w.start.hour, w.start.minute)
  const eTime = hhmm(w.end.hour, w.end.minute)
  if (w.start.dayOfWeek === w.end.dayOfWeek) return `${sDay} ${sTime}–${eTime}`
  return `${sDay} ${sTime} – ${eDay} ${eTime}`
}

function parseSchedule(json: string): ParsedSchedule | null {
  try {
    return JSON.parse(json) as ParsedSchedule
  } catch {
    return null
  }
}

function LifecycleCell({ r }: { r: RuleOutput }) {
  if (r.expiresAfterSecs != null) {
    return <span className="text-orange-400">TTL {r.expiresAfterSecs}s</span>
  }
  if (r.scheduleJson) {
    const sched = parseSchedule(r.scheduleJson)
    if (!sched) return <span className="text-cyan-400">Sched</span>
    const tz = sched.timezone ?? 'UTC'
    const windows = sched.windows ?? []
    return (
      <span className="text-cyan-400">
        <span className="block">Sched ({windows.length}w, {tz})</span>
        {windows.map((w, i) => (
          <span key={i} className="block text-cyan-600/80">{formatWindow(w)}</span>
        ))}
      </span>
    )
  }
  return <span className="text-gray-600">—</span>
}

function formatActions(actionsJson: string): string {
  try {
    const actions = JSON.parse(actionsJson) as { action: string; priority: number; param?: number }[]
    return actions.map((a) => {
      let s = `${a.action.toUpperCase()}:${a.priority}`
      if (a.action === 'log' && a.param) s += ` (${a.param}ms)`
      return s
    }).join(', ')
  } catch {
    return actionsJson
  }
}

export default function RuleList({ rules, direction, nodeId, interfaceName, onRefetch, onFlash, onPendingChange, isPending }: Props) {
  const [deleteRule] = useMutation(DELETE_RULE)
  const [flushRules] = useMutation(FLUSH_RULES)

  const filtered = rules.filter(
    (r) => r.direction.toLowerCase() === direction.toLowerCase(),
  )

  async function handleDelete(ruleId: string) {
    if (!confirm('Delete this rule?')) return
    onPendingChange?.(true, 'delete_rule')
    try {
      const result = await deleteRule({ variables: { ruleId } })
      onRefetch()
      const dr = (result.data as any)?.deleteRule
      if (dr?.success === true) {
        onFlash?.('Rule deleted.')
      } else if (dr?.success === false) {
        onFlash?.(`Delete failed: ${dr.message ?? 'unknown error'}`)
      }
    } finally {
      onPendingChange?.(false)
    }
  }

  async function handleFlush() {
    if (!nodeId || !interfaceName) return
    if (!confirm(`Delete all ${filtered.length} ${direction} rule(s) on ${interfaceName}?`)) return
    onPendingChange?.(true, 'flush_rules')
    try {
      const result = await flushRules({
        variables: { nodeId, interfaceName, direction },
      })
      onRefetch()
      const fr = (result.data as any)?.flushRules
      if (fr?.success === true) {
        onFlash?.(fr.message ?? 'Rules flushed.')
      } else if (fr?.success === false) {
        onFlash?.(`Flush failed: ${fr.message ?? 'unknown error'}`)
      }
    } finally {
      onPendingChange?.(false)
    }
  }

  if (filtered.length === 0) {
    return (
      <div className="text-xs text-gray-600 py-2 px-3">
        No {direction} rules.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      {nodeId && interfaceName && (
        <div className="flex justify-end px-2 pt-1">
          <button
            onClick={handleFlush}
            disabled={isPending}
            className="text-xs text-red-500 hover:text-red-400 disabled:opacity-40 disabled:cursor-not-allowed"
            title={`Delete all ${direction} rules on ${interfaceName}`}
          >
            Delete all
          </button>
        </div>
      )}
      <table className="w-full text-xs">
        <thead className="text-gray-500 uppercase bg-gray-900/50">
          <tr>
            {['Src', 'Dst', 'Ports', 'Proto', 'SNI', 'MAC', 'Actions', 'Lifecycle', ...(nodeId ? ['Hits / Bytes'] : []), 'Created', ''].map((h) => (
              <th key={h} className={`px-2 py-1 text-left font-medium${h === 'Hits / Bytes' ? ' text-blue-500/70' : ''}`}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.map((r) => (
            <tr key={r.id} className="border-t border-gray-800 hover:bg-gray-800/50">
              <td className="px-2 py-1 text-gray-300">{r.srcCidr ?? 'any'}</td>
              <td className="px-2 py-1 text-gray-300">{r.dstCidr ?? 'any'}</td>
              <td className="px-2 py-1 text-gray-400">
                {r.srcPort ?? '*'}:{r.dstPort ?? '*'}
              </td>
              <td className="px-2 py-1 text-gray-400">{r.protocol}</td>
              <td className="px-2 py-1 text-gray-400">{r.sniPattern ?? '—'}</td>
              <td className="px-2 py-1 text-gray-500">
                {r.srcMac || r.dstMac
                  ? `${r.srcMac ?? '*'} / ${r.dstMac ?? '*'}`
                  : '—'}
              </td>
              <td className="px-2 py-1 text-gray-300">{formatActions(r.actionsJson)}</td>
              <td className="px-2 py-1"><LifecycleCell r={r} /></td>
              {nodeId && (
                <RuleStatCell nodeId={nodeId} ruleId={r.id} direction={r.direction} />
              )}
              <td className="px-2 py-1 text-gray-600">
                {new Date(r.createdAt).toLocaleDateString()}
              </td>
              <td className="px-2 py-1">
                <button
                  onClick={() => handleDelete(r.id)}
                  disabled={isPending}
                  className="text-red-500 hover:text-red-400 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
