// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { gql, useQuery, useMutation } from '@apollo/client'
import { useState } from 'react'
import { getPortName } from './portMappings'
import { isMulticast } from './netUtils'
import { getIcmpTypeName, getIcmpCodeName } from './icmpMappings'
import { getProtocolName } from './protocolMappings'

const GET_RULES = gql`
  query GetRules($direction: GqlDirection!) {
    rules(direction: $direction) {
      ruleId
      interface
      srcPrefix
      dstPrefix
      sport
      dport
      protocol
      actions {
        action
        priority
        param
      }
      sni
      quicVersion
      srcMac
      dstMac
    }
  }
`

const GET_ATTACHED_INTERFACES = gql`
  query GetAttachedInterfaces {
    interfaces {
      interface
      direction
      mode
    }
  }
`

const GET_RULE_STATS = gql`
  query GetRuleStats($ruleId: String!, $direction: GqlDirection!) {
    ruleStats(ruleId: $ruleId, direction: $direction) {
      packets
      bytes
      lastSeenNs
    }
  }
`

const ADD_RULE = gql`
  mutation AddRule($input: AddRuleInput!) {
    addRule(input: $input) {
      success
      message
    }
  }
`

const DELETE_RULE = gql`
  mutation DeleteRule($input: DeleteRuleInput!) {
    deleteRule(input: $input) {
      success
      message
    }
  }
`

const FLUSH_RULES = gql`
  mutation FlushRules($interface: String!, $direction: GqlDirection!) {
    flushRules(interface: $interface, direction: $direction) {
      success
      message
    }
  }
`

const GET_MANAGED_RULES = gql`
  query GetManagedRules($direction: GqlDirection!) {
    managedRules(direction: $direction) {
      ruleId
      ruleState
      expiresAtMs
      schedule {
        windows {
          start { dayOfWeek hour minute }
          end   { dayOfWeek hour minute }
        }
        timezone
      }
    }
  }
`

interface RuleAction {
  action: string
  priority: number
  param: number
}

interface PolicyRule {
  ruleId: string
  interface: string
  srcPrefix: string
  dstPrefix: string
  sport: number | null
  dport: number | null
  protocol: string
  actions: RuleAction[]
  sni: string | null
  quicVersion: string | null
  srcMac: string | null
  dstMac: string | null
}

interface AttachedInterface {
  interface: string
  direction: string
  mode: string
}

interface InterfacesData {
  interfaces: AttachedInterface[]
}

interface RulesData {
  rules: PolicyRule[]
}

interface WeeklyTimePoint { dayOfWeek: number; hour: number; minute: number }
interface WeeklyWindow { start: WeeklyTimePoint; end: WeeklyTimePoint }

interface ManagedRule {
  ruleId: string
  ruleState: string
  expiresAtMs: string | null
  schedule: { windows: WeeklyWindow[]; timezone: string } | null
}

interface ManagedRulesData {
  managedRules: ManagedRule[]
}

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

function pad2(n: number) { return String(n).padStart(2, '0') }

function formatWeeklyPoint(p: WeeklyTimePoint) {
  return `${DAY_NAMES[p.dayOfWeek]} ${pad2(p.hour)}:${pad2(p.minute)}`
}

function formatExpiresAt(ms: string): string {
  const d = new Date(parseInt(ms))
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
}

interface LifecycleWindowInput { startDay: string; startHH: string; startMM: string; endDay: string; endHH: string; endMM: string }

interface RuleStatsData {
  ruleStats: {
    packets: number
    bytes: number
    lastSeenNs: number
  } | null
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

function RuleRow({
  rule,
  direction,
  managed,
  onDelete,
}: {
  rule: PolicyRule
  direction: 'INGRESS' | 'EGRESS'
  managed?: ManagedRule
  onDelete: (ruleId: string, iface: string) => void
}) {
  const { data: statsData } = useQuery<RuleStatsData>(GET_RULE_STATS, {
    variables: { ruleId: String(rule.ruleId), direction },
    pollInterval: 2000,
  })

  const stats = statsData?.ruleStats

  // Determine port names if protocol is tcp/udp
  const proto = rule.protocol.toLowerCase();
  const showPortNames = proto === 'tcp' || proto === 'udp';
  const showIcmpNames = proto === 'icmp';
  const sportName =
    showPortNames && rule.sport != null
      ? getPortName(proto, rule.sport)
      : null;
  const dportName =
    showPortNames && rule.dport != null
      ? getPortName(proto, rule.dport)
      : null;
  // ICMP type/code display
  const icmpTypeName =
    showIcmpNames && rule.sport != null
      ? getIcmpTypeName(rule.sport, false) // TODO: detect IPv6 if needed
      : null;
  const icmpCodeName =
    showIcmpNames && rule.sport != null && rule.dport != null
      ? getIcmpCodeName(rule.sport, rule.dport, false)
      : null;

  // Helper to extract address from prefix (e.g., 224.0.0.1/32 -> 224.0.0.1)
  const extractAddr = (prefix: string) => prefix.split('/')[0];
  const srcAddr = extractAddr(rule.srcPrefix);
  const dstAddr = extractAddr(rule.dstPrefix);
  const srcIsMc = isMulticast(srcAddr);
  const dstIsMc = isMulticast(dstAddr);

  return (
    <tr className="border-b border-gray-700/50 hover:bg-gray-700/30">
      <td className="py-2 px-2 font-mono text-xs">{rule.ruleId}</td>
      <td className="py-2 px-2 font-mono text-xs text-cyan-300">{rule.interface || '-'}</td>
      <td className="py-2 px-2 font-mono">
        {rule.srcPrefix}
        {srcIsMc && <span title="Multicast" className="ml-1 text-xs text-yellow-400 font-bold">M</span>}
      </td>
      <td className="py-2 px-2 font-mono">
        {rule.dstPrefix}
        {dstIsMc && <span title="Multicast" className="ml-1 text-xs text-yellow-400 font-bold">M</span>}
      </td>
      <td className="py-2 px-2 uppercase">{getProtocolName(rule.protocol)}</td>
      <td className="py-2 px-2">
        {showPortNames ? (
          <>
            <span className="font-mono">{rule.sport ?? '*'}</span>
            {rule.sport != null && (
              <span className="ml-1 text-xs text-gray-400">[{sportName ?? 'unknown'}]</span>
            )}
            :
            <span className="font-mono">{rule.dport ?? '*'}</span>
            {rule.dport != null && (
              <span className="ml-1 text-xs text-gray-400">[{dportName ?? 'unknown'}]</span>
            )}
          </>
        ) : showIcmpNames ? (
          <>
            <span className="font-mono">{rule.sport ?? '*'}</span>
            {rule.sport != null && (
              <span className="ml-1 text-xs text-gray-400">[{icmpTypeName ?? 'unknown'}]</span>
            )}
            :
            <span className="font-mono">{rule.dport ?? '*'}</span>
            {rule.sport != null && rule.dport != null && (
              <span className="ml-1 text-xs text-gray-400">[{icmpCodeName ?? 'unknown'}]</span>
            )}
          </>
        ) : (
          <>
            <span className="font-mono">{rule.sport ?? '*'}</span>:
            <span className="font-mono">{rule.dport ?? '*'}</span>
          </>
        )}
      </td>
      <td className="py-2 px-2">
        {rule.actions.map((a, i) => (
          <span
            key={i}
            className={`inline-block px-2 py-0.5 rounded text-xs mr-1 ${
              a.action === 'DROP'
                ? 'bg-red-500/20 text-red-400'
                : a.action === 'PASS'
                  ? 'bg-green-500/20 text-green-400'
                  : a.action === 'INSPECT'
                    ? 'bg-purple-500/20 text-purple-400'
                    : 'bg-yellow-500/20 text-yellow-400'
            }`}
            title={a.action === 'LOG' && a.param > 0 ? `Rate limit: ${a.param}ms` : undefined}
          >
            {a.action}{a.action === 'LOG' && a.param > 0 ? ` (${a.param}ms)` : ''}
          </span>
        ))}
      </td>
      <td className="py-2 px-2 font-mono text-xs">
        {rule.sni && <span className="text-cyan-400">{rule.sni}</span>}
        {rule.quicVersion && (
          <span className="text-cyan-300 ml-1" title={`QUIC ${rule.quicVersion}`}>
            {rule.quicVersion === 'any' ? 'QUIC' : `QUIC-${rule.quicVersion.toUpperCase()}`}
          </span>
        )}
        {!rule.sni && !rule.quicVersion && <span className="text-gray-600">-</span>}
      </td>
      <td className="py-2 px-2 font-mono text-xs">
        {rule.srcMac && (
          <div><span className="text-gray-500 text-xs">src </span><span className="text-orange-400">{rule.srcMac}</span></div>
        )}
        {rule.dstMac && (
          <div><span className="text-gray-500 text-xs">dst </span><span className="text-orange-300">{rule.dstMac}</span></div>
        )}
        {!rule.srcMac && !rule.dstMac && <span className="text-gray-600">-</span>}
      </td>
      <td className="py-2 px-2 font-mono text-xs">
        {managed ? (
          managed.expiresAtMs ? (
            <span className="text-orange-400" title={`Expires ${formatExpiresAt(managed.expiresAtMs)}`}>
              TTL
            </span>
          ) : managed.schedule ? (
            <span
              className="text-cyan-400 cursor-default"
              title={`${managed.schedule.timezone}\n` + managed.schedule.windows.map(w => `${formatWeeklyPoint(w.start)} → ${formatWeeklyPoint(w.end)}`).join('\n')}
            >
              Sched
            </span>
          ) : null
        ) : (
          <span className="text-gray-600">-</span>
        )}
      </td>
      <td className="py-2 px-2 text-right font-mono text-xs text-gray-400">
        {stats ? (
          <span title={`${formatNumber(stats.packets)} packets, ${formatBytes(stats.bytes)}`}>
            {formatNumber(stats.packets)} pkts / {formatBytes(stats.bytes)}
          </span>
        ) : (
          <span className="text-gray-600">-</span>
        )}
      </td>
      <td className="py-2 px-2 text-right">
        <button
          onClick={() => onDelete(rule.ruleId, rule.interface)}
          className="px-2 py-1 text-xs bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition"
        >
          Delete
        </button>
      </td>
    </tr>
  )
}

export function RulesList({ inspectSupported = false }: { inspectSupported?: boolean }) {
  const [activeDirection, setActiveDirection] = useState<'INGRESS' | 'EGRESS'>('INGRESS')

  const { loading, error, data, refetch } = useQuery<RulesData>(GET_RULES, {
    variables: { direction: activeDirection },
    pollInterval: 5000,
  })
  const { data: managedData, refetch: refetchManaged } = useQuery<ManagedRulesData>(GET_MANAGED_RULES, {
    variables: { direction: activeDirection },
    pollInterval: 10000,
  })
  const { data: interfacesData } = useQuery<InterfacesData>(GET_ATTACHED_INTERFACES, {
    pollInterval: 10000,
  })
  const [addRule] = useMutation<{ addRule: OperationResult }>(ADD_RULE)
  const [deleteRule] = useMutation<{ deleteRule: OperationResult }>(DELETE_RULE)
  const [flushRules] = useMutation<{ flushRules: OperationResult }>(FLUSH_RULES)

  const [showAddForm, setShowAddForm] = useState(false)
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Interfaces attached in the active direction — used to populate the form dropdown.
  // The backend reports direction as a lowercase string ("ingress"/"egress"),
  // while activeDirection is uppercase, so compare case-insensitively.
  const availableInterfaces = Array.from(
    new Set(
      (interfacesData?.interfaces ?? [])
        .filter((i) => i.direction.toUpperCase() === activeDirection)
        .map((i) => i.interface),
    ),
  )

  // Form state
  const [formData, setFormData] = useState({
    interface: '',
    src: '0.0.0.0/0',
    dst: '0.0.0.0/0',
    sport: '',
    dport: '',
    protocol: 'any',
    sni: '',
    quicVersion: '',
    srcMac: '',
    dstMac: '',
  })
  // Multi-action list: each entry has { action, param (ms, for LOG rate-limiting) }
  const [formActions, setFormActions] = useState<Array<{ action: string; param: string }>>([
    { action: 'DROP', param: '' },
  ])
  // Lifecycle mode
  const [lifecycleMode, setLifecycleMode] = useState<'permanent' | 'ttl' | 'scheduled'>('permanent')
  const [ttlSecs, setTtlSecs] = useState('')
  const [scheduleTz, setScheduleTz] = useState('UTC')
  const [scheduleWindows, setScheduleWindows] = useState<LifecycleWindowInput[]>([
    { startDay: '0', startHH: '00', startMM: '00', endDay: '5', endHH: '00', endMM: '00' },
  ])

  // Build lookup map for managed rules
  const managedByRuleId = new Map<string, ManagedRule>()
  for (const mr of managedData?.managedRules ?? []) {
    managedByRuleId.set(String(mr.ruleId), mr)
  }

  const handleAddRule = async () => {
    if (!formData.interface) {
      setFeedback({ type: 'error', message: 'Interface is required' })
      return
    }
    if (formData.sni && formData.protocol !== 'tcp' && formData.protocol !== 'udp') {
      setFeedback({ type: 'error', message: 'SNI matching requires TCP or UDP protocol' })
      return
    }
    if (formData.quicVersion && formData.protocol !== 'udp' && formData.protocol !== 'any') {
      setFeedback({ type: 'error', message: 'QUIC version matching requires UDP or Any protocol' })
      return
    }
    const macRe = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/
    if (formData.srcMac && !macRe.test(formData.srcMac)) {
      setFeedback({ type: 'error', message: 'Invalid source MAC address (expected aa:bb:cc:dd:ee:ff)' })
      return
    }
    if (formData.dstMac && !macRe.test(formData.dstMac)) {
      setFeedback({ type: 'error', message: 'Invalid destination MAC address (expected aa:bb:cc:dd:ee:ff)' })
      return
    }
    if (formActions.length === 0) {
      setFeedback({ type: 'error', message: 'At least one action must be specified' })
      return
    }
    try {
      const actions = formActions.map((a, i) => ({
        action: a.action,
        priority: i,
        param: a.action === 'LOG' && a.param ? parseInt(a.param) : 0,
      }))

      let expiresAfterSecs: number | null = null
      let schedule: object | null = null

      if (lifecycleMode === 'ttl') {
        const v = parseInt(ttlSecs)
        if (!ttlSecs || isNaN(v) || v <= 0) {
          setFeedback({ type: 'error', message: 'TTL must be a positive number of seconds' })
          return
        }
        expiresAfterSecs = v
      } else if (lifecycleMode === 'scheduled') {
        if (scheduleWindows.length === 0) {
          setFeedback({ type: 'error', message: 'At least one schedule window is required' })
          return
        }
        schedule = {
          timezone: scheduleTz || 'UTC',
          windows: scheduleWindows.map(w => ({
            start: { dayOfWeek: parseInt(w.startDay), hour: parseInt(w.startHH), minute: parseInt(w.startMM) },
            end:   { dayOfWeek: parseInt(w.endDay),   hour: parseInt(w.endHH),   minute: parseInt(w.endMM)   },
          })),
        }
      }

      const result = await addRule({
        variables: {
          input: {
            interface: formData.interface,
            direction: activeDirection,
            src: formData.src || null,
            dst: formData.dst || null,
            sport: formData.sport ? parseInt(formData.sport) : 0,
            dport: formData.dport ? parseInt(formData.dport) : 0,
            protocol: formData.protocol,
            actions,
            sni: formData.sni || null,
            quicVersion: formData.quicVersion || null,
            srcMac: formData.srcMac || null,
            dstMac: formData.dstMac || null,
            expiresAfterSecs,
            schedule,
          },
        },
      })
      if (result.data?.addRule.success) {
        setFeedback({ type: 'success', message: result.data.addRule.message })
        setShowAddForm(false)
        setFormData({
          interface: '',
          src: '0.0.0.0/0',
          dst: '0.0.0.0/0',
          sport: '',
          dport: '',
          protocol: 'any',
          sni: '',
          quicVersion: '',
          srcMac: '',
          dstMac: '',
        })
        setFormActions([{ action: 'DROP', param: '' }])
        setLifecycleMode('permanent')
        setTtlSecs('')
        setScheduleWindows([{ startDay: '0', startHH: '00', startMM: '00', endDay: '5', endHH: '00', endMM: '00' }])
        refetch()
        refetchManaged()
      } else {
        setFeedback({ type: 'error', message: result.data?.addRule.message || 'Failed to add rule' })
      }
    } catch (e) {
      setFeedback({ type: 'error', message: String(e) })
    }

    setTimeout(() => setFeedback(null), 5000)
  }

  const handleDeleteRule = async (ruleId: string, iface: string) => {
    try {
      const result = await deleteRule({
        variables: {
          input: { interface: iface, direction: activeDirection, id: String(ruleId) },
        },
      })
      if (result.data?.deleteRule.success) {
        setFeedback({ type: 'success', message: result.data.deleteRule.message })
        refetch()
        refetchManaged()
      }
    } catch (e) {
      setFeedback({ type: 'error', message: String(e) })
    }

    setTimeout(() => setFeedback(null), 5000)
  }

  const handleFlushRules = async (iface: string) => {
    if (!iface) return
    if (!confirm(`Delete all ${activeDirection.toLowerCase()} rules on ${iface}?`)) return

    try {
      const result = await flushRules({
        variables: { interface: iface, direction: activeDirection },
      })
      if (result.data?.flushRules.success) {
        setFeedback({ type: 'success', message: result.data.flushRules.message })
        refetch()
      }
    } catch (e) {
      setFeedback({ type: 'error', message: String(e) })
    }

    setTimeout(() => setFeedback(null), 5000)
  }

  if (loading && !data) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4">Policy Rules</h2>
        <div className="animate-pulse space-y-2">
          <div className="h-12 bg-gray-700 rounded"></div>
          <div className="h-12 bg-gray-700 rounded"></div>
          <div className="h-12 bg-gray-700 rounded"></div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-900/50 border border-red-500 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4 text-red-400">Policy Rules</h2>
        <p className="text-red-300">Error: {error.message}</p>
      </div>
    )
  }

  const rules = data?.rules || []

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
      <div className="flex justify-between items-center mb-4">
        <div className="flex items-center gap-4">
          <h2 className="text-xl font-semibold">Policy Rules</h2>
          <div className="flex rounded-lg overflow-hidden border border-gray-600">
            <button
              onClick={() => setActiveDirection('INGRESS')}
              className={`px-3 py-1 text-sm transition ${
                activeDirection === 'INGRESS'
                  ? 'bg-blue-500/30 text-blue-400'
                  : 'bg-gray-700 text-gray-400 hover:text-white'
              }`}
            >
              Ingress
            </button>
            <button
              onClick={() => {
                setActiveDirection('EGRESS')
                // INSPECT is ingress-only; reset any INSPECT actions to DROP when switching to egress
                setFormActions((prev) =>
                  prev.map((a) => (a.action === 'INSPECT' ? { ...a, action: 'DROP' } : a))
                )
              }}
              className={`px-3 py-1 text-sm transition ${
                activeDirection === 'EGRESS'
                  ? 'bg-purple-500/30 text-purple-400'
                  : 'bg-gray-700 text-gray-400 hover:text-white'
              }`}
            >
              Egress
            </button>
          </div>
          <span className="text-gray-500 text-sm">({rules.length})</span>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            className="px-3 py-1 text-sm bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30 transition"
          >
            {showAddForm ? 'Cancel' : 'Add Rule'}
          </button>
          {Array.from(new Set(rules.map((r) => r.interface))).map((iface) => (
            <button
              key={iface}
              onClick={() => handleFlushRules(iface)}
              className="px-3 py-1 text-sm bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition"
              title={`Delete all ${activeDirection.toLowerCase()} rules on ${iface}`}
            >
              Flush {iface}
            </button>
          ))}
        </div>
      </div>

      {feedback && (
        <div
          className={`mb-4 p-3 rounded ${
            feedback.type === 'success'
              ? 'bg-green-500/20 text-green-400'
              : 'bg-red-500/20 text-red-400'
          }`}
        >
          {feedback.message}
        </div>
      )}

      {/* Add rule form */}
      {showAddForm && (
        <div className="mb-4 p-4 bg-gray-700/50 rounded-lg">
          <h3 className="text-sm font-medium text-gray-400 mb-3">
            Add New {activeDirection === 'INGRESS' ? 'Ingress' : 'Egress'} Rule
          </h3>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div className="col-span-2">
              <label className="block text-xs text-gray-400 mb-1">Interface</label>
              {availableInterfaces.length === 0 ? (
                <div className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 text-sm text-gray-400">
                  No interfaces attached in {activeDirection.toLowerCase()}. Attach one first.
                </div>
              ) : (
                <select
                  value={formData.interface}
                  onChange={(e) => setFormData({ ...formData, interface: e.target.value })}
                  className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
                >
                  <option value="">Select interface…</option>
                  {availableInterfaces.map((name) => (
                    <option key={name} value={name}>{name}</option>
                  ))}
                </select>
              )}
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Source CIDR</label>
              <input
                type="text"
                value={formData.src}
                onChange={(e) => setFormData({ ...formData, src: e.target.value })}
                placeholder="0.0.0.0/0"
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Destination CIDR</label>
              <input
                type="text"
                value={formData.dst}
                onChange={(e) => setFormData({ ...formData, dst: e.target.value })}
                placeholder="0.0.0.0/0"
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Source Port (0 = any)</label>
              <input
                type="number"
                value={formData.sport}
                onChange={(e) => setFormData({ ...formData, sport: e.target.value })}
                placeholder="0"
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Destination Port (0 = any)</label>
              <input
                type="number"
                value={formData.dport}
                onChange={(e) => setFormData({ ...formData, dport: e.target.value })}
                placeholder="0"
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Protocol</label>
              <select
                value={formData.protocol}
                onChange={(e) => setFormData({
                  ...formData,
                  protocol: e.target.value,
                  sni: (e.target.value !== 'tcp' && e.target.value !== 'udp') ? '' : formData.sni,
                  quicVersion: (e.target.value !== 'udp' && e.target.value !== 'any') ? '' : formData.quicVersion,
                })}
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
              >
                <option value="any">Any</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">SNI (TCP or UDP/QUIC)</label>
              <input
                type="text"
                value={formData.sni}
                onChange={(e) => setFormData({ ...formData, sni: e.target.value })}
                placeholder="example.com or *.example.com"
                disabled={formData.protocol !== 'tcp' && formData.protocol !== 'udp'}
                className={`w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm ${formData.protocol !== 'tcp' && formData.protocol !== 'udp' ? 'opacity-50 cursor-not-allowed' : ''}`}
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">QUIC Version (UDP/Any only)</label>
              <select
                value={formData.quicVersion}
                onChange={(e) => setFormData({ ...formData, quicVersion: e.target.value })}
                disabled={formData.protocol !== 'udp' && formData.protocol !== 'any'}
                className={`w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm ${formData.protocol !== 'udp' && formData.protocol !== 'any' ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <option value="">None</option>
                <option value="any">Any QUIC</option>
                <option value="v1">QUIC v1 (RFC 9000)</option>
                <option value="v2">QUIC v2 (RFC 9369)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Source MAC (optional)</label>
              <input
                type="text"
                value={formData.srcMac}
                onChange={(e) => setFormData({ ...formData, srcMac: e.target.value })}
                placeholder="aa:bb:cc:dd:ee:ff"
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Destination MAC (optional)</label>
              <input
                type="text"
                value={formData.dstMac}
                onChange={(e) => setFormData({ ...formData, dstMac: e.target.value })}
                placeholder="aa:bb:cc:dd:ee:ff"
                className="w-full px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm font-mono"
              />
            </div>
          </div>
          {/* Lifecycle mode */}
          <div className="mb-4">
            <label className="block text-xs text-gray-400 mb-2">Lifecycle</label>
            <div className="flex gap-2 mb-3">
              {(['permanent', 'ttl', 'scheduled'] as const).map(mode => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setLifecycleMode(mode)}
                  className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                    lifecycleMode === mode
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-600 hover:bg-gray-500 text-gray-300'
                  }`}
                >
                  {mode === 'permanent' ? 'Permanent' : mode === 'ttl' ? 'TTL' : 'Scheduled'}
                </button>
              ))}
            </div>
            {lifecycleMode === 'ttl' && (
              <div>
                <label className="block text-xs text-gray-400 mb-1">Expire after (seconds)</label>
                <input
                  type="number"
                  value={ttlSecs}
                  onChange={e => setTtlSecs(e.target.value)}
                  placeholder="e.g. 3600"
                  min="1"
                  className="w-48 px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
                />
              </div>
            )}
            {lifecycleMode === 'scheduled' && (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Timezone (IANA)</label>
                  <input
                    type="text"
                    value={scheduleTz}
                    onChange={e => setScheduleTz(e.target.value)}
                    placeholder="UTC"
                    className="w-56 px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
                  />
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs text-gray-400">Windows (active when inside any window)</label>
                    <button
                      type="button"
                      onClick={() => setScheduleWindows([...scheduleWindows, { startDay: '0', startHH: '00', startMM: '00', endDay: '1', endHH: '00', endMM: '00' }])}
                      className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30 transition"
                    >
                      + Add Window
                    </button>
                  </div>
                  <div className="space-y-2">
                    {scheduleWindows.map((w, idx) => (
                      <div key={idx} className="flex items-center gap-1 flex-wrap">
                        <span className="text-xs text-gray-500 w-4">{idx + 1}.</span>
                        {(['startDay', 'endDay'] as const).map((dayKey, di) => {
                          const hhKey = di === 0 ? 'startHH' : 'endHH'
                          const mmKey = di === 0 ? 'startMM' : 'endMM'
                          return (
                            <div key={di} className="flex items-center gap-1">
                              {di === 1 && <span className="text-xs text-gray-500">→</span>}
                              <select
                                value={w[dayKey]}
                                onChange={e => { const u = [...scheduleWindows]; u[idx] = { ...u[idx], [dayKey]: e.target.value }; setScheduleWindows(u) }}
                                className="px-1 py-1 bg-gray-700 rounded border border-gray-600 text-xs focus:outline-none"
                              >
                                {DAY_NAMES.map((d, i) => <option key={i} value={String(i)}>{d}</option>)}
                              </select>
                              <input type="text" value={w[hhKey]} onChange={e => { const u = [...scheduleWindows]; u[idx] = { ...u[idx], [hhKey]: e.target.value }; setScheduleWindows(u) }} placeholder="HH" maxLength={2} className="w-10 px-1 py-1 bg-gray-700 rounded border border-gray-600 text-xs text-center focus:outline-none" />
                              <span className="text-gray-500 text-xs">:</span>
                              <input type="text" value={w[mmKey]} onChange={e => { const u = [...scheduleWindows]; u[idx] = { ...u[idx], [mmKey]: e.target.value }; setScheduleWindows(u) }} placeholder="MM" maxLength={2} className="w-10 px-1 py-1 bg-gray-700 rounded border border-gray-600 text-xs text-center focus:outline-none" />
                            </div>
                          )
                        })}
                        {scheduleWindows.length > 1 && (
                          <button type="button" onClick={() => setScheduleWindows(scheduleWindows.filter((_, i) => i !== idx))} className="text-xs px-1 py-1 text-red-400 hover:text-red-300 transition">✕</button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
          {/* Actions list */}
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-gray-400">Actions (processed in order; DROP stops further processing)</label>
              <button
                type="button"
                onClick={() => {
                  const usedActions = new Set(formActions.map((a) => a.action))
                  const next = ['LOG', 'PASS', 'DROP', 'INSPECT'].find((a) => {
                    if (a === 'INSPECT' && (activeDirection !== 'INGRESS' || !inspectSupported)) return false
                    return !usedActions.has(a)
                  }) || 'PASS'
                  setFormActions([...formActions, { action: next, param: '' }])
                }}
                className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30 transition"
              >
                + Add Action
              </button>
            </div>
            <div className="space-y-2">
              {formActions.map((fa, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <span className="text-xs text-gray-500 w-4">{idx + 1}.</span>
                  <select
                    value={fa.action}
                    onChange={(e) => {
                      const updated = [...formActions]
                      updated[idx] = { ...updated[idx], action: e.target.value, param: '' }
                      setFormActions(updated)
                    }}
                    className="px-2 py-1.5 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
                  >
                    <option value="DROP">Drop</option>
                    <option value="PASS">Pass</option>
                    <option value="LOG">Log</option>
                    {activeDirection === 'INGRESS' && inspectSupported && (
                      <option value="INSPECT">Inspect (IPS)</option>
                    )}
                  </select>
                  {fa.action === 'LOG' && (
                    <input
                      type="number"
                      value={fa.param}
                      onChange={(e) => {
                        const updated = [...formActions]
                        updated[idx] = { ...updated[idx], param: e.target.value }
                        setFormActions(updated)
                      }}
                      placeholder="Rate limit ms (0 = none)"
                      min="0"
                      className="flex-1 px-2 py-1.5 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none text-sm"
                    />
                  )}
                  {formActions.length > 1 && (
                    <button
                      type="button"
                      onClick={() => setFormActions(formActions.filter((_, i) => i !== idx))}
                      className="text-xs px-2 py-1 text-red-400 hover:text-red-300 transition"
                    >
                      ✕
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
          <button
            onClick={handleAddRule}
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition"
          >
            Add Rule
          </button>
        </div>
      )}

      {/* Rules list */}
      {rules.length === 0 ? (
        <p className="text-gray-400 text-center py-8">
          No {activeDirection.toLowerCase()} rules configured
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-2 font-medium text-gray-400">ID</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">Interface</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">Source</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">Destination</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">Proto</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">Ports</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">Actions</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">SNI</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">MAC</th>
                <th className="text-left py-2 px-2 font-medium text-gray-400">Lifecycle</th>
                <th className="text-right py-2 px-2 font-medium text-gray-400">Stats</th>
                <th className="text-right py-2 px-2"></th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <RuleRow
                  key={rule.ruleId}
                  rule={rule}
                  direction={activeDirection}
                  managed={managedByRuleId.get(String(rule.ruleId))}
                  onDelete={handleDeleteRule}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
