// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState } from 'react'
import { useMutation, gql } from '@apollo/client'
import ConfirmDropDialog, { DropCriterion } from './ConfirmDropDialog.tsx'

const CREATE_RULE = gql`
  mutation CreateRule($input: CreateRuleInput!) {
    createRule(input: $input) {
      id interfaceName direction protocol expiresAfterSecs scheduleJson
    }
  }
`

interface ActionEntry {
  action: string
  priority: number
  param: number
}

interface LifecycleWindowInput {
  startDay: string; startHH: string; startMM: string
  endDay: string; endHH: string; endMM: string
}

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

interface Props {
  nodeId: string
  interfaceName: string
  direction: string
  /** Node advertised the "suricata" capability — offers the INSPECT action. */
  suricataCapable?: boolean
  onClose: () => void
  onCreated: () => void
  onPendingChange?: (pending: boolean, opKind?: string) => void
}

const PROTOCOLS = ['any', 'tcp', 'udp', 'icmp', 'icmpv6']

const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^[0-9a-fA-F:]+\/\d{1,3}$/
const MAC_RE = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/

function validateCidr(v: string): boolean {
  return v === '' || CIDR_RE.test(v)
}
function validateMac(v: string): boolean {
  return v === '' || MAC_RE.test(v)
}

export default function RuleCreator({ nodeId, interfaceName, direction, suricataCapable = false, onClose, onCreated, onPendingChange }: Props) {
  const [createRule] = useMutation(CREATE_RULE)

  const [srcCidr, setSrcCidr] = useState('')
  const [dstCidr, setDstCidr] = useState('')
  const [srcPort, setSrcPort] = useState('')
  const [dstPort, setDstPort] = useState('')
  const [protocol, setProtocol] = useState('any')
  const [sniPattern, setSniPattern] = useState('')
  const [quicVersion, setQuicVersion] = useState('')
  const [srcMac, setSrcMac] = useState('')
  const [dstMac, setDstMac] = useState('')
  const [actions, setActions] = useState<ActionEntry[]>([{ action: 'pass', priority: 0, param: 0 }])
  const [lifecycleMode, setLifecycleMode] = useState<'permanent' | 'ttl' | 'scheduled'>('permanent')
  const [ttlSecs, setTtlSecs] = useState('')
  const [scheduleTz, setScheduleTz] = useState('UTC')
  const [scheduleWindows, setScheduleWindows] = useState<LifecycleWindowInput[]>([
    { startDay: '1', startHH: '09', startMM: '00', endDay: '5', endHH: '17', endMM: '00' },
  ])
  const [showDropConfirm, setShowDropConfirm] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function addAction() {
    setActions((prev) => [...prev, { action: 'pass', priority: prev.length, param: 0 }])
  }

  function removeAction(idx: number) {
    setActions((prev) => prev.filter((_, i) => i !== idx))
  }

  function updateAction(idx: number, field: keyof ActionEntry, value: string | number) {
    setActions((prev) => prev.map((a, i) => (i === idx ? { ...a, [field]: value } : a)))
  }

  function buildInput() {
    let expiresAfterSecs: number | null = null
    let scheduleJson: string | null = null
    if (lifecycleMode === 'ttl') {
      expiresAfterSecs = parseInt(ttlSecs, 10) || null
    } else if (lifecycleMode === 'scheduled') {
      scheduleJson = JSON.stringify({
        timezone: scheduleTz || 'UTC',
        windows: scheduleWindows.map((w) => ({
          start: { dayOfWeek: parseInt(w.startDay), hour: parseInt(w.startHH), minute: parseInt(w.startMM) },
          end:   { dayOfWeek: parseInt(w.endDay),   hour: parseInt(w.endHH),   minute: parseInt(w.endMM)   },
        })),
      })
    }
    return {
      nodeId,
      interfaceName,
      direction,
      srcCidr: srcCidr || null,
      dstCidr: dstCidr || null,
      srcPort: srcPort ? parseInt(srcPort, 10) : null,
      dstPort: dstPort ? parseInt(dstPort, 10) : null,
      protocol: protocol || 'any',
      sniPattern: sniPattern || null,
      quicVersion: quicVersion || null,
      srcMac: srcMac || null,
      dstMac: dstMac || null,
      actionsJson: JSON.stringify(actions),
      expiresAfterSecs,
      scheduleJson,
    }
  }

  function validate(): boolean {
    if (!validateCidr(srcCidr)) { setError('Invalid source CIDR'); return false }
    if (!validateCidr(dstCidr)) { setError('Invalid destination CIDR'); return false }
    if (!validateMac(srcMac)) { setError('Invalid source MAC'); return false }
    if (!validateMac(dstMac)) { setError('Invalid destination MAC'); return false }
    if (actions.length === 0) { setError('At least one action is required'); return false }
    if (lifecycleMode === 'ttl') {
      const v = parseInt(ttlSecs, 10)
      if (!ttlSecs || isNaN(v) || v <= 0) { setError('TTL must be a positive number of seconds'); return false }
    }
    if (lifecycleMode === 'scheduled' && scheduleWindows.length === 0) {
      setError('At least one schedule window is required'); return false
    }
    setError(null)
    return true
  }

  function hasDropAction(): boolean {
    return actions.some((a) => a.action === 'drop')
  }

  function dropCriteria(): DropCriterion[] {
    const c: DropCriterion[] = []
    c.push({ label: 'Interface', value: interfaceName })
    c.push({ label: 'Direction', value: direction })
    c.push({ label: 'Protocol', value: protocol === 'any' ? 'any (all protocols)' : protocol.toUpperCase() })
    c.push({ label: 'Source', value: srcCidr ? `${srcCidr}${srcPort ? `:${srcPort}` : ''}` : `any${srcPort ? `:${srcPort}` : ''}` })
    c.push({ label: 'Destination', value: dstCidr ? `${dstCidr}${dstPort ? `:${dstPort}` : ''}` : `any${dstPort ? `:${dstPort}` : ''}` })
    if (sniPattern) c.push({ label: 'SNI pattern', value: sniPattern })
    if (srcMac) c.push({ label: 'Source MAC', value: srcMac })
    if (dstMac) c.push({ label: 'Dest MAC', value: dstMac })
    if (quicVersion) c.push({ label: 'QUIC version', value: quicVersion })
    return c
  }

  async function doCreate() {
    onPendingChange?.(true, 'create_rule')
    try {
      await createRule({ variables: { input: buildInput() } })
      onCreated()
      onClose()
    } catch (e) {
      setError(String(e).replace(/^ApolloError:\s*/, ''))
    } finally {
      onPendingChange?.(false)
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validate()) return
    if (hasDropAction()) {
      setShowDropConfirm(true)
    } else {
      doCreate()
    }
  }

  return (
    <>
      {showDropConfirm && (
        <ConfirmDropDialog
          criteria={dropCriteria()}
          onConfirm={() => { setShowDropConfirm(false); doCreate() }}
          onCancel={() => setShowDropConfirm(false)}
        />
      )}

      <form onSubmit={handleSubmit} className="bg-gray-800 rounded border border-gray-600 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-semibold text-gray-200">
            New Rule: {interfaceName} / {direction}
          </h4>
          <button type="button" onClick={onClose} className="text-xs text-gray-500 hover:text-gray-300">
            Cancel
          </button>
        </div>

        {error && <div className="text-xs text-red-400">{error}</div>}

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Source CIDR</label>
            <input
              value={srcCidr}
              onChange={(e) => setSrcCidr(e.target.value)}
              placeholder="e.g. 10.0.0.0/8"
              className={`w-full bg-gray-700 border rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500 ${
                srcCidr && !validateCidr(srcCidr) ? 'border-red-600' : 'border-gray-600'
              }`}
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Destination CIDR</label>
            <input
              value={dstCidr}
              onChange={(e) => setDstCidr(e.target.value)}
              placeholder="e.g. 192.168.1.0/24"
              className={`w-full bg-gray-700 border rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500 ${
                dstCidr && !validateCidr(dstCidr) ? 'border-red-600' : 'border-gray-600'
              }`}
            />
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Source Port</label>
            <input
              type="number"
              min={0}
              max={65535}
              value={srcPort}
              onChange={(e) => setSrcPort(e.target.value)}
              placeholder="0 = any"
              className="w-full bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Destination Port</label>
            <input
              type="number"
              min={0}
              max={65535}
              value={dstPort}
              onChange={(e) => setDstPort(e.target.value)}
              placeholder="0 = any"
              className="w-full bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Protocol</label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="w-full bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
            >
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1">SNI Pattern</label>
          <input
            value={sniPattern}
            onChange={(e) => setSniPattern(e.target.value)}
            placeholder="e.g. *.example.com"
            className="w-full bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
          />
          <p className="text-[11px] text-gray-500 mt-1">
            Matches the server name in TLS (TCP) or QUIC (UDP) handshakes. Leave blank to ignore SNI.
          </p>
        </div>

        {protocol === 'udp' && (
          <div>
            <label className="block text-xs text-gray-400 mb-1">QUIC Version</label>
            <input
              value={quicVersion}
              onChange={(e) => setQuicVersion(e.target.value)}
              placeholder="e.g. 1"
              className="w-full bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
            />
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Source MAC</label>
            <input
              value={srcMac}
              onChange={(e) => setSrcMac(e.target.value)}
              placeholder="aa:bb:cc:dd:ee:ff"
              className={`w-full bg-gray-700 border rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500 ${
                srcMac && !validateMac(srcMac) ? 'border-red-600' : 'border-gray-600'
              }`}
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Destination MAC</label>
            <input
              value={dstMac}
              onChange={(e) => setDstMac(e.target.value)}
              placeholder="aa:bb:cc:dd:ee:ff"
              className={`w-full bg-gray-700 border rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500 ${
                dstMac && !validateMac(dstMac) ? 'border-red-600' : 'border-gray-600'
              }`}
            />
          </div>
        </div>

        {/* Actions list */}
        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs text-gray-400">Actions</label>
            <button
              type="button"
              onClick={addAction}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              + Add Action
            </button>
          </div>
          <div className="space-y-1">
            {actions.map((a, i) => (
              <div key={i} className="flex gap-2 items-center">
                <select
                  value={a.action}
                  onChange={(e) => updateAction(i, 'action', e.target.value)}
                  className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs"
                >
                  <option value="pass">PASS</option>
                  <option value="drop">DROP</option>
                  <option value="log">LOG</option>
                  {suricataCapable && <option value="inspect">INSPECT</option>}
                </select>
                <input
                  type="number"
                  min={0}
                  value={a.priority}
                  onChange={(e) => updateAction(i, 'priority', parseInt(e.target.value, 10) || 0)}
                  className="w-16 bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs"
                  title="Priority"
                />
                {a.action === 'log' && (
                  <input
                    type="number"
                    min={0}
                    value={a.param}
                    onChange={(e) => updateAction(i, 'param', parseInt(e.target.value, 10) || 0)}
                    className="w-20 bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs"
                    placeholder="rate ms"
                    title="Rate limit (ms)"
                  />
                )}
                {actions.length > 1 && (
                  <button
                    type="button"
                    onClick={() => removeAction(i)}
                    className="text-xs text-red-500 hover:text-red-400"
                  >
                    Remove
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Lifecycle */}
        <div>
          <label className="block text-xs text-gray-400 mb-1">Lifecycle</label>
          <div className="flex gap-2 mb-2">
            {(['permanent', 'ttl', 'scheduled'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setLifecycleMode(mode)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                  lifecycleMode === mode ? 'bg-blue-600 text-white' : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
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
                min={1}
                value={ttlSecs}
                onChange={(e) => setTtlSecs(e.target.value)}
                placeholder="e.g. 3600"
                className="w-40 bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
              />
            </div>
          )}
          {lifecycleMode === 'scheduled' && (
            <div className="space-y-2">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Timezone (IANA)</label>
                <input
                  type="text"
                  value={scheduleTz}
                  onChange={(e) => setScheduleTz(e.target.value)}
                  placeholder="UTC"
                  className="w-48 bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs text-gray-400">Windows (active inside any window)</label>
                  <button
                    type="button"
                    onClick={() => setScheduleWindows([...scheduleWindows, { startDay: '1', startHH: '09', startMM: '00', endDay: '5', endHH: '17', endMM: '00' }])}
                    className="text-xs text-blue-400 hover:text-blue-300"
                  >
                    + Add Window
                  </button>
                </div>
                <div className="space-y-1">
                  {scheduleWindows.map((w, idx) => (
                    <div key={idx} className="flex items-center gap-1 flex-wrap text-xs">
                      <span className="text-gray-500 w-4">{idx + 1}.</span>
                      {(['startDay', 'endDay'] as const).map((dayKey, di) => {
                        const hhKey = di === 0 ? 'startHH' : 'endHH'
                        const mmKey = di === 0 ? 'startMM' : 'endMM'
                        return (
                          <div key={di} className="flex items-center gap-1">
                            {di === 1 && <span className="text-gray-500">→</span>}
                            <select
                              value={w[dayKey]}
                              onChange={(e) => { const u = [...scheduleWindows]; u[idx] = { ...u[idx], [dayKey]: e.target.value }; setScheduleWindows(u) }}
                              className="bg-gray-700 border border-gray-600 rounded px-1 py-0.5 text-xs focus:outline-none"
                            >
                              {DAY_NAMES.map((d, i) => <option key={i} value={String(i)}>{d}</option>)}
                            </select>
                            <input type="text" value={w[hhKey]} onChange={(e) => { const u = [...scheduleWindows]; u[idx] = { ...u[idx], [hhKey]: e.target.value }; setScheduleWindows(u) }} placeholder="HH" maxLength={2} className="w-9 bg-gray-700 border border-gray-600 rounded px-1 py-0.5 text-xs text-center focus:outline-none" />
                            <span className="text-gray-500">:</span>
                            <input type="text" value={w[mmKey]} onChange={(e) => { const u = [...scheduleWindows]; u[idx] = { ...u[idx], [mmKey]: e.target.value }; setScheduleWindows(u) }} placeholder="MM" maxLength={2} className="w-9 bg-gray-700 border border-gray-600 rounded px-1 py-0.5 text-xs text-center focus:outline-none" />
                          </div>
                        )
                      })}
                      {scheduleWindows.length > 1 && (
                        <button type="button" onClick={() => setScheduleWindows(scheduleWindows.filter((_, i) => i !== idx))} className="text-red-500 hover:text-red-400 text-xs">✕</button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            className="px-4 py-1.5 rounded text-sm bg-blue-700 hover:bg-blue-600 text-white"
          >
            Create Rule
          </button>
        </div>
      </form>
    </>
  )
}
