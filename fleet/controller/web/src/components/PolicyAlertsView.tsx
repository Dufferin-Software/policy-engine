// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState, useCallback } from 'react'
import { gql, useQuery, useMutation } from '@apollo/client'

// ── GraphQL ────────────────────────────────────────────────────────────────

const ALERT_RULES_QUERY = gql`
  query PolicyAlertRules {
    alertRules {
      id name enabled matchJson groupBy severity
      receiverIds thresholdCount thresholdWindowS
      groupWaitS groupIntervalS repeatIntervalS resolveAfterS
      createdAt updatedAt
    }
  }
`
const RECEIVERS_QUERY = gql`
  query PolicyReceivers {
    receivers { id name kind configJson }
  }
`
const SILENCES_QUERY = gql`
  query PolicySilences($active: Boolean) {
    silences(active: $active) { id matcherJson startsAt endsAt createdBy comment }
  }
`
const ALERT_HISTORY_QUERY = gql`
  query PolicyAlertHistory($filter: AlertHistoryFilterInput, $limit: Int, $cursor: String) {
    alertHistory(filter: $filter, limit: $limit, cursor: $cursor) {
      items { id ruleId groupKey firedAt resolvedAt eventCount sampleEventIds silenced }
      nextCursor
    }
  }
`

const CREATE_RULE = gql`
  mutation CreateAlertRule($input: CreateAlertRuleInput!) {
    createAlertRule(input: $input) { id }
  }
`
const UPDATE_RULE = gql`
  mutation UpdateAlertRule($id: ID!, $input: CreateAlertRuleInput!) {
    updateAlertRule(id: $id, input: $input) { id }
  }
`
const DELETE_RULE = gql`
  mutation DeleteAlertRule($id: ID!) { deleteAlertRule(id: $id) }
`
const CREATE_RECEIVER = gql`
  mutation CreateReceiver($input: CreateReceiverInput!) {
    createReceiver(input: $input) { id }
  }
`
const DELETE_RECEIVER = gql`
  mutation DeleteReceiver($id: ID!) { deleteReceiver(id: $id) }
`
const CREATE_SILENCE = gql`
  mutation CreateSilence($input: CreateSilenceInput!) {
    createSilence(input: $input) { id }
  }
`
const DELETE_SILENCE = gql`
  mutation DeleteSilence($id: ID!) { deleteSilence(id: $id) }
`

// ── Types ──────────────────────────────────────────────────────────────────

interface AlertRule {
  id: string
  name: string
  enabled: boolean
  matchJson: string
  groupBy: string[]
  severity: string
  receiverIds: string[]
  thresholdCount: number | null
  thresholdWindowS: number | null
  groupWaitS: number
  groupIntervalS: number
  repeatIntervalS: number
  resolveAfterS: number
  createdAt: string
  updatedAt: string
}
interface Receiver { id: string; name: string; kind: string; configJson: string }
interface Silence {
  id: string; matcherJson: string; startsAt: string; endsAt: string
  createdBy: string | null; comment: string | null
}
interface AlertHistoryItem {
  id: string; ruleId: string; groupKey: string; firedAt: string
  resolvedAt: string | null; eventCount: number; sampleEventIds: string[]
  silenced: boolean
}

// ── Shared helpers ─────────────────────────────────────────────────────────

function fmtTime(iso: string) {
  try { return new Date(iso).toLocaleString(undefined, { timeZone: 'UTC', timeZoneName: 'short' }) }
  catch { return iso }
}

function SeverityBadge({ s }: { s: string }) {
  const cls =
    s === 'critical' ? 'bg-red-900 text-red-200' :
    s === 'warning'  ? 'bg-yellow-900 text-yellow-200' :
                       'bg-gray-700 text-gray-300'
  return <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${cls}`}>{s}</span>
}

function Btn({
  onClick, children, variant = 'ghost', disabled = false,
}: {
  onClick?: () => void; children: React.ReactNode
  variant?: 'primary' | 'danger' | 'ghost'; disabled?: boolean
}) {
  const base = 'px-3 py-1.5 rounded text-sm transition-colors disabled:opacity-40'
  const cls =
    variant === 'primary' ? `${base} bg-blue-700 hover:bg-blue-600 text-white` :
    variant === 'danger'  ? `${base} bg-red-900 hover:bg-red-800 text-red-200` :
                            `${base} text-gray-400 hover:text-gray-100 hover:bg-gray-700`
  return <button className={cls} onClick={onClick} disabled={disabled}>{children}</button>
}

function Label({ children }: { children: React.ReactNode }) {
  return <label className="block text-xs text-gray-400 mb-1">{children}</label>
}
function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`w-full bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm
        text-gray-100 focus:outline-none focus:border-blue-500 ${props.className ?? ''}`}
    />
  )
}
function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={`w-full bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm
        text-gray-100 font-mono focus:outline-none focus:border-blue-500 resize-y ${props.className ?? ''}`}
    />
  )
}
function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={`bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm
        text-gray-100 focus:outline-none focus:border-blue-500 ${props.className ?? ''}`}
    />
  )
}

function ErrorMsg({ msg }: { msg: string }) {
  return <p className="text-red-400 text-sm mt-1">{msg}</p>
}

// ── Alert Rules sub-panel ──────────────────────────────────────────────────

interface RuleFormState {
  name: string
  enabled: boolean
  matchJson: string
  groupBy: string       // comma-sep field names
  severity: string
  receiverIds: string[] // selected IDs
  groupWaitS: string
  groupIntervalS: string
  repeatIntervalS: string
  resolveAfterS: string
  thresholdCount: string
  thresholdWindowS: string
}

const BLANK_RULE: RuleFormState = {
  name: '', enabled: true,
  matchJson: '{"action":["drop"]}',
  groupBy: 'rule_id',
  severity: 'warning',
  receiverIds: [],
  groupWaitS: '30',
  groupIntervalS: '300',
  repeatIntervalS: '14400',
  resolveAfterS: '1500',
  thresholdCount: '',
  thresholdWindowS: '',
}

function ruleToForm(r: AlertRule): RuleFormState {
  return {
    name: r.name,
    enabled: r.enabled,
    matchJson: r.matchJson,
    groupBy: r.groupBy.join(', '),
    severity: r.severity,
    receiverIds: r.receiverIds,
    groupWaitS: String(r.groupWaitS),
    groupIntervalS: String(r.groupIntervalS),
    repeatIntervalS: String(r.repeatIntervalS),
    resolveAfterS: String(r.resolveAfterS),
    thresholdCount: r.thresholdCount != null ? String(r.thresholdCount) : '',
    thresholdWindowS: r.thresholdWindowS != null ? String(r.thresholdWindowS) : '',
  }
}

function formToInput(f: RuleFormState) {
  const groupBy = f.groupBy.split(',').map(s => s.trim()).filter(Boolean)
  const tc = f.thresholdCount.trim() ? parseInt(f.thresholdCount, 10) : null
  const tw = f.thresholdWindowS.trim() ? parseInt(f.thresholdWindowS, 10) : null
  return {
    name: f.name.trim(),
    enabled: f.enabled,
    matchJson: f.matchJson.trim(),
    groupBy,
    severity: f.severity,
    receiverIds: f.receiverIds,
    groupWaitS: parseInt(f.groupWaitS, 10) || 30,
    groupIntervalS: parseInt(f.groupIntervalS, 10) || 300,
    repeatIntervalS: parseInt(f.repeatIntervalS, 10) || 14400,
    resolveAfterS: parseInt(f.resolveAfterS, 10) || 1500,
    thresholdCount: tc,
    thresholdWindowS: tw,
  }
}

function RuleForm({
  initial, receivers, onSave, onCancel, saving, error,
}: {
  initial: RuleFormState
  receivers: Receiver[]
  onSave: (f: RuleFormState) => void
  onCancel: () => void
  saving: boolean
  error: string
}) {
  const [f, setF] = useState(initial)
  const set = (k: keyof RuleFormState, v: string | boolean | string[]) =>
    setF(p => ({ ...p, [k]: v }))

  function toggleReceiver(id: string) {
    set('receiverIds', f.receiverIds.includes(id)
      ? f.receiverIds.filter(r => r !== id)
      : [...f.receiverIds, id])
  }

  return (
    <div className="bg-gray-850 border border-gray-700 rounded p-4 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>Name</Label>
          <TextInput value={f.name} onChange={e => set('name', e.target.value)} placeholder="high-drop-rate" />
        </div>
        <div>
          <Label>Severity</Label>
          <Select value={f.severity} onChange={e => set('severity', e.target.value)} className="w-full">
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </Select>
        </div>
      </div>

      <div>
        <Label>Match JSON (MatchSpec — AND across fields)</Label>
        <TextArea
          rows={3} value={f.matchJson}
          onChange={e => set('matchJson', e.target.value)}
          placeholder='{"action":["drop"],"dport":[22]}'
        />
        <p className="text-xs text-gray-500 mt-0.5">
          Fields: action, rule_id, node_id, proto, dport, sport, src_cidr, dst_cidr, sni_glob, direction
        </p>
      </div>

      <div>
        <Label>Group by (comma-separated field names)</Label>
        <TextInput
          value={f.groupBy}
          onChange={e => set('groupBy', e.target.value)}
          placeholder="rule_id, src_ip"
        />
        <p className="text-xs text-gray-500 mt-0.5">
          Low-cardinality fields only. Not sni.
        </p>
      </div>

      <div>
        <Label>Receivers</Label>
        {receivers.length === 0
          ? <p className="text-xs text-gray-500">No receivers configured. Create one first.</p>
          : (
            <div className="space-y-1">
              {receivers.map(r => (
                <label key={r.id} className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    className="accent-blue-500"
                    checked={f.receiverIds.includes(r.id)}
                    onChange={() => toggleReceiver(r.id)}
                  />
                  <span className="text-gray-200">{r.name}</span>
                  <span className="text-gray-500 text-xs">({r.kind})</span>
                </label>
              ))}
            </div>
          )
        }
      </div>

      <details className="text-sm">
        <summary className="text-gray-400 cursor-pointer select-none hover:text-gray-200">
          Timing &amp; threshold (advanced)
        </summary>
        <div className="grid grid-cols-2 gap-3 mt-2">
          {[
            ['groupWaitS', 'Group wait (s)'],
            ['groupIntervalS', 'Group interval (s)'],
            ['repeatIntervalS', 'Repeat interval (s)'],
            ['resolveAfterS', 'Resolve after (s)'],
            ['thresholdCount', 'Threshold count (optional)'],
            ['thresholdWindowS', 'Threshold window (s, optional)'],
          ].map(([k, label]) => (
            <div key={k}>
              <Label>{label}</Label>
              <TextInput
                type="number" min="0"
                value={f[k as keyof RuleFormState] as string}
                onChange={e => set(k as keyof RuleFormState, e.target.value)}
              />
            </div>
          ))}
        </div>
      </details>

      <div className="flex items-center gap-2">
        <label className="flex items-center gap-1.5 text-sm text-gray-300 cursor-pointer">
          <input
            type="checkbox" className="accent-blue-500"
            checked={f.enabled} onChange={e => set('enabled', e.target.checked)}
          />
          Enabled
        </label>
      </div>

      {error && <ErrorMsg msg={error} />}

      <div className="flex gap-2">
        <Btn variant="primary" onClick={() => onSave(f)} disabled={saving}>
          {saving ? 'Saving…' : 'Save'}
        </Btn>
        <Btn onClick={onCancel}>Cancel</Btn>
      </div>
    </div>
  )
}

function AlertRulesPanel() {
  const { data: rulesData, refetch: refetchRules, loading } =
    useQuery<{ alertRules: AlertRule[] }>(ALERT_RULES_QUERY, { fetchPolicy: 'cache-and-network' })
  const { data: recvData } =
    useQuery<{ receivers: Receiver[] }>(RECEIVERS_QUERY, { fetchPolicy: 'cache-and-network' })

  const [createRule, { loading: creating }] = useMutation(CREATE_RULE)
  const [updateRule, { loading: updating }] = useMutation(UPDATE_RULE)
  const [deleteRule] = useMutation(DELETE_RULE)

  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<AlertRule | null>(null)
  const [formError, setFormError] = useState('')

  const receivers = recvData?.receivers ?? []
  const rules = rulesData?.alertRules ?? []

  const handleCreate = useCallback(async (f: RuleFormState) => {
    setFormError('')
    try {
      await createRule({ variables: { input: formToInput(f) } })
      setShowCreate(false)
      void refetchRules()
    } catch (e) {
      setFormError(String((e as Error).message ?? e))
    }
  }, [createRule, refetchRules])

  const handleUpdate = useCallback(async (f: RuleFormState) => {
    if (!editing) return
    setFormError('')
    try {
      await updateRule({ variables: { id: editing.id, input: formToInput(f) } })
      setEditing(null)
      void refetchRules()
    } catch (e) {
      setFormError(String((e as Error).message ?? e))
    }
  }, [editing, updateRule, refetchRules])

  const handleDelete = useCallback(async (id: string, name: string) => {
    if (!confirm(`Delete alert rule "${name}"?`)) return
    try {
      await deleteRule({ variables: { id } })
      void refetchRules()
    } catch (e) {
      alert(String((e as Error).message ?? e))
    }
  }, [deleteRule, refetchRules])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h3 className="text-base font-medium text-gray-200">Alert Rules</h3>
        {!showCreate && !editing && (
          <Btn variant="primary" onClick={() => { setShowCreate(true); setFormError('') }}>
            + New rule
          </Btn>
        )}
      </div>

      {showCreate && (
        <RuleForm
          initial={BLANK_RULE} receivers={receivers}
          onSave={handleCreate} onCancel={() => setShowCreate(false)}
          saving={creating} error={formError}
        />
      )}

      {loading && rules.length === 0 && <p className="text-gray-500 text-sm">Loading…</p>}

      <div className="space-y-2">
        {rules.map(rule => (
          <div key={rule.id}>
            {editing?.id === rule.id ? (
              <RuleForm
                initial={ruleToForm(rule)} receivers={receivers}
                onSave={handleUpdate} onCancel={() => setEditing(null)}
                saving={updating} error={formError}
              />
            ) : (
              <div className="bg-gray-800 border border-gray-700 rounded p-3">
                <div className="flex items-start gap-2 flex-wrap">
                  <span className={`font-medium text-sm ${rule.enabled ? 'text-gray-100' : 'text-gray-500 line-through'}`}>
                    {rule.name}
                  </span>
                  <SeverityBadge s={rule.severity} />
                  {!rule.enabled && (
                    <span className="text-xs text-gray-500 bg-gray-700 px-1.5 py-0.5 rounded">disabled</span>
                  )}
                  {rule.thresholdCount != null && (
                    <span className="text-xs text-blue-400 bg-blue-900/30 px-1.5 py-0.5 rounded">
                      threshold {rule.thresholdCount}/{rule.thresholdWindowS}s
                    </span>
                  )}
                  <span className="ml-auto flex gap-2">
                    <Btn onClick={() => { setEditing(rule); setFormError('') }}>Edit</Btn>
                    <Btn variant="danger" onClick={() => void handleDelete(rule.id, rule.name)}>Delete</Btn>
                  </span>
                </div>
                <div className="mt-1 text-xs font-mono text-gray-400 truncate" title={rule.matchJson}>
                  match: {rule.matchJson}
                </div>
                <div className="text-xs text-gray-500 mt-0.5">
                  group by: [{rule.groupBy.join(', ')}]
                  {' · '}{rule.receiverIds.length} receiver(s)
                  {' · '}wait {rule.groupWaitS}s / interval {rule.groupIntervalS}s
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
      {!loading && rules.length === 0 && (
        <p className="text-gray-500 text-sm">No alert rules configured.</p>
      )}
    </div>
  )
}

// ── Receivers sub-panel ────────────────────────────────────────────────────

const RECEIVER_HINTS: Record<string, string> = {
  webhook: '{"url":"https://hooks.example.com/...","method":"POST","headers":{}}',
  email: '{"host":"smtp.example.com","port":587,"from":"alerts@example.com","to":["ops@example.com"],"username":"","password":""}',
  alertmanager: '{"url":"http://alertmanager:9093","extra_labels":{}}',
}

function ReceiversPanel() {
  const { data, refetch, loading } =
    useQuery<{ receivers: Receiver[] }>(RECEIVERS_QUERY, { fetchPolicy: 'cache-and-network' })
  const [createReceiver, { loading: creating }] = useMutation(CREATE_RECEIVER)
  const [deleteReceiver] = useMutation(DELETE_RECEIVER)

  const [show, setShow] = useState(false)
  const [name, setName] = useState('')
  const [kind, setKind] = useState('webhook')
  const [configJson, setConfigJson] = useState(RECEIVER_HINTS.webhook)
  const [formError, setFormError] = useState('')

  const receivers = data?.receivers ?? []

  async function handleCreate() {
    setFormError('')
    try {
      await createReceiver({ variables: { input: { name: name.trim(), kind, configJson: configJson.trim() } } })
      setShow(false); setName(''); setConfigJson(RECEIVER_HINTS.webhook)
      void refetch()
    } catch (e) {
      setFormError(String((e as Error).message ?? e))
    }
  }

  async function handleDelete(id: string, n: string) {
    if (!confirm(`Delete receiver "${n}"?`)) return
    try { await deleteReceiver({ variables: { id } }); void refetch() }
    catch (e) { alert(String((e as Error).message ?? e)) }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h3 className="text-base font-medium text-gray-200">Receivers</h3>
        {!show && <Btn variant="primary" onClick={() => { setShow(true); setFormError('') }}>+ New receiver</Btn>}
      </div>

      {show && (
        <div className="bg-gray-850 border border-gray-700 rounded p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Name</Label>
              <TextInput value={name} onChange={e => setName(e.target.value)} placeholder="ops-webhook" />
            </div>
            <div>
              <Label>Kind</Label>
              <Select value={kind} onChange={e => { setKind(e.target.value); setConfigJson(RECEIVER_HINTS[e.target.value] ?? '{}') }} className="w-full">
                <option value="webhook">webhook</option>
                <option value="email">email</option>
                <option value="alertmanager">alertmanager</option>
              </Select>
            </div>
          </div>
          <div>
            <Label>Config JSON</Label>
            <TextArea rows={5} value={configJson} onChange={e => setConfigJson(e.target.value)} />
          </div>
          {formError && <ErrorMsg msg={formError} />}
          <div className="flex gap-2">
            <Btn variant="primary" onClick={() => void handleCreate()} disabled={creating}>
              {creating ? 'Saving…' : 'Save'}
            </Btn>
            <Btn onClick={() => setShow(false)}>Cancel</Btn>
          </div>
        </div>
      )}

      {loading && receivers.length === 0 && <p className="text-gray-500 text-sm">Loading…</p>}

      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left text-xs text-gray-400 border-b border-gray-700">
              <th className="pb-1 pr-4">Name</th>
              <th className="pb-1 pr-4">Kind</th>
              <th className="pb-1 pr-4">Config (truncated)</th>
              <th className="pb-1" />
            </tr>
          </thead>
          <tbody>
            {receivers.map(r => (
              <tr key={r.id} className="border-b border-gray-800 hover:bg-gray-800/40">
                <td className="py-1.5 pr-4 text-gray-100">{r.name}</td>
                <td className="py-1.5 pr-4">
                  <span className="text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">{r.kind}</span>
                </td>
                <td className="py-1.5 pr-4 font-mono text-xs text-gray-400 max-w-xs truncate" title={r.configJson}>
                  {r.configJson}
                </td>
                <td className="py-1.5">
                  <Btn variant="danger" onClick={() => void handleDelete(r.id, r.name)}>Delete</Btn>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!loading && receivers.length === 0 && (
        <p className="text-gray-500 text-sm">No receivers configured.</p>
      )}
    </div>
  )
}

// ── Silences sub-panel ─────────────────────────────────────────────────────

function SilencesPanel() {
  const [showExpired, setShowExpired] = useState(false)
  const { data, refetch, loading } = useQuery<{ silences: Silence[] }>(
    SILENCES_QUERY,
    { variables: { active: showExpired ? undefined : true }, fetchPolicy: 'cache-and-network' }
  )
  const [createSilence, { loading: creating }] = useMutation(CREATE_SILENCE)
  const [deleteSilence] = useMutation(DELETE_SILENCE)

  const [show, setShow] = useState(false)
  const [matcherJson, setMatcherJson] = useState('{"action":["drop"]}')
  const [startsAt, setStartsAt] = useState(() => new Date().toISOString().slice(0, 16))
  const [endsAt, setEndsAt] = useState(() => {
    const d = new Date(); d.setHours(d.getHours() + 2)
    return d.toISOString().slice(0, 16)
  })
  const [comment, setComment] = useState('')
  const [formError, setFormError] = useState('')

  const silences = data?.silences ?? []

  async function handleCreate() {
    setFormError('')
    try {
      await createSilence({
        variables: {
          input: {
            matcherJson: matcherJson.trim(),
            startsAt: new Date(startsAt).toISOString(),
            endsAt: new Date(endsAt).toISOString(),
            comment: comment.trim() || null,
            createdBy: null,
          },
        },
      })
      setShow(false); void refetch()
    } catch (e) {
      setFormError(String((e as Error).message ?? e))
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this silence?')) return
    try { await deleteSilence({ variables: { id } }); void refetch() }
    catch (e) { alert(String((e as Error).message ?? e)) }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h3 className="text-base font-medium text-gray-200">Silences</h3>
        {!show && <Btn variant="primary" onClick={() => { setShow(true); setFormError('') }}>+ New silence</Btn>}
        <label className="ml-auto flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer">
          <input type="checkbox" className="accent-blue-500" checked={showExpired} onChange={e => setShowExpired(e.target.checked)} />
          Show expired
        </label>
      </div>

      {show && (
        <div className="bg-gray-850 border border-gray-700 rounded p-4 space-y-3">
          <div>
            <Label>Matcher JSON (subset of MatchSpec)</Label>
            <TextArea rows={2} value={matcherJson} onChange={e => setMatcherJson(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Starts at (UTC)</Label>
              <TextInput type="datetime-local" value={startsAt} onChange={e => setStartsAt(e.target.value)} />
            </div>
            <div>
              <Label>Ends at (UTC)</Label>
              <TextInput type="datetime-local" value={endsAt} onChange={e => setEndsAt(e.target.value)} />
            </div>
          </div>
          <div>
            <Label>Comment (optional)</Label>
            <TextInput value={comment} onChange={e => setComment(e.target.value)} placeholder="Maintenance window" />
          </div>
          {formError && <ErrorMsg msg={formError} />}
          <div className="flex gap-2">
            <Btn variant="primary" onClick={() => void handleCreate()} disabled={creating}>
              {creating ? 'Saving…' : 'Save'}
            </Btn>
            <Btn onClick={() => setShow(false)}>Cancel</Btn>
          </div>
        </div>
      )}

      {loading && silences.length === 0 && <p className="text-gray-500 text-sm">Loading…</p>}

      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left text-xs text-gray-400 border-b border-gray-700">
              <th className="pb-1 pr-4">Matcher</th>
              <th className="pb-1 pr-4">Active from</th>
              <th className="pb-1 pr-4">Expires</th>
              <th className="pb-1 pr-4">Comment</th>
              <th className="pb-1" />
            </tr>
          </thead>
          <tbody>
            {silences.map(s => {
              const expired = new Date(s.endsAt) < new Date()
              return (
                <tr key={s.id} className={`border-b border-gray-800 hover:bg-gray-800/40 ${expired ? 'opacity-50' : ''}`}>
                  <td className="py-1.5 pr-4 font-mono text-xs text-gray-300 max-w-xs truncate" title={s.matcherJson}>
                    {s.matcherJson}
                  </td>
                  <td className="py-1.5 pr-4 text-xs text-gray-400 whitespace-nowrap">{fmtTime(s.startsAt)}</td>
                  <td className="py-1.5 pr-4 text-xs text-gray-400 whitespace-nowrap">{fmtTime(s.endsAt)}</td>
                  <td className="py-1.5 pr-4 text-xs text-gray-400">{s.comment ?? '—'}</td>
                  <td className="py-1.5">
                    {!expired && <Btn variant="danger" onClick={() => void handleDelete(s.id)}>Delete</Btn>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {!loading && silences.length === 0 && (
        <p className="text-gray-500 text-sm">No {showExpired ? '' : 'active '}silences.</p>
      )}
    </div>
  )
}

// ── Alert History sub-panel ────────────────────────────────────────────────

function HistoryPanel() {
  const { data: rulesData } = useQuery<{ alertRules: AlertRule[] }>(ALERT_RULES_QUERY, { fetchPolicy: 'cache-and-network' })
  const [filterRuleId, setFilterRuleId] = useState('')
  const [rows, setRows] = useState<AlertHistoryItem[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)

  const ruleMap = Object.fromEntries((rulesData?.alertRules ?? []).map(r => [r.id, r.name]))

  const { loading, refetch } = useQuery<{
    alertHistory: { items: AlertHistoryItem[]; nextCursor: string | null }
  }>(
    ALERT_HISTORY_QUERY,
    {
      variables: { filter: filterRuleId ? { ruleId: filterRuleId } : {}, limit: 50 },
      fetchPolicy: 'cache-and-network',
      onCompleted(d) {
        setRows(d.alertHistory.items)
        setCursor(d.alertHistory.nextCursor ?? null)
        setHasMore(!!d.alertHistory.nextCursor)
      },
    }
  )

  async function loadMore() {
    if (!cursor) return
    const res = await refetch({ filter: filterRuleId ? { ruleId: filterRuleId } : {}, limit: 50, cursor })
    const page = res.data.alertHistory
    setRows(prev => [...prev, ...page.items])
    setCursor(page.nextCursor ?? null)
    setHasMore(!!page.nextCursor)
  }

  function applyFilter() {
    setRows([]); setCursor(null)
    void refetch({ filter: filterRuleId ? { ruleId: filterRuleId } : {}, limit: 50, cursor: undefined })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <h3 className="text-base font-medium text-gray-200">Alert History</h3>
        <Select value={filterRuleId} onChange={e => setFilterRuleId(e.target.value)} className="text-xs">
          <option value="">All rules</option>
          {(rulesData?.alertRules ?? []).map(r => (
            <option key={r.id} value={r.id}>{r.name}</option>
          ))}
        </Select>
        <Btn onClick={applyFilter}>Apply</Btn>
      </div>

      {loading && rows.length === 0 && <p className="text-gray-500 text-sm">Loading…</p>}

      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left text-xs text-gray-400 border-b border-gray-700">
              <th className="pb-1 pr-4">Rule</th>
              <th className="pb-1 pr-4">Group key</th>
              <th className="pb-1 pr-4">Fired at</th>
              <th className="pb-1 pr-4">Resolved at</th>
              <th className="pb-1 pr-4 text-right">Events</th>
              <th className="pb-1 pr-4">Silenced</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(h => (
              <tr key={h.id} className="border-b border-gray-800 hover:bg-gray-800/40">
                <td className="py-1.5 pr-4 text-gray-200 whitespace-nowrap">
                  {ruleMap[h.ruleId] ?? `rule:${h.ruleId}`}
                </td>
                <td className="py-1.5 pr-4 font-mono text-xs text-gray-400 max-w-xs truncate" title={h.groupKey}>
                  {h.groupKey}
                </td>
                <td className="py-1.5 pr-4 text-xs text-gray-400 whitespace-nowrap">{fmtTime(h.firedAt)}</td>
                <td className="py-1.5 pr-4 text-xs text-gray-400 whitespace-nowrap">
                  {h.resolvedAt ? fmtTime(h.resolvedAt) : '—'}
                </td>
                <td className="py-1.5 pr-4 text-right tabular-nums text-gray-300">{h.eventCount}</td>
                <td className="py-1.5 pr-4">
                  {h.silenced && (
                    <span className="text-xs bg-yellow-900/40 text-yellow-300 px-1.5 py-0.5 rounded">silenced</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {hasMore && (
        <Btn onClick={() => void loadMore()}>Load more</Btn>
      )}
      {!loading && rows.length === 0 && (
        <p className="text-gray-500 text-sm">No alert history.</p>
      )}
    </div>
  )
}

// ── Root component ─────────────────────────────────────────────────────────

type SubTab = 'rules' | 'receivers' | 'silences' | 'history'
const SUB_TABS: { id: SubTab; label: string }[] = [
  { id: 'rules', label: 'Alert Rules' },
  { id: 'receivers', label: 'Receivers' },
  { id: 'silences', label: 'Silences' },
  { id: 'history', label: 'History' },
]

export default function PolicyAlertsView() {
  const [sub, setSub] = useState<SubTab>('rules')

  return (
    <div>
      <nav className="flex gap-1 mb-5 border-b border-gray-700 pb-2">
        {SUB_TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setSub(t.id)}
            className={`px-3 py-1 rounded text-sm transition-colors ${
              sub === t.id
                ? 'bg-blue-800 text-white'
                : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>
      {sub === 'rules'     && <AlertRulesPanel />}
      {sub === 'receivers' && <ReceiversPanel />}
      {sub === 'silences'  && <SilencesPanel />}
      {sub === 'history'   && <HistoryPanel />}
    </div>
  )
}
