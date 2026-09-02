// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { gql, useQuery, useMutation } from '@apollo/client'
import { useState } from 'react'

const GET_FLOW_EXPORT_STATUS = gql`
  query GetFlowExportStatus {
    flowExportStatus {
      enabled
      collectorHost
      collectorPort
      idleTimeoutS
      activeTimeoutS
      flowsExportedTotal
      activeFlowCount
    }
  }
`

const CONFIGURE_FLOW_EXPORT = gql`
  mutation ConfigureFlowExport($input: ConfigureFlowExportInput!) {
    configureFlowExport(input: $input) {
      success
      message
    }
  }
`

interface FlowExportStatus {
  enabled: boolean
  collectorHost: string
  collectorPort: number
  idleTimeoutS: number
  activeTimeoutS: number
  flowsExportedTotal: number
  activeFlowCount: number
}

interface OperationResult {
  success: boolean
  message: string
}

function Tip({ label, tip }: { label: string; tip: string }) {
  return (
    <div className="group relative inline-flex items-center gap-1 text-gray-400 cursor-default">
      {label}
      <span className="text-gray-600 text-xs select-none">ⓘ</span>
      <div className="absolute left-0 top-full mt-1 w-56 bg-gray-900 border border-gray-600 rounded-lg p-2 text-xs text-gray-300 z-50 shadow-xl hidden group-hover:block whitespace-normal">
        {tip}
      </div>
    </div>
  )
}

export function FlowExportPanel() {
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  )
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState({
    collectorHost: '',
    collectorPort: '',
    idleTimeoutS: '',
    activeTimeoutS: '',
  })

  const { data, loading } = useQuery<{ flowExportStatus: FlowExportStatus }>(
    GET_FLOW_EXPORT_STATUS,
    { pollInterval: 10000 }
  )

  const [configureFlowExport, { loading: mutating }] = useMutation<{
    configureFlowExport: OperationResult
  }>(CONFIGURE_FLOW_EXPORT, {
    refetchQueries: [{ query: GET_FLOW_EXPORT_STATUS }],
  })

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message })
    setTimeout(() => setFeedback(null), 5000)
  }

  const status = data?.flowExportStatus

  const handleToggle = async () => {
    if (!status) return
    try {
      const result = await configureFlowExport({
        variables: { input: { enabled: !status.enabled } },
      })
      if (result.data?.configureFlowExport.success) {
        showFeedback('success', result.data.configureFlowExport.message)
      } else if (result.data) {
        showFeedback('error', result.data.configureFlowExport.message)
      }
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const startEditing = () => {
    if (!status) return
    setForm({
      collectorHost: status.collectorHost,
      collectorPort: String(status.collectorPort),
      idleTimeoutS: String(status.idleTimeoutS),
      activeTimeoutS: String(status.activeTimeoutS),
    })
    setEditing(true)
  }

  const cancelEditing = () => setEditing(false)

  const handleSave = async () => {
    const port = parseInt(form.collectorPort, 10)
    const idle = parseInt(form.idleTimeoutS, 10)
    const active = parseInt(form.activeTimeoutS, 10)
    if (!form.collectorHost || isNaN(port) || port < 1 || port > 65535) {
      showFeedback('error', 'Invalid collector host or port (1–65535)')
      return
    }
    if (isNaN(idle) || idle < 1 || isNaN(active) || active < 1) {
      showFeedback('error', 'Timeouts must be at least 1 second')
      return
    }
    try {
      const result = await configureFlowExport({
        variables: {
          input: {
            enabled: status?.enabled ?? false,
            collectorHost: form.collectorHost,
            collectorPort: port,
            idleTimeoutS: idle,
            activeTimeoutS: active,
          },
        },
      })
      if (result.data?.configureFlowExport.success) {
        showFeedback('success', result.data.configureFlowExport.message)
        setEditing(false)
      } else if (result.data) {
        showFeedback('error', result.data.configureFlowExport.message)
      }
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const enabled = status?.enabled ?? false

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 group relative">
          <h2 className="text-xl font-semibold">IPFIX Flow Export</h2>
          <span className="text-gray-500 cursor-default select-none text-sm">ⓘ</span>
          <div className="absolute left-0 top-full mt-2 w-80 bg-gray-900 border border-gray-600 rounded-lg p-3 text-xs text-gray-300 z-50 shadow-xl hidden group-hover:block">
            Exports per-flow statistics as RFC 7011 IPFIX UDP datagrams to a collector.
            Flows are exported when idle for more than <em>idle timeout</em> seconds or
            when active for more than <em>active timeout</em> seconds. Both XDP (ingress)
            and TC (egress) flows are tracked independently.
          </div>
        </div>

        <div className="flex items-center gap-3">
          {status && !editing && (
            <button
              onClick={startEditing}
              className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 hover:text-white rounded transition-colors"
            >
              Configure
            </button>
          )}
          <button
            onClick={handleToggle}
            disabled={loading || mutating}
            className={`relative inline-flex h-7 w-12 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none disabled:opacity-50 ${
              enabled ? 'bg-green-500' : 'bg-gray-600'
            }`}
          >
            <span
              className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                enabled ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
        </div>
      </div>

      {/* Status row */}
      {status && !editing && (
        <div className="mt-4 space-y-3">
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
            <Tip label="Collector" tip="UDP host:port of the IPFIX collector receiving flow datagrams." />
            <div className="font-mono text-gray-200">
              {status.collectorHost}:{status.collectorPort}
            </div>
            <Tip label="Idle timeout" tip="A flow idle for longer than this many seconds is exported and removed from the cache." />
            <div className="text-gray-200">{status.idleTimeoutS}s</div>
            <Tip label="Active timeout" tip="A long-running flow is exported after this many seconds regardless of activity." />
            <div className="text-gray-200">{status.activeTimeoutS}s</div>
            <Tip label="Active flows" tip="Number of flows currently tracked across the XDP (ingress) and TC (egress) flow cache maps." />
            <div className="text-gray-200">{status.activeFlowCount.toLocaleString()}</div>
            <Tip label="Flows exported" tip="Total number of flow records exported to the collector since the daemon started." />
            <div className="text-gray-200">{status.flowsExportedTotal.toLocaleString()}</div>
          </div>
        </div>
      )}

      {/* Edit form */}
      {editing && (
        <div className="mt-4 space-y-3">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <label className="block text-gray-400 mb-1">Collector host</label>
              <input
                type="text"
                value={form.collectorHost}
                onChange={e => setForm(f => ({ ...f, collectorHost: e.target.value }))}
                placeholder="127.0.0.1"
                className="w-full bg-gray-700 text-white rounded px-3 py-1.5 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-gray-400 mb-1">Port</label>
              <input
                type="number"
                value={form.collectorPort}
                onChange={e => setForm(f => ({ ...f, collectorPort: e.target.value }))}
                min={1}
                max={65535}
                className="w-full bg-gray-700 text-white rounded px-3 py-1.5 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-gray-400 mb-1">Idle timeout (s)</label>
              <input
                type="number"
                value={form.idleTimeoutS}
                onChange={e => setForm(f => ({ ...f, idleTimeoutS: e.target.value }))}
                min={1}
                className="w-full bg-gray-700 text-white rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-gray-400 mb-1">Active timeout (s)</label>
              <input
                type="number"
                value={form.activeTimeoutS}
                onChange={e => setForm(f => ({ ...f, activeTimeoutS: e.target.value }))}
                min={1}
                className="w-full bg-gray-700 text-white rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
          </div>
          <div className="flex gap-2 pt-1">
            <button
              onClick={handleSave}
              disabled={mutating}
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm rounded transition-colors"
            >
              Save
            </button>
            <button
              onClick={cancelEditing}
              className="px-4 py-1.5 bg-gray-600 hover:bg-gray-500 text-white text-sm rounded transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {feedback && (
        <div
          className={`mt-3 p-2 rounded text-sm ${
            feedback.type === 'success'
              ? 'bg-green-500/20 text-green-400'
              : 'bg-red-500/20 text-red-400'
          }`}
        >
          {feedback.message}
        </div>
      )}
    </div>
  )
}
