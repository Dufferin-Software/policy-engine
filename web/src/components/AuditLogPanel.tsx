// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { gql, useQuery, useLazyQuery } from '@apollo/client'
import { useState } from 'react'

const GET_AUDIT = gql`
  query GetAuditLog($limit: Int) {
    auditLog(limit: $limit) {
      timestamp
      operation
      input
      result
      message
      sourceIp
    }
  }
`

const EXPORT_AUDIT = gql`
  query ExportAuditLog($format: String!, $from: String, $to: String) {
    exportAuditLog(format: $format, from: $from, to: $to) {
      filename
      contentType
      data
    }
  }
`

interface AuditEntry {
  timestamp: string
  operation: string
  input: unknown
  result: string
  message: string
  sourceIp: string
}

interface AuditExport {
  filename: string
  contentType: string
  data: string
}

const LIMIT = 100

/** datetime-local value ("2026-06-19T12:00") → RFC 3339 UTC, or undefined. */
function toRfc3339(local: string): string | undefined {
  if (!local) return undefined
  const d = new Date(local)
  return isNaN(d.getTime()) ? undefined : d.toISOString()
}

/** Trigger a browser download of `data` as `filename`. */
function downloadBlob(filename: string, contentType: string, data: string) {
  const blob = new Blob([data], { type: contentType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function resultColor(result: string): string {
  return result === 'ok' ? 'text-green-400' : 'text-red-400'
}

export function AuditLogPanel() {
  const [format, setFormat] = useState<'csv' | 'json'>('csv')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  )

  const { data, loading, error, refetch } = useQuery<{ auditLog: AuditEntry[] }>(GET_AUDIT, {
    variables: { limit: LIMIT },
    fetchPolicy: 'network-only',
  })

  const [runExport, { loading: exporting }] = useLazyQuery<{ exportAuditLog: AuditExport }>(
    EXPORT_AUDIT,
    { fetchPolicy: 'network-only' }
  )

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message })
    setTimeout(() => setFeedback(null), 5000)
  }

  const handleExport = async () => {
    try {
      const result = await runExport({
        variables: { format, from: toRfc3339(from), to: toRfc3339(to) },
      })
      const exp = result.data?.exportAuditLog
      if (exp) {
        downloadBlob(exp.filename, exp.contentType, exp.data)
        showFeedback('success', `Exported ${exp.filename}`)
      } else if (result.error) {
        showFeedback('error', result.error.message)
      }
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const entries = data?.auditLog ?? []

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Audit Log</h2>
        <button
          onClick={() => refetch()}
          className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 hover:text-white rounded transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* Export controls */}
      <div className="flex flex-wrap items-end gap-3 bg-gray-900/40 rounded-lg p-3 border border-gray-700">
        <div>
          <label className="block text-gray-400 mb-1 text-xs">Format</label>
          <select
            value={format}
            onChange={e => setFormat(e.target.value as 'csv' | 'json')}
            className="bg-gray-700 text-white rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
          </select>
        </div>
        <div>
          <label className="block text-gray-400 mb-1 text-xs">From</label>
          <input
            type="datetime-local"
            value={from}
            onChange={e => setFrom(e.target.value)}
            className="bg-gray-700 text-white rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-gray-400 mb-1 text-xs">To</label>
          <input
            type="datetime-local"
            value={to}
            onChange={e => setTo(e.target.value)}
            className="bg-gray-700 text-white rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm rounded transition-colors"
        >
          {exporting ? 'Exporting…' : 'Export'}
        </button>
        <span className="text-xs text-gray-500 self-center">
          Leave the time fields blank to export the full history.
        </span>
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

      {loading && <div className="text-gray-500">Loading…</div>}
      {error && <div className="text-red-400">Error: {error.message}</div>}

      {/* Recent entries (last {LIMIT}) */}
      <div className="rounded-lg border border-gray-700 overflow-hidden">
        <table className="w-full text-xs font-mono">
          <thead className="bg-gray-900 text-gray-400">
            <tr>
              {['Time', 'Operation', 'Result', 'Message', 'Source'].map(h => (
                <th key={h} className="px-4 py-2 text-left">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={i} className="border-t border-gray-800 hover:bg-gray-800/40">
                <td className="px-4 py-1.5 text-gray-500 whitespace-nowrap">
                  {new Date(e.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-1.5 text-gray-200">{e.operation}</td>
                <td className={`px-4 py-1.5 font-medium ${resultColor(e.result)}`}>{e.result}</td>
                <td className="px-4 py-1.5 text-gray-400 max-w-md truncate">{e.message}</td>
                <td className="px-4 py-1.5 text-gray-500">{e.sourceIp}</td>
              </tr>
            ))}
            {!loading && entries.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-600">
                  No audit entries yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-gray-600">
        Showing the most recent {LIMIT} entries from the in-memory buffer. Export reads the full
        on-disk log.
      </p>
    </div>
  )
}
