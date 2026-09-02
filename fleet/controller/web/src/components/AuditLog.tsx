// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState } from 'react'
import { useQuery, useLazyQuery, gql } from '@apollo/client'
import { AuditEntry, AuditExport } from './types.ts'

const GET_AUDIT = gql`
  query GetAudit($limit: Int, $offset: Int) {
    auditLog(limit: $limit, offset: $offset) {
      id ts operator action nodeId detail
    }
  }
`

const EXPORT_AUDIT = gql`
  query ExportAudit($format: String!, $from: String, $to: String) {
    exportAuditLog(format: $format, from: $from, to: $to) {
      filename contentType data
    }
  }
`

const PAGE_SIZE = 50

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

function actionColor(action: string): string {
  if (action.includes('fail') || action.includes('reject')) return 'text-red-400'
  if (action.includes('push') || action.includes('apply')) return 'text-green-400'
  if (action.includes('decommission') || action.includes('remove')) return 'text-orange-400'
  if (action.includes('enroll') || action.includes('approve')) return 'text-blue-400'
  return 'text-gray-400'
}

export default function AuditLog() {
  const [offset, setOffset] = useState(0)
  const [format, setFormat] = useState<'csv' | 'json'>('csv')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [exportError, setExportError] = useState<string | null>(null)
  const { data, loading, error, refetch } = useQuery<{ auditLog: AuditEntry[] }>(GET_AUDIT, {
    variables: { limit: PAGE_SIZE, offset },
    fetchPolicy: 'network-only',
  })

  const [runExport, { loading: exporting }] = useLazyQuery<{ exportAuditLog: AuditExport }>(
    EXPORT_AUDIT,
    { fetchPolicy: 'network-only' }
  )

  const handleExport = async () => {
    setExportError(null)
    try {
      const result = await runExport({
        variables: { format, from: toRfc3339(from), to: toRfc3339(to) },
      })
      const exp = result.data?.exportAuditLog
      if (exp) {
        downloadBlob(exp.filename, exp.contentType, exp.data)
      } else if (result.error) {
        setExportError(result.error.message)
      }
    } catch (e) {
      setExportError(String(e))
    }
  }

  const entries = data?.auditLog ?? []
  const hasMore = entries.length === PAGE_SIZE

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-200">Audit Log</h2>
        <button
          onClick={() => { setOffset(0); refetch() }}
          className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded text-sm"
        >
          Refresh
        </button>
      </div>

      {/* Export controls */}
      <div className="flex flex-wrap items-end gap-3 rounded-lg border border-gray-700 bg-gray-800/40 p-3">
        <div>
          <label className="block text-gray-400 mb-1 text-xs">Format</label>
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value as 'csv' | 'json')}
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
            onChange={(e) => setFrom(e.target.value)}
            className="bg-gray-700 text-white rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-gray-400 mb-1 text-xs">To</label>
          <input
            type="datetime-local"
            value={to}
            onChange={(e) => setTo(e.target.value)}
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
      {exportError && <div className="text-red-400 text-sm">Export failed: {exportError}</div>}

      {loading && <div className="text-gray-500">Loading…</div>}
      {error && <div className="text-red-400">Error: {error.message}</div>}

      <div className="rounded-lg border border-gray-700 overflow-hidden">
        <table className="w-full text-xs font-mono">
          <thead className="bg-gray-800 text-gray-400">
            <tr>
              {['Time', 'Action', 'Node', 'Operator', 'Detail'].map((h) => (
                <th key={h} className="px-4 py-2 text-left">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id} className="border-t border-gray-800 hover:bg-gray-800/40">
                <td className="px-4 py-1.5 text-gray-500 whitespace-nowrap">
                  {new Date(e.ts).toLocaleString()}
                </td>
                <td className={`px-4 py-1.5 font-medium ${actionColor(e.action)}`}>
                  {e.action}
                </td>
                <td className="px-4 py-1.5 text-gray-400">
                  {e.nodeId ? e.nodeId.slice(0, 12) + '…' : '—'}
                </td>
                <td className="px-4 py-1.5 text-gray-500">
                  {e.operator ?? 'system'}
                </td>
                <td className="px-4 py-1.5 text-gray-400 max-w-xs truncate">
                  {e.detail ?? '—'}
                </td>
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

      {/* Pagination */}
      <div className="flex gap-2 justify-end items-center text-sm">
        <button
          disabled={offset === 0}
          onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
          className="px-3 py-1 rounded bg-gray-700 hover:bg-gray-600 disabled:opacity-40"
        >
          ← Prev
        </button>
        <span className="text-gray-500">
          {offset + 1}–{offset + entries.length}
        </span>
        <button
          disabled={!hasMore}
          onClick={() => setOffset((o) => o + PAGE_SIZE)}
          className="px-3 py-1 rounded bg-gray-700 hover:bg-gray-600 disabled:opacity-40"
        >
          Next →
        </button>
      </div>
    </div>
  )
}
