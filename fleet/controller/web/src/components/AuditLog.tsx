// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useState } from 'react'
import { useQuery, gql } from '@apollo/client'
import { AuditEntry } from './types.ts'

const GET_AUDIT = gql`
  query GetAudit($limit: Int, $offset: Int) {
    auditLog(limit: $limit, offset: $offset) {
      id ts operator action nodeId detail
    }
  }
`

const PAGE_SIZE = 50

function actionColor(action: string): string {
  if (action.includes('fail') || action.includes('reject')) return 'text-red-400'
  if (action.includes('push') || action.includes('apply')) return 'text-green-400'
  if (action.includes('decommission') || action.includes('remove')) return 'text-orange-400'
  if (action.includes('enroll') || action.includes('approve')) return 'text-blue-400'
  return 'text-gray-400'
}

export default function AuditLog() {
  const [offset, setOffset] = useState(0)
  const { data, loading, error, refetch } = useQuery<{ auditLog: AuditEntry[] }>(GET_AUDIT, {
    variables: { limit: PAGE_SIZE, offset },
    fetchPolicy: 'network-only',
  })

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
