// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useState } from 'react'
import { useQuery, useMutation, gql } from '@apollo/client'
import { ControlledNode, nodeDisplayName, relTime, shortId, statusColor } from './types.ts'
import NodeDetail, { NodeTab } from './NodeDetail.tsx'
import FleetRuleCreator from './FleetRuleCreator.tsx'
import MonitoringSetup from './MonitoringSetup.tsx'

const GET_FLEET = gql`
  query GetFleet {
    nodes {
      id label hostname status certExpiry lastSeen enrolledAt tpmBacked agentVersion dmiUuid
    }
    onlineNodes
    pendingGenerations {
      generationId nodeId opKind issuedAt
    }
  }
`

const DECOMMISSION = gql`
  mutation Decommission($nodeId: ID!) {
    decommissionNode(nodeId: $nodeId) { success message }
  }
`

const REMOVE_NODE = gql`
  mutation RemoveNode($nodeId: ID!) {
    removeNode(nodeId: $nodeId) { success message }
  }
`

const LABEL_NODE = gql`
  mutation LabelNode($nodeId: ID!, $label: String!) {
    labelNode(nodeId: $nodeId, label: $label) { success message }
  }
`

interface PendingGenerationRow {
  generationId: string
  nodeId: string
  opKind: string
  issuedAt: string
}

interface FleetData {
  nodes: ControlledNode[]
  onlineNodes: string[]
  pendingGenerations: PendingGenerationRow[]
}

interface FleetDashboardProps {
  selectedNode: { nodeId: string; initialTab?: NodeTab } | null
  onSelectNode: (target: { nodeId: string; initialTab?: NodeTab } | null) => void
}

export default function FleetDashboard({ selectedNode, onSelectNode }: FleetDashboardProps) {
  const { data, loading, error, refetch } = useQuery<FleetData>(GET_FLEET, {
    pollInterval: 10_000,
  })
  const [decommission] = useMutation(DECOMMISSION)
  const [removeNode] = useMutation(REMOVE_NODE)
  const [labelNode] = useMutation(LABEL_NODE)
  const [showFleetRule, setShowFleetRule] = useState(false)
  const [showMonitoring, setShowMonitoring] = useState(false)
  const [labelEdit, setLabelEdit] = useState<{ id: string; value: string } | null>(null)
  const [msg, setMsg] = useState<string | null>(null)

  function flash(m: string) {
    setMsg(m)
    setTimeout(() => setMsg(null), 4000)
  }

  async function handleDecommission(nodeId: string) {
    if (!confirm(`Decommission node ${nodeId.slice(0, 12)}?`)) return
    await decommission({ variables: { nodeId } })
    flash('Node decommissioned.')
    refetch()
  }

  async function handleRemove(nodeId: string) {
    if (!confirm(`Permanently remove node ${nodeId.slice(0, 12)}?`)) return
    await removeNode({ variables: { nodeId } })
    flash('Node removed.')
    refetch()
  }

  async function handleLabel(nodeId: string, label: string) {
    await labelNode({ variables: { nodeId, label } })
    setLabelEdit(null)
    refetch()
  }

  if (selectedNode) {
    return (
      <NodeDetail
        nodeId={selectedNode.nodeId}
        initialTab={selectedNode.initialTab}
        onBack={() => onSelectNode(null)}
      />
    )
  }

  const online = new Set(data?.onlineNodes ?? [])
  const nodes = data?.nodes ?? []
  const pendingByNode = new Map<string, PendingGenerationRow>(
    (data?.pendingGenerations ?? []).map((p) => [p.nodeId, p]),
  )
  const active = nodes.filter((n) => n.status === 'active').length
  const onlineCount = nodes.filter((n) => online.has(n.id)).length

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Nodes', value: nodes.length },
          { label: 'Active', value: active },
          { label: 'Online Now', value: onlineCount },
          { label: 'Pending', value: nodes.filter((n) => n.status === 'pending').length },
        ].map((c) => (
          <div key={c.label} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="text-2xl font-bold text-white">{c.value}</div>
            <div className="text-sm text-gray-400">{c.label}</div>
          </div>
        ))}
      </div>

      {/* Actions bar */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-200">Fleet Nodes</h2>
        <div className="flex gap-2 items-center">
          {msg && (
            <span className="text-sm text-green-400 mr-2">{msg}</span>
          )}
          <button
            onClick={() => setShowFleetRule(true)}
            className="bg-blue-800 hover:bg-blue-700 text-white px-3 py-1.5 rounded text-sm"
          >
            Fleet Rule
          </button>
          <button
            onClick={() => setShowMonitoring(true)}
            className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded text-sm"
            title="Generate a Prometheus scrape config for the fleet"
          >
            Prometheus
          </button>
          <button
            onClick={() => refetch()}
            className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded text-sm"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Node table */}
      {loading && <div className="text-gray-500">Loading…</div>}
      {error && <div className="text-red-400">Error: {error.message}</div>}
      {!loading && !error && (
        <div className="overflow-x-auto rounded-lg border border-gray-700">
          <table className="w-full text-sm">
            <thead className="bg-gray-800 text-gray-400 text-xs uppercase">
              <tr>
                {['', 'Node ID / Label', 'Status', 'Agent', 'Last Seen', 'Actions'].map((h) => (
                  <th key={h} className="px-4 py-2 text-left">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {nodes.map((node) => (
                <tr
                  key={node.id}
                  className="border-t border-gray-800 hover:bg-gray-800/50 transition-colors"
                >
                  {/* Online dot */}
                  <td className="px-4 py-2">
                    <span
                      className={`inline-block w-2 h-2 rounded-full ${
                        online.has(node.id) ? 'bg-green-400' : 'bg-gray-600'
                      }`}
                      title={online.has(node.id) ? 'Online' : 'Offline'}
                    />
                  </td>

                  {/* Node ID / label */}
                  <td className="px-4 py-2">
                    <button
                      onClick={() => onSelectNode({ nodeId: node.id })}
                      className="text-blue-400 hover:text-blue-300 hover:underline text-left"
                    >
                      {nodeDisplayName(node)}
                    </button>
                    <div className="text-gray-600 text-xs">
                      {node.hostname
                        ? [node.label, shortId(node.id)].filter(Boolean).join(' · ')
                        : node.label
                          ? shortId(node.id)
                          : ''}
                    </div>
                    {node.tpmBacked && (
                      <span className="text-xs text-purple-400" title="TPM-backed key">TPM</span>
                    )}
                  </td>

                  {/* Status */}
                  <td className="px-4 py-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor(node.status)}`}>
                      {node.status}
                    </span>
                    {pendingByNode.has(node.id) && (
                      <span
                        className="ml-2 px-2 py-0.5 rounded text-xs font-medium bg-amber-900/70 text-amber-200 border border-amber-700 animate-pulse"
                        title={`Pending confirm (${pendingByNode.get(node.id)!.opKind})`}
                      >
                        ⏳ pending
                      </span>
                    )}
                  </td>

                  {/* Agent version */}
                  <td className="px-4 py-2 text-gray-400">
                    {node.agentVersion ?? '—'}
                  </td>

                  {/* Last seen */}
                  <td className="px-4 py-2 text-gray-400">
                    {relTime(node.lastSeen)}
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-2">
                    <div className="flex gap-1 flex-wrap">
                      {/* Edit label inline */}
                      {labelEdit?.id === node.id ? (
                        <form
                          onSubmit={(e) => {
                            e.preventDefault()
                            handleLabel(node.id, labelEdit.value)
                          }}
                          className="flex gap-1"
                        >
                          <input
                            value={labelEdit.value}
                            onChange={(e) => setLabelEdit({ id: node.id, value: e.target.value })}
                            className="bg-gray-700 border border-gray-600 rounded px-2 py-0.5 text-xs w-28"
                            autoFocus
                          />
                          <button type="submit" className="text-xs bg-green-700 hover:bg-green-600 px-2 py-0.5 rounded">
                            Save
                          </button>
                          <button type="button" onClick={() => setLabelEdit(null)} className="text-xs bg-gray-600 hover:bg-gray-500 px-2 py-0.5 rounded">
                            ✕
                          </button>
                        </form>
                      ) : (
                        <button
                          onClick={() => setLabelEdit({ id: node.id, value: node.label ?? '' })}
                          className="text-xs bg-gray-700 hover:bg-gray-600 px-2 py-0.5 rounded"
                        >
                          Label
                        </button>
                      )}

                      {node.status === 'active' && (
                        <button
                          onClick={() => handleDecommission(node.id)}
                          className="text-xs bg-red-900 hover:bg-red-800 px-2 py-0.5 rounded"
                        >
                          Decommission
                        </button>
                      )}
                      {node.status === 'decommissioned' && (
                        <button
                          onClick={() => handleRemove(node.id)}
                          className="text-xs bg-red-900 hover:bg-red-800 px-2 py-0.5 rounded"
                        >
                          Remove
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {nodes.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-600">
                    No nodes enrolled yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showFleetRule && (
        <FleetRuleCreator
          nodes={nodes}
          onClose={() => setShowFleetRule(false)}
          onCreated={() => {
            setShowFleetRule(false)
            flash('Fleet rule created.')
            refetch()
          }}
        />
      )}

      {showMonitoring && <MonitoringSetup onClose={() => setShowMonitoring(false)} />}
    </div>
  )
}
