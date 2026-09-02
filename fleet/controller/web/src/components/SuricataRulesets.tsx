// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState } from 'react'
import { gql, useQuery, useMutation } from '@apollo/client'
import { capabilityFeatures, nodeDisplayName, shortId } from './types.ts'

const GET_RULESETS = gql`
  query GetSuricataRulesets {
    suricataRulesets {
      id name filename sha256 ruleCount createdAt updatedAt assignedNodeIds
    }
    nodes(status: "active") { id label hostname capabilities }
    onlineNodes
  }
`

const GET_RULESET_CONTENT = gql`
  query GetSuricataRuleset($id: ID!) {
    suricataRuleset(id: $id) { id content }
  }
`

const CREATE_RULESET = gql`
  mutation CreateSuricataRuleset($name: String!, $content: String!) {
    createSuricataRuleset(name: $name, content: $content) { id }
  }
`

const UPDATE_RULESET = gql`
  mutation UpdateSuricataRuleset($id: ID!, $content: String!) {
    updateSuricataRuleset(id: $id, content: $content) { id sha256 }
  }
`

const DELETE_RULESET = gql`
  mutation DeleteSuricataRuleset($id: ID!) {
    deleteSuricataRuleset(id: $id) { success message }
  }
`

const ASSIGN_RULESET = gql`
  mutation AssignSuricataRuleset($nodeId: ID!, $rulesetId: ID!) {
    assignSuricataRuleset(nodeId: $nodeId, rulesetId: $rulesetId) { success message }
  }
`

const UNASSIGN_RULESET = gql`
  mutation UnassignSuricataRuleset($nodeId: ID!, $rulesetId: ID!) {
    unassignSuricataRuleset(nodeId: $nodeId, rulesetId: $rulesetId) { success message }
  }
`

const PUSH_RULESETS = gql`
  mutation PushSuricataRulesets($nodeId: ID!) {
    pushSuricataRulesets(nodeId: $nodeId) { success message }
  }
`

interface Ruleset {
  id: string
  name: string
  filename: string
  sha256: string
  ruleCount: number
  createdAt: string
  updatedAt: string
  assignedNodeIds: string[]
}

interface NodeRow {
  id: string
  label: string | null
  hostname: string | null
  capabilities: string
}

interface RulesetsData {
  suricataRulesets: Ruleset[]
  nodes: NodeRow[]
  onlineNodes: string[]
}

function suricataCapable(capabilities: string): boolean {
  return capabilityFeatures(capabilities).includes('suricata')
}

export default function SuricataRulesets() {
  const { data, refetch } = useQuery<RulesetsData>(GET_RULESETS, { pollInterval: 10000 })
  const [createRuleset] = useMutation(CREATE_RULESET)
  const [updateRuleset] = useMutation(UPDATE_RULESET)
  const [deleteRuleset] = useMutation(DELETE_RULESET)
  const [assignRuleset] = useMutation(ASSIGN_RULESET)
  const [unassignRuleset] = useMutation(UNASSIGN_RULESET)
  const [pushRulesets] = useMutation(PUSH_RULESETS)

  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('')
  const [newContent, setNewContent] = useState('')
  const [editing, setEditing] = useState<{ id: string; content: string } | null>(null)
  const [assigning, setAssigning] = useState<string | null>(null) // ruleset id
  const [error, setError] = useState<string | null>(null)

  const { refetch: fetchContent } = useQuery(GET_RULESET_CONTENT, { skip: true })

  const rulesets = data?.suricataRulesets ?? []
  const nodes = data?.nodes ?? []
  const online = new Set(data?.onlineNodes ?? [])
  const capableNodes = nodes.filter((n) => suricataCapable(n.capabilities))

  const flash = (msg: string) => {
    setError(msg)
    setTimeout(() => setError(null), 6000)
  }

  const run = async (fn: () => Promise<{ success?: boolean; message?: string | null } | undefined>) => {
    try {
      const r = await fn()
      if (r && r.success === false) flash(r.message ?? 'Operation failed')
      else refetch()
    } catch (e) {
      flash(String(e).replace(/^ApolloError:\s*/, ''))
    }
  }

  const nodeLabel = (id: string) => {
    const n = nodes.find((x) => x.id === id)
    const name = n ? nodeDisplayName(n) : shortId(id)
    return online.has(id) ? name : `${name} (offline)`
  }

  const openEditor = async (id: string) => {
    try {
      const res = await fetchContent({ id })
      setEditing({ id, content: res.data?.suricataRuleset?.content ?? '' })
    } catch (e) {
      flash(String(e))
    }
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="px-3 py-2 bg-red-900/50 border border-red-700 rounded text-xs text-red-300">
          {error}
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-gray-200">Suricata rulesets</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Fleet-managed signature files. Each ruleset lands on assigned nodes as{' '}
            <span className="font-mono">fleet-&lt;name&gt;.rules</span>; node-local rule files are
            never touched. Nodes converge automatically on drift.
          </p>
        </div>
        <button
          onClick={() => setCreating((v) => !v)}
          className="px-2 py-1 text-xs rounded bg-blue-700 text-white hover:bg-blue-600"
        >
          {creating ? 'Cancel' : 'New ruleset'}
        </button>
      </div>

      {creating && (
        <div className="border border-gray-700 rounded p-3 space-y-2 bg-gray-900/40">
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="ruleset-name (lowercase, digits, - _)"
            className="w-64 bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs text-gray-200 font-mono"
          />
          <textarea
            value={newContent}
            onChange={(e) => setNewContent(e.target.value)}
            placeholder={'alert tcp any any -> any any (msg:"…"; sid:1000001; rev:1;)'}
            rows={8}
            className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs text-gray-200 font-mono"
          />
          <button
            onClick={() =>
              run(async () => {
                const r = await createRuleset({ variables: { name: newName.trim(), content: newContent } })
                if (r.data?.createSuricataRuleset?.id) {
                  setCreating(false)
                  setNewName('')
                  setNewContent('')
                }
                return { success: true }
              })
            }
            disabled={!newName.trim() || !newContent.trim()}
            className="px-2 py-1 text-xs rounded bg-green-700 text-white hover:bg-green-600 disabled:opacity-40"
          >
            Create
          </button>
        </div>
      )}

      {rulesets.length === 0 && !creating && (
        <div className="text-sm text-gray-600 py-6 text-center">No rulesets yet.</div>
      )}

      {rulesets.map((rs) => (
        <div key={rs.id} className="border border-gray-800 rounded p-3 space-y-2">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm text-gray-200">{rs.filename}</span>
            <span className="text-xs text-gray-500">
              {rs.ruleCount} rules · sha256 {rs.sha256.slice(0, 12)}…
            </span>
            <span className="ml-auto inline-flex gap-1.5">
              <button
                onClick={() => openEditor(rs.id)}
                className="px-1.5 py-0.5 text-[11px] rounded border bg-gray-800 border-gray-700 text-gray-300 hover:text-white"
              >
                Edit
              </button>
              <button
                onClick={() => setAssigning((v) => (v === rs.id ? null : rs.id))}
                className="px-1.5 py-0.5 text-[11px] rounded border bg-gray-800 border-gray-700 text-gray-300 hover:text-white"
              >
                Assign
              </button>
              <button
                onClick={() => {
                  if (confirm(`Delete ruleset ${rs.name}? Its file is removed from all assigned nodes.`))
                    run(async () => (await deleteRuleset({ variables: { id: rs.id } })).data?.deleteSuricataRuleset)
                }}
                className="px-1.5 py-0.5 text-[11px] rounded border bg-red-900/40 border-red-700 text-red-300 hover:bg-red-900/70"
              >
                Delete
              </button>
            </span>
          </div>

          {editing?.id === rs.id && (
            <div className="space-y-2">
              <textarea
                value={editing.content}
                onChange={(e) => setEditing({ id: rs.id, content: e.target.value })}
                rows={10}
                className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs text-gray-200 font-mono"
              />
              <span className="inline-flex gap-1.5">
                <button
                  onClick={() =>
                    run(async () => {
                      await updateRuleset({ variables: { id: rs.id, content: editing.content } })
                      setEditing(null)
                      return { success: true }
                    })
                  }
                  className="px-2 py-0.5 text-xs rounded bg-green-700 text-white hover:bg-green-600"
                >
                  Save & sync
                </button>
                <button
                  onClick={() => setEditing(null)}
                  className="px-2 py-0.5 text-xs rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
                >
                  Cancel
                </button>
              </span>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-gray-500">Nodes:</span>
            {rs.assignedNodeIds.length === 0 && <span className="text-gray-600">none</span>}
            {rs.assignedNodeIds.map((nid) => (
              <span
                key={nid}
                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-300"
              >
                {nodeLabel(nid)}
                <button
                  onClick={() =>
                    run(async () =>
                      (await pushRulesets({ variables: { nodeId: nid } })).data?.pushSuricataRulesets
                    )
                  }
                  className="text-cyan-400 hover:text-cyan-200"
                  title="Force a sync of this node now and wait for its confirm"
                >
                  push
                </button>
                <button
                  onClick={() =>
                    run(async () =>
                      (await unassignRuleset({ variables: { nodeId: nid, rulesetId: rs.id } })).data
                        ?.unassignSuricataRuleset
                    )
                  }
                  className="text-red-400 hover:text-red-200"
                  title="Unassign (removes the file from the node)"
                >
                  ×
                </button>
              </span>
            ))}
          </div>

          {assigning === rs.id && (
            <div className="flex flex-wrap gap-1.5 text-xs border-t border-gray-800 pt-2">
              <span className="text-gray-500">Assign to:</span>
              {capableNodes.filter((n) => !rs.assignedNodeIds.includes(n.id)).length === 0 && (
                <span className="text-gray-600">no unassigned suricata-capable nodes</span>
              )}
              {capableNodes
                .filter((n) => !rs.assignedNodeIds.includes(n.id))
                .map((n) => (
                  <button
                    key={n.id}
                    onClick={() =>
                      run(async () => {
                        const r = (
                          await assignRuleset({ variables: { nodeId: n.id, rulesetId: rs.id } })
                        ).data?.assignSuricataRuleset
                        if (r?.success) setAssigning(null)
                        return r
                      })
                    }
                    className="px-1.5 py-0.5 rounded border bg-blue-900/40 border-blue-700 text-blue-300 hover:bg-blue-900/70"
                  >
                    {nodeLabel(n.id)}
                  </button>
                ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
