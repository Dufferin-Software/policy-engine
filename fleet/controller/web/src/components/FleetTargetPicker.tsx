// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useMemo, useState } from 'react'
import { useQuery, gql } from '@apollo/client'
import { ControlledNode, nodeDisplayName, shortId } from './types.ts'

const GET_ALL_INTERFACES = gql`
  query GetAllNodeInterfaces {
    allNodeInterfaces { nodeId name xdpAttached tcAttached }
  }
`

// Which fleet action the picker is feeding. Traffic rules apply to either
// direction; FIB forwarding and uRPF are XDP ingress-only features.
export type TargetMode = 'rule' | 'fib' | 'urpf'

export interface Target {
  nodeId: string
  nodeLabel: string
  interfaceName: string
  direction: string
}

interface AllIfaceData {
  allNodeInterfaces: { nodeId: string; name: string; xdpAttached: boolean; tcAttached: boolean }[]
}

// An interface is "active" for a direction only when the matching program is
// attached: XDP for ingress, TC for egress. Targets on an interface with no
// program attached are stored but never take effect until it is enabled.
function ifaceActiveForDir(att: { xdpAttached: boolean; tcAttached: boolean } | undefined, dir: string): boolean {
  if (!att) return false
  return dir === 'ingress' ? att.xdpAttached : att.tcAttached
}

interface Props {
  nodes: ControlledNode[]
  mode: TargetMode
  targets: Target[]
  onChange: (targets: Target[]) => void
}

export default function FleetTargetPicker({ nodes, mode, targets, onChange }: Props) {
  const { data: ifaceData } = useQuery<AllIfaceData>(GET_ALL_INTERFACES)

  const activeNodes = nodes.filter((n) => n.status === 'active')

  // FIB and uRPF are ingress-only (XDP); rules can target either direction.
  const ingressOnly = mode !== 'rule'

  // ── Target picker session state ──────────────────────────────────────────
  const [pickNodeId, setPickNodeId] = useState('')
  // ifaceName -> direction for the current picker session
  const [pickSelections, setPickSelections] = useState<Map<string, string>>(new Map())

  // Per-node interface list from the query
  const ifacesByNode = useMemo(() => {
    const map = new Map<string, string[]>()
    for (const iface of ifaceData?.allNodeInterfaces ?? []) {
      if (!map.has(iface.nodeId)) map.set(iface.nodeId, [])
      map.get(iface.nodeId)!.push(iface.name)
    }
    map.forEach((names) => names.sort())
    return map
  }, [ifaceData])

  // Attachment status keyed by "nodeId|interfaceName" so targets can be checked
  // against the program (XDP/TC) actually attached for their direction.
  const attachByKey = useMemo(() => {
    const map = new Map<string, { xdpAttached: boolean; tcAttached: boolean }>()
    for (const iface of ifaceData?.allNodeInterfaces ?? []) {
      map.set(`${iface.nodeId}|${iface.name}`, { xdpAttached: iface.xdpAttached, tcAttached: iface.tcAttached })
    }
    return map
  }, [ifaceData])

  function targetIsActive(t: Target): boolean {
    return ifaceActiveForDir(attachByKey.get(`${t.nodeId}|${t.interfaceName}`), t.direction)
  }

  const inactiveTargets = targets.filter((t) => !targetIsActive(t))
  const pickedNodeInterfaces = pickNodeId ? (ifacesByNode.get(pickNodeId) ?? []) : []

  function onPickNodeChange(nodeId: string) {
    setPickNodeId(nodeId)
    setPickSelections(new Map())
  }

  function togglePickIface(ifaceName: string) {
    setPickSelections((prev) => {
      const next = new Map(prev)
      if (next.has(ifaceName)) next.delete(ifaceName)
      else next.set(ifaceName, 'ingress') // default direction
      return next
    })
  }

  function setPickDir(ifaceName: string, dir: string) {
    setPickSelections((prev) => new Map(prev).set(ifaceName, dir))
  }

  function addTargets() {
    if (!pickNodeId || pickSelections.size === 0) return
    const node = activeNodes.find((n) => n.id === pickNodeId)
    const nodeLabel = node ? nodeDisplayName(node) : shortId(pickNodeId)
    const newTargets: Target[] = []
    for (const [ifaceName, dir] of pickSelections) {
      const direction = ingressOnly ? 'ingress' : dir
      const exists = targets.some(
        (t) => t.nodeId === pickNodeId && t.interfaceName === ifaceName && t.direction === direction,
      )
      if (!exists) newTargets.push({ nodeId: pickNodeId, nodeLabel, interfaceName: ifaceName, direction })
    }
    onChange([...targets, ...newTargets])
    setPickNodeId('')
    setPickSelections(new Map())
  }

  function removeTarget(idx: number) {
    onChange(targets.filter((_, i) => i !== idx))
  }

  // Warning copy depends on which programs the mode needs.
  const inactiveWarning = ingressOnly
    ? 'are on interfaces with no XDP program attached for ingress. The action will be ' +
      'stored but has no effect until each interface is enabled.'
    : 'are on interfaces with no program attached for the chosen direction ' +
      '(ingress → XDP, egress → TC). The rule will be stored but has no effect until ' +
      'each interface is explicitly enabled.'

  return (
    <div className="space-y-2">
      <label className="block text-xs text-gray-400 font-medium uppercase tracking-wide">
        1 · Add Targets
      </label>

      {/* Node picker */}
      <select
        value={pickNodeId}
        onChange={(e) => onPickNodeChange(e.target.value)}
        className="w-full bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
      >
        <option value="">— select a node —</option>
        {activeNodes.map((n) => (
          <option key={n.id} value={n.id}>
            {nodeDisplayName(n)}{n.hostname && n.label ? ` — ${n.label}` : ''}
          </option>
        ))}
      </select>

      {/* Interface list for selected node */}
      {pickNodeId && (
        <div className="bg-gray-800 rounded border border-gray-700 overflow-hidden">
          {pickedNodeInterfaces.length === 0 ? (
            <div className="text-xs text-gray-600 p-2">No interfaces reported for this node.</div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-700 text-gray-500">
                  <th className="px-3 py-1.5 text-left font-medium w-6"></th>
                  <th className="px-3 py-1.5 text-left font-medium">Interface</th>
                  {!ingressOnly && <th className="px-3 py-1.5 text-left font-medium">Direction</th>}
                </tr>
              </thead>
              <tbody>
                {pickedNodeInterfaces.map((iface) => {
                  const checked = pickSelections.has(iface)
                  const dir = pickSelections.get(iface) ?? 'ingress'
                  return (
                    <tr key={iface} className="border-t border-gray-700/50">
                      <td className="px-3 py-1">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => togglePickIface(iface)}
                          className="rounded border-gray-600"
                        />
                      </td>
                      <td className="px-3 py-1 font-mono text-gray-200">{iface}</td>
                      {!ingressOnly && (
                        <td className="px-3 py-1">
                          {checked ? (
                            <select
                              value={dir}
                              onChange={(e) => setPickDir(iface, e.target.value)}
                              className="bg-gray-700 border border-gray-600 rounded px-1.5 py-0.5 text-xs focus:outline-none focus:border-blue-500"
                            >
                              <option value="ingress">Ingress</option>
                              <option value="egress">Egress</option>
                            </select>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </td>
                      )}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
          {pickSelections.size > 0 && (
            <div className="px-3 py-2 border-t border-gray-700 flex justify-end">
              <button
                type="button"
                onClick={addTargets}
                className="text-xs bg-blue-800 hover:bg-blue-700 text-blue-100 px-3 py-1 rounded"
              >
                Add {pickSelections.size} target{pickSelections.size !== 1 ? 's' : ''}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Accumulated target list */}
      {targets.length > 0 && (
        <div className="bg-gray-800 rounded border border-gray-700 overflow-hidden">
          <div className="px-3 py-1.5 border-b border-gray-700 text-xs text-gray-400 font-medium">
            Targets ({targets.length})
          </div>
          <table className="w-full text-xs">
            <tbody>
              {targets.map((t, i) => {
                const inactive = !targetIsActive(t)
                return (
                  <tr key={i} className="border-t border-gray-700/50">
                    <td className="px-3 py-1 text-gray-300">{t.nodeLabel}</td>
                    <td className="px-3 py-1 font-mono text-gray-300">{t.interfaceName}</td>
                    <td className="px-3 py-1 text-gray-400">
                      {t.direction}
                      {inactive && (
                        <span
                          className="ml-2 px-1.5 py-0.5 rounded bg-amber-900/50 text-amber-300 text-[10px] font-medium"
                          title={`No ${t.direction === 'ingress' ? 'XDP' : 'TC'} program attached — action will not take effect until the interface is enabled.`}
                        >
                          inactive
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-1 text-right">
                      <button
                        type="button"
                        onClick={() => removeTarget(i)}
                        className="text-red-500 hover:text-red-400"
                        title="Remove"
                      >
                        &times;
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {inactiveTargets.length > 0 && (
        <div className="text-xs text-amber-300 bg-amber-900/30 border border-amber-800/50 px-3 py-2 rounded">
          <span className="font-semibold">Heads up:</span>{' '}
          {inactiveTargets.length} of {targets.length} target{targets.length !== 1 ? 's' : ''}{' '}
          {inactiveTargets.length === 1 ? 'is' : 'are'} {inactiveWarning}
        </div>
      )}
    </div>
  )
}
