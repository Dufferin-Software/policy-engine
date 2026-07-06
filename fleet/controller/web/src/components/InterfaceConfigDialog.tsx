// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import React, { useEffect } from 'react'
import { NodeInterfaceOutput, parseAddresses } from './types.ts'

type Direction = 'ingress' | 'egress'

interface Props {
  iface: NodeInterfaceOutput
  suricataCapable: boolean
  hasIngressRules: boolean
  hasEgressRules: boolean
  error: string | null
  onClearError: () => void
  attachPending: (dir: Direction) => boolean
  actionPending: (dir: Direction) => boolean
  fibPending: boolean
  urpfPending: boolean
  inspectPending: boolean
  onAttach: (dir: Direction) => void
  onDetach: (dir: Direction) => void
  onSetDefaultAction: (dir: Direction, action: string) => void
  onToggleFib: (enabled: boolean) => void
  onSetUrpf: (mode: string) => void
  onToggleInspect: (enabled: boolean) => void
  onClose: () => void
}

function Spinner() {
  return (
    <svg className="animate-spin h-3.5 w-3.5 text-blue-400 inline-block" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
    </svg>
  )
}

interface SegmentOption {
  value: string
  label: string
  /** Classes applied when this option is the active one. */
  activeCls: string
  title?: string
}

function Segmented({
  value,
  options,
  onChange,
  disabled,
}: {
  value: string
  options: SegmentOption[]
  onChange: (v: string) => void
  disabled?: boolean
}) {
  return (
    <span className={`inline-flex rounded overflow-hidden text-xs border border-gray-600 ${disabled ? 'opacity-40 pointer-events-none' : ''}`}>
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => { if (value !== o.value) onChange(o.value) }}
          disabled={disabled}
          title={o.title}
          className={`px-2.5 py-1 font-medium ${value === o.value ? o.activeCls : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
        >
          {o.label}
        </button>
      ))}
    </span>
  )
}

function ConfigRow({
  label,
  desc,
  dimmed,
  control,
}: {
  label: string
  /** Shown as a hover tooltip on the row label. */
  desc: string
  /** Grey the row out (control should also be disabled by the caller). */
  dimmed?: boolean
  control: React.ReactNode
}) {
  return (
    <div className={`flex items-center justify-between gap-4 px-4 py-2 border-t border-gray-800 ${dimmed ? 'opacity-50' : ''}`}>
      <span className="text-sm text-gray-200 cursor-help" title={desc}>{label}</span>
      <div className="flex-shrink-0">{control}</div>
    </div>
  )
}

/** Per-interface configuration dialog: attach state, default action and the
 *  ingress-only features (FIB forwarding, uRPF, IDS inspection), grouped by
 *  direction with the explanation text visible instead of tooltip-only. */
export default function InterfaceConfigDialog({
  iface,
  suricataCapable,
  hasIngressRules,
  hasEgressRules,
  error,
  onClearError,
  attachPending,
  actionPending,
  fibPending,
  urpfPending,
  inspectPending,
  onAttach,
  onDetach,
  onSetDefaultAction,
  onToggleFib,
  onSetUrpf,
  onToggleInspect,
  onClose,
}: Props) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const addrs = parseAddresses(iface.addressesJson)

  function attachRow(dir: Direction) {
    const attached = dir === 'ingress' ? iface.xdpAttached : iface.tcAttached
    const hasRules = dir === 'ingress' ? hasIngressRules : hasEgressRules
    return (
      <ConfigRow
        label="Filtering"
        desc={
          dir === 'ingress'
            ? 'Attach the XDP program to filter inbound packets at line rate.'
            : 'Attach the TC program to filter outbound packets.'
        }
        control={
          attachPending(dir) ? (
            <Spinner />
          ) : (
            <span className="inline-flex items-center gap-2">
              {!attached && hasRules && (
                <span
                  className="text-xs text-amber-400 bg-amber-900/30 border border-amber-700/50 px-1.5 py-0.5 rounded"
                  title="Rules are stored in BPF maps but are not enforced — attach the program to activate them"
                >
                  ⚠ rules inactive
                </span>
              )}
              <Segmented
                value={attached ? 'attached' : 'detached'}
                onChange={(v) => (v === 'attached' ? onAttach(dir) : onDetach(dir))}
                options={[
                  { value: 'detached', label: 'Detached', activeCls: 'bg-gray-600 text-gray-200', title: `No ${dir} filtering on this interface` },
                  { value: 'attached', label: 'Attached', activeCls: 'bg-green-700 text-white', title: `${dir === 'ingress' ? 'XDP' : 'TC'} program attached — ${dir} rules are enforced` },
                ]}
              />
            </span>
          )
        }
      />
    )
  }

  function defaultActionRow(dir: Direction) {
    const attached = dir === 'ingress' ? iface.xdpAttached : iface.tcAttached
    const current = ((dir === 'ingress' ? iface.ingressDefaultAction : iface.egressDefaultAction) ?? 'pass').toLowerCase()
    return (
      <ConfigRow
        label="Default action"
        desc="Verdict applied to packets that match no policy rule."
        dimmed={!attached}
        control={
          actionPending(dir) ? (
            <Spinner />
          ) : (
            <Segmented
              value={current}
              onChange={(v) => onSetDefaultAction(dir, v)}
              disabled={!attached}
              options={[
                { value: 'pass', label: 'PASS', activeCls: 'bg-green-700 text-white', title: 'Unmatched packets are allowed' },
                { value: 'drop', label: 'DROP', activeCls: 'bg-red-700 text-white', title: 'Unmatched packets are dropped' },
              ]}
            />
          )
        }
      />
    )
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between px-4 py-3 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
          <div>
            <h3 className="text-base font-bold text-gray-100">
              Configure <span className="font-mono">{iface.name}</span>
              {iface.tag && <span className="ml-2 text-sm text-blue-400 font-normal">({iface.tag})</span>}
            </h3>
            <div className="text-xs text-gray-500 mt-0.5 space-x-3">
              <span className={iface.linkState.toLowerCase() === 'up' ? 'text-green-400' : 'text-red-400'}>
                link {iface.linkState}
              </span>
              {iface.macAddress && <span className="font-mono">{iface.macAddress}</span>}
              {addrs.length > 0 && (
                <span className="font-mono">{addrs.map((a) => `${a.address}/${a.prefix_len}`).join(', ')}</span>
              )}
            </div>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200 text-lg leading-none px-1" title="Close (Esc)">
            &times;
          </button>
        </div>

        {error && (
          <div className="flex items-center gap-2 px-3 py-2 m-3 bg-red-900/50 border border-red-700 rounded text-xs text-red-300">
            <span className="flex-1">{error}</span>
            <button onClick={onClearError} className="text-red-400 hover:text-red-200 font-bold">&times;</button>
          </div>
        )}

        {/* Ingress */}
        <div className="px-4 pt-3 pb-1">
          <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wide">Ingress</h4>
        </div>
        {attachRow('ingress')}
        {defaultActionRow('ingress')}
        <ConfigRow
          label="FIB forwarding"
          desc="Forward allowed transit packets at line rate via bpf_fib_lookup. Bypasses the kernel stack, so egress filtering on the outbound interface is NOT applied to forwarded traffic."
          dimmed={!iface.xdpAttached}
          control={
            fibPending ? (
              <Spinner />
            ) : (
              <Segmented
                value={iface.fibForwarding ? 'on' : 'off'}
                onChange={(v) => onToggleFib(v === 'on')}
                disabled={!iface.xdpAttached}
                options={[
                  { value: 'off', label: 'Off', activeCls: 'bg-gray-600 text-gray-200' },
                  { value: 'on', label: 'On', activeCls: 'bg-amber-700 text-white' },
                ]}
              />
            )
          }
        />
        <ConfigRow
          label="uRPF"
          desc="Unicast Reverse Path Filtering drops source-spoofed ingress traffic. Loose: drop only if no route to the source exists. Strict: drop unless the route back to the source exits via this interface."
          dimmed={!iface.xdpAttached}
          control={
            urpfPending ? (
              <Spinner />
            ) : (
              <Segmented
                value={(iface.urpfMode || 'off').toLowerCase()}
                onChange={onSetUrpf}
                disabled={!iface.xdpAttached}
                options={[
                  { value: 'off', label: 'Off', activeCls: 'bg-gray-600 text-gray-200' },
                  { value: 'loose', label: 'Loose', activeCls: 'bg-purple-700 text-white' },
                  { value: 'strict', label: 'Strict', activeCls: 'bg-purple-700 text-white' },
                ]}
              />
            )
          }
        />
        {suricataCapable && (
          <ConfigRow
            label="IDS inspection"
            desc="Mirror INSPECT-matched flows on this interface to Suricata. Requires an active node IPS/IDS mode (see node settings) and INSPECT rules to select traffic."
            dimmed={!iface.xdpAttached}
            control={
              inspectPending ? (
                <Spinner />
              ) : (
                <Segmented
                  value={iface.inspectEnabled ? 'on' : 'off'}
                  onChange={(v) => onToggleInspect(v === 'on')}
                  disabled={!iface.xdpAttached}
                  options={[
                    { value: 'off', label: 'Off', activeCls: 'bg-gray-600 text-gray-200' },
                    { value: 'on', label: 'On', activeCls: 'bg-purple-700 text-white' },
                  ]}
                />
              )
            }
          />
        )}

        {/* Egress */}
        <div className="px-4 pt-4 pb-1">
          <h4 className="text-xs font-semibold text-orange-400 uppercase tracking-wide">Egress</h4>
        </div>
        {attachRow('egress')}
        {defaultActionRow('egress')}

        <div className="flex justify-end px-4 py-3 border-t border-gray-700 mt-2">
          <button onClick={onClose} className="px-4 py-1.5 rounded text-sm bg-gray-700 hover:bg-gray-600 text-gray-200">
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
