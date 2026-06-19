// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

// GraphQL response types matching the controller schema.

export interface ControlledNode {
  id: string
  label: string | null
  hostname: string | null
  dmiUuid: string | null
  status: string
  certExpiry: string | null
  lastSeen: string | null
  enrolledAt: string | null
  tpmBacked: boolean
  agentVersion: string | null
  osPrettyName: string | null
  kernelVersion: string | null
  dmiSysVendor: string | null
  dmiProductName: string | null
  tenantId: string
  stopBehavior: string | null
  metricsIntervalSecs: number | null
}

export interface RuleOutput {
  id: string
  tenantId: string
  nodeId: string
  interfaceName: string
  direction: string
  srcCidr: string | null
  dstCidr: string | null
  srcPort: number | null
  dstPort: number | null
  protocol: string
  sniPattern: string | null
  quicVersion: string | null
  srcMac: string | null
  dstMac: string | null
  actionsJson: string
  createdAt: string
  createdBy: string | null
  expiresAfterSecs: number | null
  scheduleJson: string | null
}

export interface NodeInterfaceOutput {
  nodeId: string
  name: string
  macAddress: string | null
  linkState: string
  addressesJson: string
  tag: string | null
  lastReported: string
  xdpAttached: boolean
  tcAttached: boolean
  fibForwarding: boolean
  ingressDefaultAction: string | null
  egressDefaultAction: string | null
}

export interface AuditEntry {
  id: number
  ts: string
  operator: string | null
  action: string
  nodeId: string | null
  detail: string | null
}

export interface AuditExport {
  filename: string
  contentType: string
  data: string
}

export interface OperationResult {
  success: boolean
  message: string | null
}

// ── Common UI helpers ─────────────────────────────────────────────────────────

export function statusColor(status: string): string {
  switch (status) {
    case 'active':
      return 'bg-green-800 text-green-200'
    case 'pending':
      return 'bg-yellow-800 text-yellow-200'
    case 'decommissioned':
      return 'bg-red-900 text-red-300'
    default:
      return 'bg-gray-700 text-gray-300'
  }
}

export function relTime(iso: string | null): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function shortId(id: string): string {
  return id.slice(0, 12) + '…'
}

// Primary display name for a node: prefer the hostname (distinctive per box)
// over a user label (often the shared fleet name), falling back to the short id.
export function nodeDisplayName(
  node: { hostname: string | null; label: string | null; id: string },
): string {
  return node.hostname ?? node.label ?? shortId(node.id)
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n}B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}M`
  return `${(n / 1024 / 1024 / 1024).toFixed(1)}G`
}

export function fmtCount(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`
  return `${(n / 1_000_000).toFixed(1)}M`
}
