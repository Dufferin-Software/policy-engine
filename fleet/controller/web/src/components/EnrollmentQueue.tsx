// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useEffect, useState } from 'react'
import { useQuery, useMutation, gql } from '@apollo/client'
import { ControlledNode, relTime, shortId } from './types.ts'

const GET_PENDING = gql`
  query GetPending {
    pendingEnrollments {
      id label hostname dmiUuid tpmBacked enrolledAt agentVersion
    }
  }
`

const GET_SERVICE_ENDPOINTS = gql`
  query GetServiceEndpoints {
    serviceEndpoints { controllerUrl enrollmentUrl }
  }
`

const APPROVE = gql`
  mutation Approve($nodeId: ID!, $label: String) {
    approveEnrollment(nodeId: $nodeId, label: $label) { id label status }
  }
`

const REJECT = gql`
  mutation Reject($nodeId: ID!, $reason: String) {
    rejectEnrollment(nodeId: $nodeId, reason: $reason) { success message }
  }
`

const CREATE_ENROLLMENT_TOKEN = gql`
  mutation CreateEnrollmentToken(
    $enrollmentUrl: String!
    $controllerUrl: String!
    $ttlSeconds: Int!
    $maxUses: Int!
    $cidrScope: String
    $fleetLabel: String
  ) {
    createEnrollmentToken(
      enrollmentUrl: $enrollmentUrl
      controllerUrl: $controllerUrl
      ttlSeconds: $ttlSeconds
      maxUses: $maxUses
      cidrScope: $cidrScope
      fleetLabel: $fleetLabel
    ) {
      tokenId
      bundle
      expiresAt
      usesRemaining
    }
  }
`

// Matches the CLI's parse_duration (s/m/h/d, default seconds).
function parseDuration(s: string): number | null {
  const m = s.trim().match(/^(\d+)([smhd]?)$/)
  if (!m) return null
  const n = parseInt(m[1], 10)
  const unit = m[2] || 's'
  const mult = unit === 'm' ? 60 : unit === 'h' ? 3600 : unit === 'd' ? 86400 : 1
  return n * mult
}

interface IssuedToken {
  tokenId: string
  bundle: string
  expiresAt: string
  usesRemaining: number
}

function MintEnrollmentBundle() {
  const { data: ep } = useQuery<{
    serviceEndpoints: { controllerUrl: string; enrollmentUrl: string }
  }>(GET_SERVICE_ENDPOINTS)
  const [createToken, { loading }] = useMutation<{
    createEnrollmentToken: IssuedToken
  }>(CREATE_ENROLLMENT_TOKEN)

  const [ttl, setTtl] = useState('10m')
  const [fleetLabel, setFleetLabel] = useState('')
  const [maxUses, setMaxUses] = useState('1')
  const [cidr, setCidr] = useState('')
  const [controllerUrl, setControllerUrl] = useState('')
  const [enrollmentUrl, setEnrollmentUrl] = useState('')
  const [issued, setIssued] = useState<IssuedToken | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  // Pre-fill URLs from the controller once the query resolves.
  useEffect(() => {
    if (ep?.serviceEndpoints) {
      if (!controllerUrl) setControllerUrl(ep.serviceEndpoints.controllerUrl)
      if (!enrollmentUrl) setEnrollmentUrl(ep.serviceEndpoints.enrollmentUrl)
    }
  }, [ep, controllerUrl, enrollmentUrl])

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setIssued(null)
    const ttlSecs = parseDuration(ttl)
    if (ttlSecs == null || ttlSecs <= 0) {
      setError(`Invalid TTL "${ttl}" — use forms like 30s, 10m, 1h, 7d`)
      return
    }
    const uses = parseInt(maxUses, 10)
    if (!Number.isFinite(uses) || uses < 1) {
      setError('Max uses must be ≥ 1')
      return
    }
    try {
      const res = await createToken({
        variables: {
          enrollmentUrl,
          controllerUrl,
          ttlSeconds: ttlSecs,
          maxUses: uses,
          cidrScope: cidr.trim() || null,
          fleetLabel: fleetLabel.trim() || null,
        },
      })
      if (res.data?.createEnrollmentToken) setIssued(res.data.createEnrollmentToken)
    } catch (e) {
      setError(String(e).replace(/^ApolloError:\s*/, ''))
    }
  }

  async function onCopy() {
    if (!issued) return
    await navigator.clipboard.writeText(issued.bundle)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function onDownload() {
    if (!issued) return
    const blob = new Blob([issued.bundle], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `enrollment-bundle-${issued.tokenId.slice(0, 12)}.b64`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 space-y-3">
      <h3 className="text-sm font-semibold text-gray-200">Mint enrollment bundle</h3>
      <p className="text-xs text-gray-500">
        Generates a ZTP bundle (base64) to copy onto a new node. The bundle
        carries the controller URL, enrollment URL, and a single-use token.
      </p>

      <form onSubmit={onSubmit} className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
        <label
          className="flex flex-col gap-1"
          title="How long the token stays valid before it expires and can no longer be redeemed. Use s/m/h/d (e.g. 30s, 10m, 1h, 7d). Short TTLs are the norm — generate, install, redeem, done."
        >
          <span className="text-gray-500 cursor-help underline decoration-dotted decoration-gray-600">TTL</span>
          <input
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            placeholder="10m"
            title="Token lifetime, e.g. 30s, 10m, 1h, 7d."
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label
          className="flex flex-col gap-1"
          title="Optional tag stamped onto every node that enrolls via this bundle. Useful for grouping a rollout (e.g. 'home-fleet', 'lab-bench'); appears alongside the node in the Fleet table and audit log."
        >
          <span className="text-gray-500 cursor-help underline decoration-dotted decoration-gray-600">Fleet label</span>
          <input
            value={fleetLabel}
            onChange={(e) => setFleetLabel(e.target.value)}
            placeholder="(optional)"
            title="Tag applied to every node that enrolls with this bundle."
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-gray-200"
          />
        </label>
        <label
          className="flex flex-col gap-1"
          title="How many distinct nodes may redeem this bundle before it is exhausted. Default 1 = single-use (recommended). Set higher to onboard a batch of machines with a single bundle; each redemption decrements uses_remaining."
        >
          <span className="text-gray-500 cursor-help underline decoration-dotted decoration-gray-600">Max uses</span>
          <input
            value={maxUses}
            onChange={(e) => setMaxUses(e.target.value)}
            title="Number of nodes that may redeem this bundle. 1 = single-use."
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label
          className="flex flex-col gap-1"
          title="Optional source-IP restriction (e.g. 10.0.0.0/24) recorded on the token, intended to limit which network a node may enroll from. Stored on the token record for audit; runtime enforcement is not yet wired up, so treat this as documentation for now."
        >
          <span className="text-gray-500 cursor-help underline decoration-dotted decoration-gray-600">CIDR scope</span>
          <input
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="(optional)"
            title="e.g. 10.0.0.0/24 — recorded for audit; enforcement TBD."
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label
          className="flex flex-col gap-1 md:col-span-2"
          title="mTLS management endpoint the agent connects to after enrollment, for AgentHello, rule sync, event streaming. Pre-filled from the controller's server_san + management_addr port — edit if agents reach the controller via a different hostname (e.g. behind a load balancer)."
        >
          <span className="text-gray-500 cursor-help underline decoration-dotted decoration-gray-600">Controller URL (mgmt)</span>
          <input
            value={controllerUrl}
            onChange={(e) => setControllerUrl(e.target.value)}
            title="mTLS management URL the agent talks to once enrolled."
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <label
          className="flex flex-col gap-1 md:col-span-2"
          title="One-time TLS enrollment endpoint embedded in the bundle. The agent calls this URL with the token to receive its client cert; after that it switches to the management URL. Pre-filled from server_san + enrollment_addr port."
        >
          <span className="text-gray-500 cursor-help underline decoration-dotted decoration-gray-600">Enrollment URL</span>
          <input
            value={enrollmentUrl}
            onChange={(e) => setEnrollmentUrl(e.target.value)}
            title="TLS enrollment URL the agent calls once to redeem the token."
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-gray-200 font-mono"
          />
        </label>
        <div className="md:col-span-4 flex items-center gap-3">
          <button
            type="submit"
            disabled={loading || !controllerUrl || !enrollmentUrl}
            title="Mint the token and produce a base64 bundle to install on the new node."
            className="bg-blue-700 hover:bg-blue-600 disabled:opacity-40 text-white px-4 py-1.5 rounded text-sm font-medium"
          >
            {loading ? 'Minting…' : 'Generate bundle'}
          </button>
          {error && <span className="text-red-400 text-xs">{error}</span>}
        </div>
      </form>

      {issued && (
        <div className="space-y-2 pt-3 border-t border-gray-700">
          <div className="flex items-center justify-between">
            <div className="text-xs text-gray-400">
              Token <span className="font-mono text-gray-300">{shortId(issued.tokenId)}</span>
              {' · '}
              expires {new Date(issued.expiresAt).toISOString().slice(0, 19)}Z
              {' · '}
              {issued.usesRemaining} use{issued.usesRemaining === 1 ? '' : 's'} left
            </div>
            <div className="flex gap-2">
              <button
                onClick={onCopy}
                title="Copy the base64 bundle to the clipboard so you can paste it onto the new node."
                className="bg-gray-700 hover:bg-gray-600 text-gray-200 px-3 py-1 rounded text-xs"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={onDownload}
                title="Save the bundle as a .b64 file (equivalent to '> bundle.b64' on the CLI)."
                className="bg-gray-700 hover:bg-gray-600 text-gray-200 px-3 py-1 rounded text-xs"
              >
                Download
              </button>
            </div>
          </div>
          <textarea
            readOnly
            value={issued.bundle}
            rows={6}
            onFocus={(e) => e.currentTarget.select()}
            className="w-full bg-gray-900 border border-gray-700 rounded p-2 font-mono text-[11px] text-gray-300 break-all"
          />
          <p className="text-xs text-amber-300/80">
            Save this now — the raw token cannot be retrieved again.
          </p>
        </div>
      )}
    </div>
  )
}

export default function EnrollmentQueue() {
  const { data, loading, error, refetch } = useQuery<{ pendingEnrollments: ControlledNode[] }>(
    GET_PENDING,
    { pollInterval: 10_000 },
  )

  const [approve] = useMutation(APPROVE)
  const [reject] = useMutation(REJECT)

  const [labels, setLabels] = useState<Record<string, string>>({})
  const [msg, setMsg] = useState<string | null>(null)

  function flash(m: string) {
    setMsg(m)
    setTimeout(() => setMsg(null), 4000)
  }

  async function handleApprove(nodeId: string) {
    const label = labels[nodeId]?.trim() || undefined
    await approve({ variables: { nodeId, label } })
    flash(`Node ${shortId(nodeId)} approved.`)
    refetch()
  }

  async function handleReject(nodeId: string) {
    const reason = prompt('Rejection reason (optional):')
    if (reason === null) return
    await reject({ variables: { nodeId, reason: reason || undefined } })
    flash(`Node ${shortId(nodeId)} rejected.`)
    refetch()
  }

  const pending = data?.pendingEnrollments ?? []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-200">Enrollment Queue</h2>
          <p className="text-sm text-gray-500">
            Nodes that have requested enrollment and are waiting for approval.
          </p>
        </div>
        <div className="flex gap-2 items-center">
          {msg && <span className="text-sm text-green-400">{msg}</span>}
          <button
            onClick={() => refetch()}
            className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded text-sm"
          >
            Refresh
          </button>
        </div>
      </div>

      <MintEnrollmentBundle />

      {loading && <div className="text-gray-500">Loading…</div>}
      {error && <div className="text-red-400">Error: {error.message}</div>}

      {!loading && !error && pending.length === 0 && (
        <div className="text-center py-12 text-gray-600 bg-gray-800/50 rounded-lg border border-gray-700">
          No pending enrollments.
        </div>
      )}

      {pending.map((node) => (
        <div
          key={node.id}
          className="bg-gray-800 rounded-lg border border-yellow-800/50 p-4 space-y-3"
        >
          <div className="flex items-start justify-between">
            <div>
              <div className="font-mono text-yellow-300 text-sm">
                {node.hostname ? `${node.hostname} — ` : ''}{shortId(node.id)}
              </div>
              <div className="text-xs text-gray-500 mt-0.5">
                Submitted {relTime(node.enrolledAt)}
                {node.agentVersion && ` · agent v${node.agentVersion}`}
                {node.tpmBacked && ' · TPM'}
                {node.dmiUuid && ` · ${node.dmiUuid}`}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              value={labels[node.id] ?? ''}
              onChange={(e) =>
                setLabels((prev) => ({ ...prev, [node.id]: e.target.value }))
              }
              placeholder="Label (optional)"
              className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={() => handleApprove(node.id)}
              className="bg-green-700 hover:bg-green-600 text-white px-4 py-1.5 rounded text-sm font-medium"
            >
              Approve
            </button>
            <button
              onClick={() => handleReject(node.id)}
              className="bg-red-800 hover:bg-red-700 text-white px-4 py-1.5 rounded text-sm font-medium"
            >
              Reject
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}
