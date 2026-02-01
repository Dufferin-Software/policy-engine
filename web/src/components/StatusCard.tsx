// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { gql, useQuery, useMutation } from '@apollo/client'
import { useState } from 'react'

const GET_STATUS = gql`
  query GetStatus {
    status {
      running
      version
      uptimeSecs
      programAttached
      inspectMode
      suricataRunning
      cpuAffinity {
        disabled
        controlCpus
        eventCpus
        dataplaneCpus
        actixWorkers
      }
    }
    interfaces {
      interface
      mode
      direction
    }
    stopBehavior {
      behavior
    }
  }
`

const SET_STOP_BEHAVIOR = gql`
  mutation ConfigureStopBehavior($behavior: String!) {
    configureStopBehavior(input: { stopBehavior: $behavior }) {
      success
      message
    }
  }
`

interface CpuAffinityStatus {
  disabled: boolean
  controlCpus: number[]
  eventCpus: number[]
  dataplaneCpus: number[]
  actixWorkers: number
}

interface ServerStatus {
  running: boolean
  version: string
  uptimeSecs: number
  programAttached: boolean
  inspectMode: string | null
  suricataRunning: boolean | null
  cpuAffinity: CpuAffinityStatus
}

interface InterfaceAttachment {
  interface: string
  mode: string
  direction: string
}

interface StopBehaviorData {
  behavior: string
}

interface StatusData {
  status: ServerStatus
  interfaces: InterfaceAttachment[]
  stopBehavior: StopBehaviorData
}

interface OperationResult {
  success: boolean
  message: string
}

function formatUptime(secs: number): string {
  const days = Math.floor(secs / 86400)
  const hours = Math.floor((secs % 86400) / 3600)
  const minutes = Math.floor((secs % 3600) / 60)
  const seconds = secs % 60

  const parts = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  if (minutes > 0) parts.push(`${minutes}m`)
  parts.push(`${seconds}s`)

  return parts.join(' ')
}

/** Compress a sorted CPU list into a range string: [0,1,2,4,5] → "0-2,4-5" */
function formatCpuList(cpus: number[]): string {
  if (cpus.length === 0) return '—'
  const sorted = [...cpus].sort((a, b) => a - b)
  const parts: string[] = []
  let start = sorted[0],
    end = sorted[0]
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i] === end + 1) {
      end = sorted[i]
    } else {
      parts.push(start === end ? `${start}` : `${start}-${end}`)
      start = end = sorted[i]
    }
  }
  parts.push(start === end ? `${start}` : `${start}-${end}`)
  return parts.join(',')
}

function AffinityBadge({ affinity }: { affinity: CpuAffinityStatus }) {
  if (affinity.disabled) {
    return (
      <span className="px-2 py-1 rounded text-sm bg-gray-500/20 text-gray-400">
        Pinning disabled
      </span>
    )
  }
  const dp = formatCpuList(affinity.dataplaneCpus)
  const ctrl = formatCpuList(affinity.controlCpus)
  const evt = formatCpuList(affinity.eventCpus)
  return (
    <span className="font-mono text-xs text-gray-300">
      ctrl:{ctrl} evt:{evt} dp:{dp}
    </span>
  )
}

export function StatusCard() {
  const [stopBehaviorPending, setStopBehaviorPending] = useState(false)
  const [stopBehaviorFeedback, setStopBehaviorFeedback] = useState<string | null>(null)

  const { loading, error, data, refetch } = useQuery<StatusData>(GET_STATUS, {
    pollInterval: 5000,
  })

  const [configureStopBehavior] = useMutation<{ configureStopBehavior: OperationResult }>(
    SET_STOP_BEHAVIOR,
    { onCompleted: () => refetch() }
  )

  const handleStopBehaviorToggle = async () => {
    const current = data?.stopBehavior?.behavior ?? 'clear-state'
    const next = current === 'clear-state' ? 'preserve-state' : 'clear-state'
    setStopBehaviorPending(true)
    setStopBehaviorFeedback(null)
    try {
      const result = await configureStopBehavior({ variables: { behavior: next } })
      if (!result.data?.configureStopBehavior.success) {
        setStopBehaviorFeedback(result.data?.configureStopBehavior.message ?? 'Failed')
      }
    } catch (e) {
      setStopBehaviorFeedback(String(e))
    } finally {
      setStopBehaviorPending(false)
    }
  }

  if (loading) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4">Server Status</h2>
        <div className="animate-pulse">
          <div className="h-4 bg-gray-700 rounded w-3/4 mb-2"></div>
          <div className="h-4 bg-gray-700 rounded w-1/2"></div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-900/50 border border-red-500 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4 text-red-400">Server Status</h2>
        <p className="text-red-300">Error: {error.message}</p>
        <p className="text-gray-400 text-sm mt-2">
          Make sure the policy-engine server is running on port 8080
        </p>
      </div>
    )
  }

  const status = data?.status

  // Derive firewall coverage from all attached interfaces (XDP ingress + TC egress)
  const ifaces = data?.interfaces || []
  const hasIngress = ifaces.some((i) => i.direction.toUpperCase() === 'INGRESS')
  const hasEgress = ifaces.some((i) => i.direction.toUpperCase() === 'EGRESS')
  let firewallLabel: string
  let firewallColor: string
  if (hasIngress && hasEgress) {
    firewallLabel = 'Ingress + Egress'
    firewallColor = 'bg-green-500/20 text-green-400'
  } else if (hasIngress) {
    firewallLabel = 'Ingress only'
    firewallColor = 'bg-blue-500/20 text-blue-400'
  } else if (hasEgress) {
    firewallLabel = 'Egress only'
    firewallColor = 'bg-purple-500/20 text-purple-400'
  } else {
    firewallLabel = 'Disabled'
    firewallColor = 'bg-gray-500/20 text-gray-400'
  }

  // Derive IDS/IPS status. inspectMode === null means suricata not compiled in.
  const inspectSupported = status?.inspectMode !== undefined && status?.inspectMode !== null
  const inspectMode = status?.inspectMode
  let threatLabel: string
  let threatColor: string
  if (inspectMode === 'IPS') {
    threatLabel = 'IPS (active blocking)'
    threatColor = 'bg-red-500/20 text-red-400'
  } else if (inspectMode === 'IDS') {
    threatLabel = 'IDS (alerts only)'
    threatColor = 'bg-yellow-500/20 text-yellow-400'
  } else {
    threatLabel = 'IDS / IPS'
    threatColor = 'bg-gray-500/20 text-gray-400'
  }

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
      <h2 className="text-xl font-semibold mb-4">Server Status</h2>
      <div className="space-y-3">
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Status</span>
          <span
            className={`px-2 py-1 rounded text-sm ${
              status?.running
                ? 'bg-green-500/20 text-green-400'
                : 'bg-red-500/20 text-red-400'
            }`}
          >
            {status?.running ? 'Running' : 'Stopped'}
          </span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Version</span>
          <span className="font-mono">{status?.version}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Uptime</span>
          <span className="font-mono">{formatUptime(status?.uptimeSecs || 0)}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Firewall</span>
          <span className={`px-2 py-1 rounded text-sm ${firewallColor}`}>
            {firewallLabel}
          </span>
        </div>
        {inspectSupported && (
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Threat Detection</span>
            <span className={`px-2 py-1 rounded text-sm ${threatColor}`}>
              {threatLabel}
            </span>
          </div>
        )}
        <div className="flex justify-between items-center">
          <span className="text-gray-400">CPU Affinity</span>
          {status?.cpuAffinity ? (
            <AffinityBadge affinity={status.cpuAffinity} />
          ) : (
            <span className="text-gray-500 text-sm">—</span>
          )}
        </div>
        <div className="flex justify-between items-center">
          <span className="text-gray-400">Stop Behavior</span>
          <button
            onClick={handleStopBehaviorToggle}
            disabled={stopBehaviorPending}
            className={`px-2 py-1 rounded text-sm transition-colors ${
              (data?.stopBehavior?.behavior ?? 'clear-state') === 'preserve-state'
                ? 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30'
                : 'bg-blue-500/20 text-blue-400 hover:bg-blue-500/30'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
            title="Click to toggle stop behavior"
          >
            {stopBehaviorPending
              ? '…'
              : (data?.stopBehavior?.behavior ?? 'clear-state')}
          </button>
        </div>
        {stopBehaviorFeedback && (
          <p className="text-red-400 text-sm">{stopBehaviorFeedback}</p>
        )}
      </div>
    </div>
  )
}
