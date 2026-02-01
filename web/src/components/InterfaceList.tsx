// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { gql, useQuery, useMutation } from '@apollo/client'
import { useState } from 'react'

const GET_INTERFACES = gql`
  query GetInterfaces {
    interfaces {
      interface
      ifindex
      mode
      direction
    }
  }
`


const GET_AVAILABLE_INTERFACES = gql`
  query GetAvailableInterfaces {
    availableInterfaces
  }
`

const ATTACH_INGRESS = gql`
  mutation AttachIngress($input: AttachIngressInput!) {
    attachIngress(input: $input) {
      success
      message
    }
  }
`

const ATTACH_EGRESS = gql`
  mutation AttachEgress($input: AttachTcInput!) {
    attachTc(input: $input) {
      success
      message
    }
  }
`

const DETACH_INGRESS = gql`
  mutation DetachIngress($input: DetachIngressInput!) {
    detachIngress(input: $input) {
      success
      message
    }
  }
`

const DETACH_EGRESS = gql`
  mutation DetachEgress($input: DetachTcInput!) {
    detachTc(input: $input) {
      success
      message
    }
  }
`

const DETACH_ALL = gql`
  mutation DetachAll {
    detachAll {
      success
      message
    }
  }
`

interface InterfaceAttachment {
  interface: string
  ifindex: number
  mode: string
  direction: string
}

interface InterfacesData {
  interfaces: InterfaceAttachment[]
}

interface AvailableInterfacesData {
  availableInterfaces: string[]
}

interface OperationResult {
  success: boolean
  message: string
}

export function InterfaceList() {
  const { loading, error, data, refetch } = useQuery<InterfacesData>(GET_INTERFACES, {
    pollInterval: 5000,
  })
  const { data: availableData } = useQuery<AvailableInterfacesData>(GET_AVAILABLE_INTERFACES, {
    pollInterval: 10000,
  })
  const [attachIngress] = useMutation<{ attachIngress: OperationResult }>(ATTACH_INGRESS)
  const [attachEgress] = useMutation<{ attachTc: OperationResult }>(ATTACH_EGRESS)
  const [detachIngress] = useMutation<{ detachIngress: OperationResult }>(DETACH_INGRESS)
  const [detachEgress] = useMutation<{ detachTc: OperationResult }>(DETACH_EGRESS)
  const [detachAll] = useMutation<{ detachAll: OperationResult }>(DETACH_ALL)

  const [newInterface, setNewInterface] = useState('')
  const [attachMode, setAttachMode] = useState('auto')
  const [attachDirection, setAttachDirection] = useState<'INGRESS' | 'EGRESS'>('INGRESS')
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Filter out loopback, sort alphabetically
  const availableInterfaces = (availableData?.availableInterfaces || []).filter((i) => i !== 'lo')

  const handleAttach = async () => {
    if (!newInterface.trim()) return

    try {
      let result
      if (attachDirection === 'INGRESS') {
        result = await attachIngress({
          variables: {
            input: {
              interface: newInterface.trim(),
              mode: attachMode,
            },
          },
        })
        if (result.data?.attachIngress.success) {
          setFeedback({ type: 'success', message: result.data.attachIngress.message })
          setNewInterface('')
          refetch()
        } else {
          setFeedback({ type: 'error', message: result.data?.attachIngress.message || 'Failed to attach' })
        }
      } else {
        result = await attachEgress({
          variables: {
            input: {
              interface: newInterface.trim(),
            },
          },
        })
        if (result.data?.attachTc.success) {
          setFeedback({ type: 'success', message: result.data.attachTc.message })
          setNewInterface('')
          refetch()
        } else {
          setFeedback({ type: 'error', message: result.data?.attachTc.message || 'Failed to attach' })
        }
      }
    } catch (e) {
      setFeedback({ type: 'error', message: String(e) })
    }

    setTimeout(() => setFeedback(null), 5000)
  }

  const handleDetach = async (iface: string, direction: string) => {
    try {
      let result
      if (direction.toUpperCase() === 'EGRESS') {
        result = await detachEgress({
          variables: { input: { interface: iface } },
        })
        if (result.data?.detachTc.success) {
          setFeedback({ type: 'success', message: result.data.detachTc.message })
          refetch()
        }
      } else {
        result = await detachIngress({
          variables: { input: { interface: iface } },
        })
        if (result.data?.detachIngress.success) {
          setFeedback({ type: 'success', message: result.data.detachIngress.message })
          refetch()
        }
      }
    } catch (e) {
      setFeedback({ type: 'error', message: String(e) })
    }

    setTimeout(() => setFeedback(null), 5000)
  }

  const handleDetachAll = async () => {
    try {
      const result = await detachAll()
      if (result.data?.detachAll.success) {
        setFeedback({ type: 'success', message: result.data.detachAll.message })
        refetch()
      }
    } catch (e) {
      setFeedback({ type: 'error', message: String(e) })
    }

    setTimeout(() => setFeedback(null), 5000)
  }

  if (loading && !data) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4">Enabled Interfaces</h2>
        <div className="animate-pulse space-y-2">
          <div className="h-10 bg-gray-700 rounded"></div>
          <div className="h-10 bg-gray-700 rounded"></div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-900/50 border border-red-500 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4 text-red-400">Enabled Interfaces</h2>
        <p className="text-red-300">Error: {error.message}</p>
      </div>
    )
  }

  const interfaces = data?.interfaces || []

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold">Enabled Interfaces</h2>
        {interfaces.length > 0 && (
          <button
            onClick={handleDetachAll}
            className="px-3 py-1 text-sm bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition"
          >
            Disable All
          </button>
        )}
      </div>

      {feedback && (
        <div
          className={`mb-4 p-3 rounded ${
            feedback.type === 'success'
              ? 'bg-green-500/20 text-green-400'
              : 'bg-red-500/20 text-red-400'
          }`}
        >
          {feedback.message}
        </div>
      )}

      {/* Enable new interface */}
      <div className="mb-4 p-4 bg-gray-700/50 rounded-lg">
        <h3 className="text-sm font-medium text-gray-400 mb-3">Enable Interface</h3>
        <div className="flex gap-2">
          <select
            value={newInterface}
            onChange={(e) => setNewInterface(e.target.value)}
            className="flex-1 px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="">Select interface...</option>
            {availableInterfaces.map((iface) => (
              <option key={iface} value={iface}>
                {iface}
              </option>
            ))}
          </select>
          <select
            value={attachDirection}
            onChange={(e) => setAttachDirection(e.target.value as 'INGRESS' | 'EGRESS')}
            className="px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
          >
            <option value="INGRESS">Ingress</option>
            <option value="EGRESS">Egress</option>
          </select>
          {attachDirection === 'INGRESS' && (
            <select
              value={attachMode}
              onChange={(e) => setAttachMode(e.target.value)}
              className="px-3 py-2 bg-gray-700 rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            >
              <option value="auto">Auto</option>
              <option value="native">Native</option>
              <option value="generic">Generic</option>
              <option value="offload">Offload</option>
            </select>
          )}
          <button
            onClick={handleAttach}
            disabled={!newInterface.trim()}
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            Enable
          </button>
        </div>
      </div>

      {/* Interface list */}
      {interfaces.length === 0 ? (
        <p className="text-gray-400 text-center py-8">No interfaces enabled</p>
      ) : (
        <div className="space-y-2">
          {interfaces.map((iface) => (
            <div
              key={`${iface.interface}-${iface.direction}`}
              className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg"
            >
              <div>
                <span className="font-mono text-lg">{iface.interface}</span>
                <span className="ml-3 text-gray-400 text-sm">
                  (index: {iface.ifindex}, mode: {iface.mode})
                </span>
                <span
                  className={`ml-2 px-2 py-0.5 rounded text-xs ${
                    iface.direction.toUpperCase() === 'EGRESS'
                      ? 'bg-purple-500/20 text-purple-400'
                      : 'bg-blue-500/20 text-blue-400'
                  }`}
                >
                  {iface.direction.toUpperCase()}
                </span>
              </div>
              <button
                onClick={() => handleDetach(iface.interface, iface.direction)}
                className="px-3 py-1 text-sm bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition"
              >
                Disable
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
