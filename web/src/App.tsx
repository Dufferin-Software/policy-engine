// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useState } from 'react'
import { gql, useQuery } from '@apollo/client'
import { StatusCard, InterfaceList, RulesList, StatsPanel, EventStream, InspectPanel, PerformancePanel, FibPanel, UrpfPanel, FlowExportPanel, RuleLifecycleStream, AuditLogPanel, VerdictCachePanel } from './components'

const GET_INSPECT_SUPPORTED = gql`
  query GetInspectSupported {
    serverFeatures {
      suricata
      ipfix
    }
  }
`

type Tab = 'overview' | 'rules' | 'inspect' | 'performance' | 'audit'

const TAB_LABELS: Record<Tab, string> = {
  overview: 'Overview',
  rules: 'Rules',
  inspect: 'Inspect',
  performance: 'Performance',
  audit: 'Audit',
}

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const { data: statusData } = useQuery<{
    serverFeatures: { suricata: boolean; ipfix: boolean }
  }>(GET_INSPECT_SUPPORTED, { pollInterval: 10000 })

  const inspectSupported = statusData?.serverFeatures?.suricata ?? false
  const ipfixSupported = statusData?.serverFeatures?.ipfix ?? false
  const tabs: Tab[] = inspectSupported
    ? ['overview', 'rules', 'inspect', 'performance', 'audit']
    : ['overview', 'rules', 'performance', 'audit']

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <svg
                className="w-8 h-8 text-blue-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
              <h1 className="text-2xl font-bold">Policy Engine</h1>
            </div>
            <div className="flex items-center space-x-4">
              <a
                href="/playground"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-white transition text-sm"
              >
                GraphQL Playground →
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Tab navigation */}
      <div className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4">
          <nav className="flex">
            {tabs.map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-5 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab
                    ? 'text-blue-400 border-blue-400'
                    : 'text-gray-400 border-transparent hover:text-white hover:border-gray-500'
                }`}
              >
                {TAB_LABELS[tab]}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Main content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-8">
        {/* Overview — always mounted so EventStream WebSocket persists across tab switches */}
        <div className={activeTab === 'overview' ? 'space-y-6' : 'hidden'}>
          <StatusCard />
          <StatsPanel />
          <VerdictCachePanel />
          <FibPanel />
          <UrpfPanel />
          {ipfixSupported && <FlowExportPanel />}
          <InterfaceList />
          <EventStream />
          <RuleLifecycleStream />
        </div>
        {activeTab === 'rules' && <RulesList />}
        {activeTab === 'inspect' && inspectSupported && <InspectPanel />}
        {activeTab === 'performance' && <PerformancePanel />}
        {activeTab === 'audit' && <AuditLogPanel />}
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <p className="text-center text-gray-500 text-sm">
            Policy Engine • Built with React + GraphQL
          </p>
        </div>
      </footer>
    </div>
  )
}

export default App
