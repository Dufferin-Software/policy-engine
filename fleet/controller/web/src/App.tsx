// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useState, useEffect } from 'react'
import FleetDashboard from './components/FleetDashboard.tsx'
import EnrollmentQueue from './components/EnrollmentQueue.tsx'
import AuditLog from './components/AuditLog.tsx'
import EventsView from './components/EventsView.tsx'
import SuricataRulesets from './components/SuricataRulesets.tsx'
import AlertsView from './components/AlertsView.tsx'
import PolicyAlertsView from './components/PolicyAlertsView.tsx'
import ThemeToggle from './components/ThemeToggle.tsx'
import { getUsername, logout } from './lib/auth'

type Tab = 'fleet' | 'enrollment' | 'events' | 'policy-alerts' | 'suricata-rules' | 'ids-alerts' | 'audit'
type NodeTab = 'overview' | 'policy' | 'verdict-cache' | 'events' | 'rule-lifecycle'

const TABS: { id: Tab; label: string }[] = [
  { id: 'fleet', label: 'Fleet' },
  { id: 'enrollment', label: 'Enrollment' },
  { id: 'events', label: 'Events' },
  { id: 'policy-alerts', label: 'Policy Alerts' },
  { id: 'suricata-rules', label: 'Suricata Rules' },
  { id: 'ids-alerts', label: 'IDS Alerts' },
  { id: 'audit', label: 'Audit Log' },
]

function UtcClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  const hh = String(now.getUTCHours()).padStart(2, '0')
  const mm = String(now.getUTCMinutes()).padStart(2, '0')
  const ss = String(now.getUTCSeconds()).padStart(2, '0')
  return (
    <span className="ml-auto text-xs font-mono text-gray-400 tabular-nums">
      {hh}:{mm}:{ss} <span className="text-gray-600">UTC</span>
    </span>
  )
}

function pushTabToUrl(t: Tab): void {
  const p = new URLSearchParams(window.location.search)
  p.set('tab', t)
  history.replaceState(null, '', `?${p.toString()}`)
}

export default function App() {
  const [tab, setTab] = useState<Tab>(() => {
    const t = new URLSearchParams(window.location.search).get('tab')
    return (t && TABS.some((x) => x.id === t) ? t : 'fleet') as Tab
  })
  const [selectedNode, setSelectedNode] = useState<
    { nodeId: string; initialTab?: NodeTab } | null
  >(null)

  function changeTab(t: Tab) {
    pushTabToUrl(t)
    setTab(t)
  }

  function navigateToNode(target: { nodeId: string; initialTab?: NodeTab }) {
    setSelectedNode(target)
    changeTab('fleet')
  }

  function goHome() {
    setSelectedNode(null)
    changeTab('fleet')
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-700 px-6 py-3 flex items-center gap-6">
        <button
          onClick={goHome}
          className="text-lg font-bold text-blue-400 tracking-wide hover:text-blue-300 transition-colors"
          title="Return to the fleet dashboard"
        >
          Policy Controller
        </button>
        <nav className="flex gap-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => changeTab(t.id)}
              className={`px-4 py-1.5 rounded text-sm transition-colors ${
                tab === t.id
                  ? 'bg-blue-700 text-white'
                  : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
        <UtcClock />
        <span className="text-xs font-mono text-gray-400">
          {getUsername() ?? '—'}
        </span>
        <button
          onClick={() => {
            void logout()
          }}
          className="text-xs text-gray-400 hover:text-gray-100 px-2 py-1 rounded hover:bg-gray-800 transition-colors"
          title="Revoke this session and return to the login screen."
        >
          Sign out
        </button>
        <ThemeToggle />
      </header>

      {/* Page content */}
      <main className="flex-1 p-6">
        {tab === 'fleet' && (
          <FleetDashboard
            selectedNode={selectedNode}
            onSelectNode={setSelectedNode}
          />
        )}
        {tab === 'enrollment' && <EnrollmentQueue />}
        {tab === 'events' && <EventsView onNavigateToNode={navigateToNode} />}
        {tab === 'policy-alerts' && <PolicyAlertsView />}
        {tab === 'suricata-rules' && <SuricataRulesets />}
        {tab === 'ids-alerts' && <AlertsView />}
        {tab === 'audit' && <AuditLog />}
      </main>
    </div>
  )
}
