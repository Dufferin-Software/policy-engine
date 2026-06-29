// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useState, useRef, useEffect } from 'react'
import { gql, useQuery, useMutation } from '@apollo/client'

function Tooltip({ children, content }: { children: React.ReactNode; content: string }) {
  const [visible, setVisible] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const show = () => {
    timerRef.current = setTimeout(() => setVisible(true), 120)
  }
  const hide = () => {
    if (timerRef.current) clearTimeout(timerRef.current)
    setVisible(false)
  }

  return (
    <div className="relative inline-block" onMouseEnter={show} onMouseLeave={hide}>
      {children}
      {visible && (
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 bg-gray-900 border border-gray-600 rounded-lg p-3 text-xs text-gray-300 z-50 shadow-xl pointer-events-none">
          {content}
          <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-gray-600" />
        </div>
      )}
    </div>
  )
}

/** Extract the numeric SID from a Suricata rule string, or null if absent. */
function extractSid(rule: string): number | null {
  const m = rule.match(/\bsid:\s*(\d+)\s*;/)
  return m ? parseInt(m[1], 10) : null
}

const GET_INSPECT_STATUS = gql`
  query GetInspectStatus {
    inspectStatus {
      mode
      suricataRunning
      mirrorInterface
      mirrorIfindex
      peerInterface
      suricataVersion
      rulesetVersion
      customRuleFiles {
        filename
        ruleCount
        rules
      }
    }
  }
`

const CONFIGURE_INSPECT = gql`
  mutation ConfigureInspect($mode: GqlInspectMode!) {
    configureInspect(input: { mode: $mode }) {
      success
      message
    }
  }
`

const DISABLE_INSPECT = gql`
  mutation DisableInspect {
    disableInspect {
      success
      message
    }
  }
`

const DEPLOY_SURICATA_RULES = gql`
  mutation DeploySuricataRules($rules: String!, $filename: String!) {
    deploySuricataRules(input: { rules: $rules, filename: $filename }) {
      success
      message
    }
  }
`

const RELOAD_SURICATA_RULES = gql`
  mutation ReloadSuricataRules {
    reloadSuricataRules {
      success
      message
    }
  }
`

const ADD_CUSTOM_RULE = gql`
  mutation AddCustomRule($filename: String!, $rule: String!) {
    addCustomRule(filename: $filename, rule: $rule) {
      success
      message
    }
  }
`

const DELETE_CUSTOM_RULES = gql`
  mutation DeleteCustomRules($filename: String!, $sids: [Int!]!) {
    deleteCustomRules(input: { filename: $filename, sids: $sids }) {
      success
      message
    }
  }
`

const DELETE_RULE_FILE = gql`
  mutation DeleteRuleFile($filename: String!) {
    deleteRuleFile(filename: $filename) {
      success
      message
    }
  }
`

const DELETE_ALL_CUSTOM_RULES = gql`
  mutation DeleteAllCustomRules {
    deleteAllCustomRules {
      success
      message
    }
  }
`

const GET_INSPECT_RULES = gql`
  query GetInspectRules {
    ingressRules: rules(direction: INGRESS) {
      actions { action }
    }
    egressRules: rules(direction: EGRESS) {
      actions { action }
    }
  }
`

const GET_INTERFACES_FOR_INSPECT = gql`
  query GetInterfacesForInspect {
    interfaces {
      interface
      mode
      direction
    }
    availableInterfaces
  }
`

const ATTACH_INGRESS_FOR_INSPECT = gql`
  mutation AttachIngressForInspect($input: AttachIngressInput!) {
    attachIngress(input: $input) {
      success
      message
    }
  }
`

const ATTACH_TC_FOR_INSPECT = gql`
  mutation AttachTcForInspect($input: AttachTcInput!) {
    attachTc(input: $input) {
      success
      message
    }
  }
`

interface CustomRuleFile {
  filename: string
  ruleCount: number
  rules: string[]
}

interface InspectStatus {
  mode: string
  suricataRunning: boolean
  mirrorInterface: string | null
  mirrorIfindex: number | null
  peerInterface: string | null
  suricataVersion: string | null
  rulesetVersion: string | null
  customRuleFiles: CustomRuleFile[]
}

interface InspectStatusData {
  inspectStatus: InspectStatus
}

interface OperationResult {
  success: boolean
  message: string
}

interface InterfaceEntry {
  interface: string
  mode: string
  direction: string
}

interface InterfacesForInspectData {
  interfaces: InterfaceEntry[]
  availableInterfaces: string[]
}

export function InspectPanel() {
  const [rulesContent, setRulesContent] = useState('')
  const [filename, setFilename] = useState('custom.rules')
  const [ruleSearch, setRuleSearch] = useState('')
  const [singleRule, setSingleRule] = useState('')
  const [singleRuleFile, setSingleRuleFile] = useState('custom.rules')
  const [selectedInterfaces, setSelectedInterfaces] = useState<Set<string>>(new Set())
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  )

  const { data, loading, refetch } = useQuery<InspectStatusData>(GET_INSPECT_STATUS, {
    pollInterval: 3000,
  })

  const { data: ifaceData, refetch: refetchInterfaces } =
    useQuery<InterfacesForInspectData>(GET_INTERFACES_FOR_INSPECT, { pollInterval: 5000 })

  const { data: rulesData } = useQuery<{
    ingressRules: { actions: { action: string }[] }[]
    egressRules: { actions: { action: string }[] }[]
  }>(GET_INSPECT_RULES, { pollInterval: 10000 })

  const [configureInspect, { loading: configuring }] = useMutation<{
    configureInspect: OperationResult
  }>(CONFIGURE_INSPECT)

  const [disableInspect, { loading: disabling }] = useMutation<{
    disableInspect: OperationResult
  }>(DISABLE_INSPECT)

  const [deploySuricataRules, { loading: deploying }] = useMutation<{
    deploySuricataRules: OperationResult
  }>(DEPLOY_SURICATA_RULES)

  const [reloadSuricataRules, { loading: reloading }] = useMutation<{
    reloadSuricataRules: OperationResult
  }>(RELOAD_SURICATA_RULES)

  const [addCustomRule, { loading: addingRule }] = useMutation<{
    addCustomRule: OperationResult
  }>(ADD_CUSTOM_RULE)

  const [deleteCustomRules] = useMutation<{
    deleteCustomRules: OperationResult
  }>(DELETE_CUSTOM_RULES)

  const [deleteRuleFile] = useMutation<{
    deleteRuleFile: OperationResult
  }>(DELETE_RULE_FILE)

  const [deleteAllCustomRules, { loading: deletingAll }] = useMutation<{
    deleteAllCustomRules: OperationResult
  }>(DELETE_ALL_CUSTOM_RULES)

  const [attachIngressForInspect] = useMutation(ATTACH_INGRESS_FOR_INSPECT)
  const [attachTcForInspect] = useMutation(ATTACH_TC_FOR_INSPECT)

  const availableInterfaces = (ifaceData?.availableInterfaces ?? []).filter((i) => i !== 'lo')
  const attachedInterfaces = ifaceData?.interfaces ?? []

  // Pre-select interfaces that already have programs attached
  const initializedRef = useRef(false)
  useEffect(() => {
    if (!initializedRef.current && attachedInterfaces.length > 0) {
      initializedRef.current = true
      setSelectedInterfaces(new Set(attachedInterfaces.map((i) => i.interface)))
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attachedInterfaces.length])

  const toggleInterface = (iface: string) => {
    setSelectedInterfaces((prev) => {
      const next = new Set(prev)
      if (next.has(iface)) next.delete(iface)
      else next.add(iface)
      return next
    })
  }

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message })
    setTimeout(() => setFeedback(null), 5000)
  }

  const handleResult = (result: OperationResult | undefined, fallback: string) => {
    if (result?.success) {
      showFeedback('success', result.message)
    } else {
      showFeedback('error', result?.message ?? fallback)
    }
  }

  const status = data?.inspectStatus
  const currentMode = status?.mode ?? 'DISABLED'
  const vethReady = !!status?.mirrorInterface

  const hasInspectRules =
    [...(rulesData?.ingressRules ?? []), ...(rulesData?.egressRules ?? [])].some((rule) =>
      rule.actions.some((a) => a.action.toUpperCase() === 'INSPECT')
    )

  const handleSetMode = async (mode: 'IDS' | 'IPS' | 'DISABLED') => {
    try {
      if (mode === 'DISABLED') {
        const { data: r } = await disableInspect()
        handleResult(r?.disableInspect, 'Failed to disable inspect')
      } else {
        if (selectedInterfaces.size === 0) {
          showFeedback('error', 'Select at least one interface to monitor')
          return
        }
        // Auto-attach ingress (XDP) + TC to each selected interface
        for (const iface of selectedInterfaces) {
          const hasIngress = attachedInterfaces.some(
            (i) => i.interface === iface && i.direction.toUpperCase() === 'INGRESS'
          )
          const hasTc = attachedInterfaces.some((i) => i.interface === iface && i.mode === 'tc')
          if (!hasIngress) {
            await attachIngressForInspect({
              variables: { input: { interface: iface, mode: 'auto' } },
            })
          }
          if (!hasTc) {
            await attachTcForInspect({ variables: { input: { interface: iface } } })
          }
        }
        const { data: r } = await configureInspect({ variables: { mode } })
        handleResult(r?.configureInspect, `Failed to enable ${mode}`)
        refetchInterfaces()
      }
      refetch()
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const handleDeployRules = async () => {
    if (!rulesContent.trim() || !filename.trim()) return
    try {
      const { data: r } = await deploySuricataRules({
        variables: { rules: rulesContent, filename: filename.trim() },
      })
      if (r?.deploySuricataRules.success) {
        showFeedback('success', r.deploySuricataRules.message)
        setRulesContent('')
        refetch()
      } else {
        showFeedback('error', r?.deploySuricataRules.message ?? 'Failed to deploy rules')
      }
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const handleReloadRules = async () => {
    try {
      const { data: r } = await reloadSuricataRules()
      handleResult(r?.reloadSuricataRules, 'Failed to reload rules')
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const handleAddSingleRule = async () => {
    if (!singleRule.trim()) return
    try {
      const { data: r } = await addCustomRule({
        variables: { filename: singleRuleFile.trim() || 'custom.rules', rule: singleRule.trim() },
      })
      if (r?.addCustomRule.success) {
        showFeedback('success', r.addCustomRule.message)
        setSingleRule('')
        refetch()
      } else {
        showFeedback('error', r?.addCustomRule.message ?? 'Failed to add rule')
      }
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const handleDeleteBySid = async (fname: string, sid: number) => {
    try {
      const { data: r } = await deleteCustomRules({ variables: { filename: fname, sids: [sid] } })
      handleResult(r?.deleteCustomRules, 'Failed to delete rule')
      refetch()
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const handleDeleteFile = async (fname: string) => {
    if (!confirm(`Delete all rules in ${fname}?`)) return
    try {
      const { data: r } = await deleteRuleFile({ variables: { filename: fname } })
      handleResult(r?.deleteRuleFile, 'Failed to delete file')
      refetch()
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  const handleDeleteAll = async () => {
    if (!confirm('Delete ALL custom rule files? This cannot be undone.')) return
    try {
      const { data: r } = await deleteAllCustomRules()
      handleResult(r?.deleteAllCustomRules, 'Failed to delete rules')
      refetch()
    } catch (e) {
      showFeedback('error', String(e))
    }
  }

  // Filtered custom rule files for the rule viewer
  const searchTerm = ruleSearch.toLowerCase()
  const filteredRuleFiles = (status?.customRuleFiles ?? [])
    .map((f) => ({
      ...f,
      matchedRules: searchTerm
        ? f.rules.filter((r) => r.toLowerCase().includes(searchTerm))
        : f.rules,
    }))
    .filter((f) => f.matchedRules.length > 0)

  if (loading && !data) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
        <h2 className="text-xl font-semibold mb-4">Inspect / IPS</h2>
        <p className="text-sm text-gray-500">Loading...</p>
      </div>
    )
  }

  return (
    <div className="bg-gray-800 rounded-lg p-6 shadow-lg space-y-6">
      <h2 className="text-xl font-semibold">Inspect / IPS</h2>

      {/* Warning: INSPECT rules active but IDS/IPS disabled */}
      {hasInspectRules && currentMode === 'DISABLED' && (
        <div className="flex items-start gap-3 p-3 rounded bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 text-sm">
          <span className="text-yellow-400 text-base leading-5">⚠</span>
          <span>
            You have <strong>Inspect</strong> rules configured, but threat detection is{' '}
            <strong>disabled</strong>. Matched traffic is currently passing through uninspected.
            Enable IDS or IPS above to activate inspection.
          </span>
        </div>
      )}

      {/* Feedback banner */}
      {feedback && (
        <div
          className={`p-3 rounded text-sm ${
            feedback.type === 'success'
              ? 'bg-green-500/20 text-green-400'
              : 'bg-red-500/20 text-red-400'
          }`}
        >
          {feedback.message}
        </div>
      )}

      {/* Section 1: Status */}
      <div className="space-y-4">
        <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wide">Status</h3>

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {/* Mode */}
          <div className="bg-gray-700/50 rounded-lg p-3">
            <div className="text-xs text-gray-400 mb-1">Mode</div>
            <div className="flex items-center gap-2">
              <span
                className={`inline-block w-2 h-2 rounded-full ${
                  currentMode === 'IPS' ? 'bg-red-400' : currentMode === 'IDS' ? 'bg-yellow-400' : 'bg-gray-500'
                }`}
              />
              <span className={`font-semibold ${
                currentMode === 'IPS' ? 'text-red-400' : currentMode === 'IDS' ? 'text-yellow-400' : 'text-gray-400'
              }`}>
                {currentMode}
              </span>
            </div>
          </div>

          {/* Suricata */}
          <div className="bg-gray-700/50 rounded-lg p-3">
            <div className="text-xs text-gray-400 mb-1">Suricata</div>
            <div className="flex items-center gap-2">
              <span
                className={`inline-block w-2 h-2 rounded-full ${status?.suricataRunning ? 'bg-green-400' : 'bg-red-400'}`}
              />
              <span
                className={`font-semibold ${status?.suricataRunning ? 'text-green-400' : 'text-red-400'}`}
              >
                {status?.suricataRunning ? 'Running' : 'Stopped'}
              </span>
            </div>
          </div>

          {/* Veth pair */}
          <div className="bg-gray-700/50 rounded-lg p-3">
            <div className="text-xs text-gray-400 mb-1">Veth Pair</div>
            {vethReady ? (
              <div className="text-xs font-mono text-blue-300 leading-5">
                <div>{status?.mirrorInterface} <span className="text-gray-500">(mirror)</span></div>
                <div>{status?.peerInterface} <span className="text-gray-500">(engine)</span></div>
              </div>
            ) : (
              <span className="text-sm text-gray-500">Not created</span>
            )}
          </div>

        </div>

        {/* Engine + ruleset versions — always shown */}
        <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs">
          <span>
            <span className="text-gray-500">Engine: </span>
            <span className="font-mono text-gray-300">{status?.suricataVersion ?? '—'}</span>
          </span>
          <span>
            <span className="text-gray-500">Ruleset: </span>
            <span className="font-mono text-gray-300">{status?.rulesetVersion ?? '—'}</span>
          </span>
        </div>

        {/* Monitored interfaces — multi-select checklist */}
        <div>
          <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">
            Monitored Interfaces
            <span className="ml-2 normal-case text-gray-600 font-normal">
              (IDS/IPS mode applies globally to all checked interfaces)
            </span>
          </p>
          {availableInterfaces.length === 0 ? (
            <p className="text-sm text-gray-500">No interfaces available.</p>
          ) : (
            <div className="space-y-1">
              {availableInterfaces.map((iface) => {
                const hasIngress = attachedInterfaces.some(
                  (i) => i.interface === iface && i.direction.toUpperCase() === 'INGRESS'
                )
                const hasTc = attachedInterfaces.some(
                  (i) => i.interface === iface && i.mode === 'tc'
                )
                const checked = selectedInterfaces.has(iface)
                return (
                  <label
                    key={iface}
                    className="flex items-center gap-3 px-3 py-2 rounded bg-gray-700/50 hover:bg-gray-700 cursor-pointer select-none"
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleInterface(iface)}
                      className="accent-blue-500"
                    />
                    <span className="font-mono text-sm">{iface}</span>
                    <span className="ml-auto text-xs font-mono space-x-2">
                      <span className={hasIngress ? 'text-blue-400' : 'text-gray-600'}>
                        ● ingress
                      </span>
                      <span className={hasTc ? 'text-purple-400' : 'text-gray-600'}>
                        ● egress
                      </span>
                    </span>
                  </label>
                )
              })}
            </div>
          )}
        </div>

        {/* Mode controls */}
        <div className="flex flex-wrap gap-2">
          <Tooltip content="Intrusion Detection System: traffic is mirrored to the inspection engine which analyses it for threats and generates alerts. No packets are blocked — your application traffic flows normally.">
            <button
              onClick={() => handleSetMode('IDS')}
              disabled={configuring || disabling || currentMode === 'IDS'}
              className={`px-4 py-2 rounded text-sm font-medium transition disabled:cursor-not-allowed ${
                currentMode === 'IDS'
                  ? 'bg-yellow-700 text-white opacity-70'
                  : 'bg-yellow-600 hover:bg-yellow-700 text-white disabled:bg-gray-600'
              }`}
            >
              {configuring || disabling ? '…' : 'Enable IDS'}
            </button>
          </Tooltip>
          <Tooltip content="Intrusion Prevention System: traffic is mirrored to the inspection engine. When a threat is detected, that flow is actively blocked — subsequent packets from the offending connection are dropped at the firewall.">
            <button
              onClick={() => handleSetMode('IPS')}
              disabled={configuring || disabling || currentMode === 'IPS'}
              className={`px-4 py-2 rounded text-sm font-medium transition disabled:cursor-not-allowed ${
                currentMode === 'IPS'
                  ? 'bg-red-700 text-white opacity-70'
                  : 'bg-red-600 hover:bg-red-700 text-white disabled:bg-gray-600'
              }`}
            >
              {configuring || disabling ? '…' : 'Enable IPS'}
            </button>
          </Tooltip>
          <Tooltip content="Disable threat detection: traffic mirroring is stopped, the inspection engine is shut down, and all cached flow verdicts are cleared. Your firewall rules continue to apply.">
            <button
              onClick={() => handleSetMode('DISABLED')}
              disabled={configuring || disabling || currentMode === 'DISABLED'}
              className={`px-4 py-2 rounded text-sm font-medium transition disabled:cursor-not-allowed ${
                currentMode === 'DISABLED'
                  ? 'bg-gray-600 text-white opacity-70'
                  : 'bg-gray-500 hover:bg-gray-600 text-white disabled:bg-gray-600'
              }`}
            >
              {configuring || disabling ? '…' : 'Disable'}
            </button>
          </Tooltip>
          <span className="self-center text-xs text-gray-500">
            {currentMode === 'IDS' ? 'Alerts only — no blocking' : currentMode === 'IPS' ? 'Active blocking' : ''}
          </span>
        </div>
      </div>

      {/* Section 2: Detection Rules */}

      <div className="border-t border-gray-700 pt-4 space-y-4">
        <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
          Detection Rules
        </h3>

        {/* Installed rule file viewer */}
        {(status?.customRuleFiles ?? []).length > 0 ? (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2 items-center">
              <input
                type="text"
                value={ruleSearch}
                onChange={(e) => setRuleSearch(e.target.value)}
                placeholder="Search rules…"
                className="flex-1 sm:flex-none sm:w-72 bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-white text-sm font-mono focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={handleDeleteAll}
                disabled={deletingAll}
                className="px-3 py-1.5 text-xs bg-red-600/20 text-red-400 border border-red-600/30 rounded hover:bg-red-600/30 transition"
              >
                {deletingAll ? 'Deleting…' : 'Delete All'}
              </button>
            </div>

            {filteredRuleFiles.length === 0 ? (
              <p className="text-xs text-gray-500">No rules match "{ruleSearch}".</p>
            ) : (
              <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
                {filteredRuleFiles.map((f) => (
                  <div key={f.filename}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-blue-300">{f.filename}</span>
                      <span className="text-xs text-gray-500">
                        {f.matchedRules.length}
                        {searchTerm && f.matchedRules.length !== f.ruleCount
                          ? `/${f.ruleCount}`
                          : ''}{' '}
                        rule{f.ruleCount !== 1 ? 's' : ''}
                      </span>
                      <button
                        onClick={() => handleDeleteFile(f.filename)}
                        title={`Delete ${f.filename}`}
                        className="ml-auto px-2 py-0.5 text-xs bg-red-600/20 text-red-400 rounded hover:bg-red-600/30 transition"
                      >
                        Delete file
                      </button>
                    </div>
                    <div className="bg-gray-900 rounded p-2 space-y-1">
                      {f.matchedRules.map((rule, i) => {
                        const sid = extractSid(rule)
                        return (
                          <div
                            key={i}
                            className="flex items-start gap-2 group"
                          >
                            {sid !== null && (
                              <span className="mt-0.5 shrink-0 px-1 py-0 text-[10px] bg-gray-700 text-gray-400 rounded font-mono">
                                sid:{sid}
                              </span>
                            )}
                            <span className="text-xs font-mono text-gray-300 whitespace-pre-wrap break-all leading-5 flex-1">
                              {rule}
                            </span>
                            {sid !== null && (
                              <button
                                onClick={() => handleDeleteBySid(f.filename, sid)}
                                title="Delete this rule"
                                className="shrink-0 opacity-0 group-hover:opacity-100 px-1.5 py-0.5 text-xs text-red-400 hover:bg-red-500/20 rounded transition"
                              >
                                ✕
                              </button>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <p className="text-xs text-gray-500">No custom rule files deployed yet.</p>
        )}

        {/* Add a single rule */}
        <div className="space-y-2 pt-1">
          <p className="text-xs text-gray-400 font-medium">Add single rule</p>
          <div className="flex gap-2">
            <input
              type="text"
              value={singleRuleFile}
              onChange={(e) => setSingleRuleFile(e.target.value)}
              placeholder="custom.rules"
              className="w-32 bg-gray-700 border border-gray-600 rounded px-2 py-1.5 text-white text-xs font-mono focus:outline-none focus:border-blue-500"
            />
            <input
              type="text"
              value={singleRule}
              onChange={(e) => setSingleRule(e.target.value)}
              placeholder='alert tcp any any -> any 80 (msg:"Test"; sid:9000001; rev:1;)'
              className="flex-1 bg-gray-700 border border-gray-600 rounded px-2 py-1.5 text-white text-xs font-mono focus:outline-none focus:border-blue-500"
              onKeyDown={(e) => e.key === 'Enter' && handleAddSingleRule()}
            />
            <button
              onClick={handleAddSingleRule}
              disabled={addingRule || !singleRule.trim()}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded text-xs font-medium transition"
            >
              {addingRule ? '…' : 'Add'}
            </button>
          </div>
        </div>

        {/* Deploy new rules (bulk) */}
        <div className="space-y-3 pt-1 border-t border-gray-700/50">
          <p className="text-xs text-gray-400 font-medium">Deploy rules file</p>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Filename</label>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              placeholder="custom.rules"
              className="w-full sm:w-64 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm font-mono focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Rules</label>
            <textarea
              value={rulesContent}
              onChange={(e) => setRulesContent(e.target.value)}
              placeholder={
                '# Paste Suricata rules here\nalert http any any -> any any (msg:"Example rule"; sid:1000001; rev:1;)'
              }
              rows={5}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm font-mono focus:outline-none focus:border-blue-500 resize-y"
            />
          </div>
          <div className="flex gap-3">
            <button
              onClick={handleDeployRules}
              disabled={deploying || !rulesContent.trim() || !filename.trim()}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded text-sm font-medium transition"
            >
              {deploying ? 'Deploying...' : 'Deploy Rules'}
            </button>
            <button
              onClick={handleReloadRules}
              disabled={reloading || !status?.suricataRunning}
              title={!status?.suricataRunning ? 'Suricata is not running' : undefined}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded text-sm font-medium transition"
            >
              {reloading ? 'Reloading...' : 'Reload Rules'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
