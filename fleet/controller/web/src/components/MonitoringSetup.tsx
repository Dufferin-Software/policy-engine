// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useMemo, useState } from 'react'

interface Props {
  onClose: () => void
}

// The controller aggregates /metrics from every connected node (injecting
// node_id + hostname labels) and also exposes its own fleet_* metrics, so a
// single scrape job pointed at the controller covers the whole fleet. The web
// UI is served from the same host:port as /metrics, so window.location is the
// correct default scrape target and scheme.
function buildPrometheusYaml(target: string, https: boolean): string {
  const schemeLine = https ? '\n    scheme: https' : ''
  return `# Prometheus scrape config for the policy controller fleet.
#
# The controller aggregates /metrics from every connected node (with node_id
# and hostname labels) and exposes its own fleet_* metrics, so this single job
# covers the entire fleet — no changes are needed when nodes join or leave.
#
# Add this under scrape_configs: in /etc/prometheus/prometheus.yml, then run:
#   sudo systemctl reload prometheus
scrape_configs:
  - job_name: policy_controller
    metrics_path: /metrics${schemeLine}
    static_configs:
      - targets:
          - '${target || '<controller-host>:8443'}'`
}

export default function MonitoringSetup({ onClose }: Props) {
  // Default to the address the operator used to reach this UI — that is the
  // same host:port that serves /metrics. Editable in case Prometheus reaches
  // the controller by a different name (e.g. an internal DNS record).
  const [target, setTarget] = useState(() => window.location.host)
  const [https, setHttps] = useState(() => window.location.protocol === 'https:')
  const [copied, setCopied] = useState(false)

  const yaml = useMemo(() => buildPrometheusYaml(target.trim(), https), [target, https])

  async function copy() {
    try {
      await navigator.clipboard.writeText(yaml)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 rounded-lg border border-gray-600 p-5 w-full max-w-2xl max-h-[90vh] overflow-y-auto space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-gray-50">Prometheus Setup</h3>
          <button onClick={onClose} className="text-sm text-gray-500 hover:text-gray-300">
            Close
          </button>
        </div>

        <p className="text-xs text-gray-400">
          Paste the snippet below into your Prometheus configuration to scrape detailed
          metrics for every node in the fleet. The controller aggregates each node's
          metrics and adds its own fleet status, certificate-expiry, and rule-count series.
        </p>

        {/* Scrape target */}
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs text-gray-400 mb-1">
              Controller address (as Prometheus reaches it)
            </label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="controller.example.com:8443"
              className="w-full bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500"
            />
          </div>
          <label className="flex items-center gap-1.5 text-xs text-gray-400 pb-1.5">
            <input
              type="checkbox"
              checked={https}
              onChange={(e) => setHttps(e.target.checked)}
              className="rounded border-gray-600"
            />
            HTTPS
          </label>
        </div>

        {/* Generated YAML */}
        <div className="relative">
          <button
            onClick={copy}
            className="absolute top-2 right-2 text-xs bg-blue-800 hover:bg-blue-700 text-blue-100 px-3 py-1 rounded"
          >
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <pre className="bg-gray-950 border border-gray-700 rounded p-3 pt-3 text-xs text-gray-200 font-mono overflow-x-auto whitespace-pre">
            {yaml}
          </pre>
        </div>

        <p className="text-[11px] text-gray-500">
          After reloading Prometheus, open <span className="font-mono">/targets</span> on
          your Prometheus server and confirm the <span className="font-mono">policy_controller</span>{' '}
          job shows <span className="text-green-400">UP</span>. See{' '}
          <span className="font-mono">docs/prometheus-metrics.md</span> for the full metric
          reference and example queries.
        </p>

        <div className="flex justify-end pt-2 border-t border-gray-700">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded text-sm bg-gray-700 hover:bg-gray-600 text-gray-300"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  )
}
