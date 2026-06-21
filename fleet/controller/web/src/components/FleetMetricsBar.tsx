// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { useEffect, useState } from 'react'
import { useQuery, gql } from '@apollo/client'
import { fmtCount } from './types.ts'

const GET_FLEET_METRICS = gql`
  query GetFleetMetrics {
    fleetMetrics {
      nodesReporting
      nodesTotal
      rxPackets
      rxBytes
      txPackets
      txBytes
      policyMatches
      policyPass
      policyDrops
    }
  }
`

interface FleetMetrics {
  nodesReporting: number
  nodesTotal: number
  rxPackets: number
  rxBytes: number
  txPackets: number
  txBytes: number
  policyMatches: number
  policyPass: number
  policyDrops: number
}

type MetricField = Exclude<keyof FleetMetrics, 'nodesReporting' | 'nodesTotal'>

// Poll cadence. Node agents scrape every ~30s by default, so we smooth rates
// over a trailing window rather than trusting any single poll-to-poll delta.
const POLL_MS = 5_000
const RATE_WINDOW_MS = 30_000
const MAX_SAMPLES = 90 // ~7.5 min of history at POLL_MS
const SPARK_POINTS = 40

interface Sample {
  t: number
  m: FleetMetrics
}

interface CardSpec {
  field: MetricField
  label: string
  /**
   * Counters here are byte totals: show the rate as bits/sec bandwidth and the
   * cumulative total as a data volume, rather than a plain packet/event count.
   */
  bandwidth?: boolean
  /** Tailwind text colour for the value + stroke colour for the sparkline. */
  color: string
  stroke: string
}

const CARDS: CardSpec[] = [
  { field: 'policyMatches', label: 'Policy Matches', color: 'text-sky-300', stroke: '#7dd3fc' },
  { field: 'policyPass', label: 'Policy Pass', color: 'text-emerald-300', stroke: '#6ee7b7' },
  { field: 'policyDrops', label: 'Policy Drops', color: 'text-rose-300', stroke: '#fda4af' },
  { field: 'rxPackets', label: 'Rx Packets', color: 'text-cyan-300', stroke: '#67e8f9' },
  { field: 'txPackets', label: 'Tx Packets', color: 'text-teal-300', stroke: '#5eead4' },
  { field: 'rxBytes', label: 'Rx Bandwidth', bandwidth: true, color: 'text-amber-300', stroke: '#fcd34d' },
]

/** Format a per-second event/packet rate. */
function fmtRate(n: number): string {
  if (n > 0 && n < 10) return `${n.toFixed(1)}/s`
  return `${fmtCount(Math.round(n))}/s`
}

/** Format a bytes/sec value as a network bit-rate (bps/Kbps/Mbps/Gbps). */
function fmtBitrate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8
  if (bits < 1000) return `${Math.round(bits)} bps`
  if (bits < 1e6) return `${(bits / 1e3).toFixed(1)} Kbps`
  if (bits < 1e9) return `${(bits / 1e6).toFixed(1)} Mbps`
  return `${(bits / 1e9).toFixed(2)} Gbps`
}

/** Format a cumulative byte count as a data volume with an explicit unit. */
function fmtVolume(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`
}

/**
 * Windowed average rate for `field`: change in the cumulative counter divided
 * by the elapsed wall-clock time, measured against the oldest sample still
 * inside RATE_WINDOW_MS. Returns null until two samples exist.
 */
function windowedRate(samples: Sample[], field: MetricField): number | null {
  if (samples.length < 2) return null
  const newest = samples[samples.length - 1]
  const cutoff = newest.t - RATE_WINDOW_MS
  // Oldest sample at or after the cutoff (falling back to the very oldest).
  let base = samples[0]
  for (const s of samples) {
    if (s.t >= cutoff) {
      base = s
      break
    }
  }
  const dt = (newest.t - base.t) / 1000
  if (dt <= 0) return null
  const delta = newest.m[field] - base.m[field]
  return delta > 0 ? delta / dt : 0
}

// Rate history lives at module scope, not in component state, so that leaving
// the Fleet tab (which unmounts this component) and coming back doesn't throw
// the accumulated samples away and leave the cards showing "—" with empty
// sparklines for several poll cycles — the original "few seconds to display"
// lag. There is only ever one FleetMetricsBar, so a singleton buffer is safe,
// and both buffers are length-capped below so they can't grow unbounded.
const sampleStore: Sample[] = []
const seriesStore: Record<string, number[]> = {}

function Sparkline({ data, stroke }: { data: number[]; stroke: string }) {
  const w = 100
  const h = 28
  if (data.length < 2) {
    return <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-7" preserveAspectRatio="none" />
  }
  const max = Math.max(...data, 1e-9)
  const min = Math.min(...data)
  const span = max - min || 1
  const step = w / (data.length - 1)
  const pts = data.map((v, i) => {
    const x = i * step
    const y = h - ((v - min) / span) * (h - 2) - 1
    return `${x.toFixed(1)},${y.toFixed(1)}`
  })
  const area = `0,${h} ${pts.join(' ')} ${w},${h}`
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-7" preserveAspectRatio="none">
      <polygon points={area} fill={stroke} fillOpacity="0.12" />
      <polyline
        points={pts.join(' ')}
        fill="none"
        stroke={stroke}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}

export default function FleetMetricsBar() {
  const { data, error } = useQuery<{ fleetMetrics: FleetMetrics }>(GET_FLEET_METRICS, {
    pollInterval: POLL_MS,
    fetchPolicy: 'no-cache',
  })

  const [, force] = useState(0)

  // Drive new samples off the freshly fetched value only; fall back to the
  // last retained sample for rendering so a remount paints immediately from
  // history instead of flashing the "Loading…" placeholder.
  const fetched = data?.fleetMetrics
  const m = fetched ?? sampleStore[sampleStore.length - 1]?.m

  useEffect(() => {
    if (!fetched) return
    sampleStore.push({ t: Date.now(), m: fetched })
    if (sampleStore.length > MAX_SAMPLES) sampleStore.shift()

    for (const c of CARDS) {
      const r = windowedRate(sampleStore, c.field)
      if (r === null) continue
      const series = seriesStore[c.field] ?? (seriesStore[c.field] = [])
      series.push(r)
      if (series.length > SPARK_POINTS) series.shift()
    }
    force((n) => n + 1)
  }, [fetched])

  if (error) {
    return (
      <div className="text-sm text-red-400 bg-gray-800 rounded-lg p-3 border border-gray-700">
        Fleet metrics unavailable: {error.message}
      </div>
    )
  }
  if (!m) {
    return (
      <div className="text-sm text-gray-500 bg-gray-800 rounded-lg p-4 border border-gray-700">
        Loading fleet metrics…
      </div>
    )
  }

  const warming = sampleStore.length < 2

  return (
    <div className="bg-gray-900/60 rounded-lg border border-gray-700 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
          Fleet Metrics
        </h2>
        <div className="flex items-center gap-3 text-xs text-gray-400">
          <span>
            <span className="text-gray-200 font-medium">{m.nodesReporting}</span>
            <span className="text-gray-500">/{m.nodesTotal}</span> reporting
          </span>
          {warming && <span className="text-gray-600 italic">computing rates…</span>}
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {CARDS.map((c) => {
          const series = seriesStore[c.field] ?? []
          const rate = series.length ? series[series.length - 1] : null
          const total = m[c.field]
          return (
            <div
              key={c.field}
              className="bg-gray-800/80 rounded-lg p-3 border border-gray-700/80 flex flex-col gap-1"
            >
              <div className="text-xs text-gray-400">{c.label}</div>
              <div className={`text-xl font-bold tabular-nums ${c.color}`}>
                {rate === null ? '—' : c.bandwidth ? fmtBitrate(rate) : fmtRate(rate)}
              </div>
              <Sparkline data={series} stroke={c.stroke} />
              <div className="text-[11px] text-gray-500 tabular-nums">
                {c.bandwidth ? fmtVolume(total) : fmtCount(total)} total
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
