import { ArrowUpRight } from 'lucide-react'
import { type ReactNode } from 'react'
import { Link } from 'react-router'

import { type DirectSide, type HostReport, type NodeDetail, type NodeRoute } from '@/api/types'
import { Flag } from '@/components/flag'
import { t } from '@/i18n'
import { formatBytes } from '@/lib/format'
import { nodePath } from '@/lib/nodes'
import { msText, permilleText, problemText } from '@/lib/tests'
import { formatAge, formatDuration } from '@/lib/time'
import { cn } from '@/lib/utils'
import { routeName } from '@/topology/diagnosis'

import { type Named } from './parts'

const d = t.diagnosis
const h = d.host

/** 一端用到的全部数据：节点的详情（上报）、诊断时的主机快照、路由表里到对端那一条、直连检测里它这一端。 */
export interface HostSide {
  id: number
  name: string
  detail: NodeDetail | undefined
  host: HostReport | undefined
  toPeer: NodeRoute | undefined
  direct: DirectSide | undefined
}

type Value = ReactNode | null

interface Row {
  key: string
  label: string
  value: (side: HostSide, nodes: Named) => Value
  mono?: boolean
}

interface Group {
  key: keyof typeof d.hostSection
  /** 数据从哪里来：节点的上报、诊断时量的，或者两样都有。 */
  source: 'live' | 'test' | 'mixed'
  /** 只有诊断时的主机快照才有：没有的那一端写为什么。 */
  hostOnly: boolean
  rows: Row[]
}

const pct = (value: number | null | undefined) => (value === null || value === undefined ? '—' : `${value}%`)
const count = (value: number | null | undefined) => (value === null || value === undefined ? null : String(value))
const done = (side: HostSide) => (side.host?.state === 'done' ? side.host : undefined)
/** 空字符串（旧版本的节点不报主机名）当作没有。 */
const text = (value: string | undefined) => (value === undefined || value === '' ? null : value)
const warn = (text: string) => <span className="font-medium text-warn">{text}</span>

/** 每次画的时候现取：名字跟着语言走（不能在模块加载时取出来存着）。 */
const groups = (): Group[] => [
  {
    key: 'node',
    source: 'live',
    hostOnly: false,
    rows: [
      { key: 'version', label: h.version, value: ({ detail }) => text(detail?.version) },
      { key: 'platform', label: h.platform, value: ({ detail }) => text(detail?.platform) },
      { key: 'hostname', label: h.hostname, value: ({ detail }) => text(detail?.hostname) },
      {
        key: 'reported',
        label: h.reported,
        value: ({ detail }) =>
          detail?.reported_secs_ago === null || detail?.reported_secs_ago === undefined
            ? null
            : formatAge(detail.reported_secs_ago),
      },
      {
        key: 'profile',
        label: h.profile,
        value: ({ detail }) =>
          detail?.performance === null || detail?.performance === undefined
            ? null
            : `${detail.performance.profile} · ${h.threads} ${detail.performance.threads}`,
      },
    ],
  },
  {
    key: 'system',
    source: 'test',
    hostOnly: true,
    rows: [
      { key: 'os', label: h.os, value: (side) => done(side)?.system?.os ?? null },
      { key: 'kernel', label: h.kernel, value: (side) => done(side)?.system?.kernel ?? null },
      {
        key: 'cpu-model',
        label: h.cpuModel,
        value: (side) => {
          const system = done(side)?.system
          if (system === null || system === undefined) return null
          return (
            [system.cpu_model, system.cores === null ? null : h.cores(system.cores), system.arch]
              .filter((part) => part !== null)
              .join(' · ') || null
          )
        },
      },
      {
        key: 'uptime',
        label: h.uptime,
        value: (side) => {
          const uptime = done(side)?.system?.uptime_secs
          return uptime === null || uptime === undefined ? null : formatDuration(uptime)
        },
      },
    ],
  },
  {
    key: 'resources',
    source: 'test',
    hostOnly: true,
    rows: [
      {
        key: 'cpu',
        label: h.cpu,
        value: (side) => {
          const cpu = done(side)?.cpu
          return cpu === null || cpu === undefined
            ? null
            : h.cpuValue(pct(cpu.system_percent), pct(cpu.process_percent))
        },
      },
      {
        key: 'cpu-peak',
        label: h.cpuPeak,
        value: (side) => {
          const peak = done(side)?.cpu_peak
          if (peak === null || peak === undefined) return null
          const text = h.cpuValue(pct(peak.system_percent), pct(peak.process_percent))
          return peak.process_percent !== null && peak.process_percent >= 85 ? warn(text) : text
        },
      },
      {
        key: 'load',
        label: h.load,
        value: (side) => {
          const load = done(side)?.load_x100
          return load === null || load === undefined ? null : load.map((value) => (value / 100).toFixed(2)).join(' · ')
        },
      },
      {
        key: 'memory',
        label: h.memory,
        value: (side) => {
          const memory = done(side)?.memory
          return memory === null || memory === undefined
            ? null
            : h.memoryValue(formatBytes(memory.available_bytes), formatBytes(memory.total_bytes))
        },
      },
      {
        key: 'rss',
        label: h.rss,
        value: (side) => {
          const rss = done(side)?.memory?.process_rss_bytes
          return rss === null || rss === undefined ? null : formatBytes(rss)
        },
      },
      {
        key: 'process-uptime',
        label: h.processUptime,
        value: (side) => {
          const uptime = done(side)?.process?.uptime_secs
          return uptime === null || uptime === undefined ? null : formatDuration(uptime)
        },
      },
      { key: 'threads', label: h.threads, value: (side) => count(done(side)?.process?.threads) },
    ],
  },
  {
    key: 'connections',
    source: 'mixed',
    hostOnly: false,
    rows: [
      { key: 'peers', label: h.peers, value: (side) => count(done(side)?.connections?.peers) },
      { key: 'relays', label: h.relays, value: (side) => count(done(side)?.connections?.relays) },
      {
        key: 'relay-clients',
        label: h.relayClients,
        value: (side) => count(done(side)?.connections?.relay_clients),
      },
      {
        key: 'streams',
        label: h.streams,
        value: (side) => count(done(side)?.connections?.streams ?? side.detail?.flows),
      },
      {
        key: 'lanes',
        label: h.lanes,
        value: (side) => {
          const inUse = done(side)?.connections?.lanes_in_use
          const idle = done(side)?.connections?.lanes_idle
          if (inUse !== null && inUse !== undefined && idle !== null && idle !== undefined) {
            return h.lanesValue(inUse, idle)
          }
          const lanes = side.detail?.lanes
          return lanes === null || lanes === undefined
            ? null
            : h.lanesValue(
                lanes.total.in_use,
                lanes.peers.reduce((total, lane) => total + lane.idle + lane.ready, 0),
              )
        },
      },
      {
        key: 'traffic',
        label: h.traffic,
        value: ({ detail }) =>
          detail === undefined ? null : h.trafficValue(formatBytes(detail.tx_bytes), formatBytes(detail.rx_bytes)),
      },
    ],
  },
  {
    key: 'peer',
    source: 'mixed',
    hostOnly: false,
    rows: [
      {
        key: 'route',
        label: h.route,
        value: (side, nodes) => {
          const route = done(side)?.to_peer?.route ?? side.toPeer?.route
          return route === undefined ? null : routeName(route, nodes)
        },
      },
      {
        key: 'rtt',
        label: h.rtt,
        value: (side) => {
          const rtt = done(side)?.to_peer?.rtt_us
          if (rtt !== null && rtt !== undefined) return msText(rtt)
          const reported = side.toPeer?.rtt_ms
          return reported === null || reported === undefined ? null : t.common.ms(reported)
        },
      },
      {
        key: 'min-rtt',
        label: h.minRtt,
        value: (side) => {
          const rtt = done(side)?.to_peer?.min_rtt_us
          return rtt === null || rtt === undefined ? null : msText(rtt)
        },
      },
      {
        key: 'cwnd',
        label: h.cwnd,
        value: (side) => {
          const cwnd = done(side)?.to_peer?.cwnd_bytes
          return cwnd === null || cwnd === undefined ? null : formatBytes(cwnd)
        },
      },
      { key: 'mtu', label: h.mtu, value: (side) => count(done(side)?.to_peer?.mtu) },
      {
        key: 'congestion',
        label: h.congestion,
        value: (side) => done(side)?.to_peer?.congestion?.toUpperCase() ?? null,
      },
      {
        key: 'packets',
        label: h.packets,
        value: (side) => {
          const sent = done(side)?.to_peer?.sent_packets
          const lost = done(side)?.to_peer?.lost_packets
          if (sent === null || sent === undefined || lost === null || lost === undefined) return null
          const loss = sent === 0 ? 0 : Math.round((lost / sent) * 1000)
          const text = h.packetsValue(String(sent), String(lost), permilleText(loss))
          return loss >= 100 ? <span className="font-medium text-danger">{text}</span> : loss >= 20 ? warn(text) : text
        },
      },
      { key: 'events', label: h.congestionEvents, value: (side) => count(done(side)?.to_peer?.congestion_events) },
      {
        key: 'during',
        label: h.bytesDuring,
        value: (side) => {
          const sent = done(side)?.to_peer?.bytes_sent
          const received = done(side)?.to_peer?.bytes_received
          return sent === null || sent === undefined || received === null || received === undefined
            ? null
            : h.trafficValue(formatBytes(sent), formatBytes(received))
        },
      },
      {
        key: 'age',
        label: h.connectionAge,
        value: (side) => {
          const age = done(side)?.to_peer?.age_secs
          return age === null || age === undefined ? null : formatDuration(age)
        },
      },
      {
        key: 'since',
        label: h.since,
        value: ({ toPeer }) => (toPeer === undefined ? null : formatDuration(toPeer.since_secs)),
      },
      { key: 'flows', label: h.peerFlows, value: ({ toPeer }) => count(toPeer?.flows) },
      {
        key: 'peer-traffic',
        label: h.peerTraffic,
        value: ({ toPeer }) =>
          toPeer?.tx_bytes === null ||
          toPeer?.tx_bytes === undefined ||
          toPeer.rx_bytes === null ||
          toPeer.rx_bytes === undefined
            ? null
            : h.trafficValue(formatBytes(toPeer.tx_bytes), formatBytes(toPeer.rx_bytes)),
      },
    ],
  },
  {
    key: 'network',
    source: 'mixed',
    hostOnly: false,
    rows: [
      {
        key: 'egress',
        label: h.egress,
        value: ({ detail }) =>
          detail?.egress_ip === null || detail?.egress_ip === undefined ? null : (
            <span className="inline-flex items-center gap-1.5">
              <Flag code={detail.country} />
              <span className="font-mono text-xs">{detail.egress_ip}</span>
            </span>
          ),
      },
      {
        key: 'observed',
        label: h.observed,
        value: ({ detail }) => detail?.observed_endpoint ?? null,
        mono: true,
      },
      {
        key: 'endpoints',
        label: h.endpoints,
        mono: true,
        value: ({ detail, direct }) =>
          detail === undefined || detail.endpoints.length === 0 ? (
            direct?.candidates === null || direct?.candidates === undefined ? null : (
              String(direct.candidates)
            )
          ) : (
            <ul>
              {detail.endpoints.map((endpoint) => (
                <li key={endpoint}>{endpoint}</li>
              ))}
            </ul>
          ),
      },
      {
        key: 'nat',
        label: h.nat,
        value: ({ detail, direct }) => {
          const varies = direct?.mapping_varies ?? detail?.mapping_varies
          return varies === null || varies === undefined ? null : varies ? warn(h.natVaries) : h.natStable
        },
      },
      {
        key: 'udp',
        label: h.udp,
        value: ({ detail, direct }) => {
          if (direct?.udp === false || detail?.no_udp === true) return warn(h.udpNo)
          return direct?.udp === true || detail !== undefined ? h.udpOk : null
        },
      },
      {
        key: 'attached',
        label: h.attached,
        value: ({ detail }, nodes) => {
          if (detail === undefined) return null
          if (detail.attached.length === 0) return h.none
          const name = (id: number) => nodes.find((node) => node.id === id)?.name ?? t.common.nodeMissing(id)
          return detail.attached.map((relay) => `${name(relay.relay)} ${t.common.ms(relay.rtt_ms)}`).join(' · ')
        },
      },
    ],
  },
]

/** 一端没有诊断时的主机数据：为什么（还没诊断、版本太旧、在测、没报）。有数据是 `null`。 */
function missing(side: HostSide, tested: boolean, nodes: Named): string | null {
  const host = side.host
  if (host?.state === 'done') return null
  if (host === undefined) return tested ? d.hostNotReported : d.hostNoTest
  if (host.problem?.code === 'not_supported') return d.hostTooOld
  if (host.state === 'pending') return t.tests.pending
  return host.problem === null ? t.tests.failed : problemText(host.problem, nodes)
}

interface HostsTabProps {
  network: number
  a: HostSide
  b: HostSide
  /** 这一对诊断过（有 `host` 时才有主机数据）。 */
  tested: boolean
  nodes: Named
}

/**
 * 两端主机：一张表，两列是 A 和 B，一行一项，按节点、系统、资源、连接、到对端的连接、网络分组；
 * 组名右边写数据是节点的上报还是诊断时量的。两端都没有的行不画；只有诊断才有的组，没有数据的那一端写为什么。
 * 要注意的数（CPU 占满一个核、丢包、对称型 NAT、UDP 不通）是琥珀色。
 */
export function HostsTab({ network, a, b, tested, nodes }: HostsTabProps) {
  const sides = [
    { side: a, label: d.nodeA },
    { side: b, label: d.nodeB },
  ]
  const sourceText = { live: d.hostLive, test: d.hostTest, mixed: `${d.hostLive} · ${d.hostTest}` }
  const all = groups()
  // 两半并排：左边这台机器（节点、系统、资源、网络），右边连接（连接、到对端的连接）；每半一张表，表头都是 A、B。
  const pick = (keys: readonly Group['key'][]) => all.filter((group) => keys.includes(group.key))
  const halves = [pick(['node', 'system', 'resources', 'network']), pick(['connections', 'peer'])]
  const renderTable = (subset: Group[], first: boolean) => (
    // 窄的地方三列也放得下：名字那一列窄一些，长的值（地址）折行，A、B 才能并排着比。
    <table className="w-full min-w-[19rem] table-fixed border-collapse text-[13px] wrap-anywhere">
      <colgroup>
        <col className="w-[5.25rem] @md:w-28" />
        <col />
        <col />
      </colgroup>
      <thead>
        <tr className="border-b">
          <td className="py-1.5" />
          {sides.map(({ side, label }) => (
            <th
              key={label}
              scope="col"
              className="pt-1.5 pr-2 pb-1.5 pl-3 text-left font-normal"
              data-testid={first ? `host-${label.toLowerCase()}` : undefined}
            >
              <span className="flex min-w-0 items-baseline gap-1.5">
                <span className="text-xs font-semibold text-muted-foreground">{label}</span>
                <Link
                  to={nodePath(network, side.id)}
                  className="inline-flex min-w-0 items-center gap-0.5 rounded-sm text-[13px] font-semibold hover:text-primary"
                >
                  <span className="truncate">{side.detail?.name ?? side.name}</span>
                  <ArrowUpRight className="size-3.5 shrink-0 self-center text-faint" aria-label={d.toNode} />
                </Link>
              </span>
            </th>
          ))}
        </tr>
      </thead>
      {subset.map((group) => {
        const reasons = sides.map(({ side }) => (group.hostOnly ? missing(side, tested, nodes) : null))
        const rows = group.rows.filter((row) => sides.some(({ side }) => row.value(side, nodes) !== null))
        return (
          <tbody key={group.key} data-testid={`hosts-${group.key}`}>
            <tr>
              <th scope="colgroup" colSpan={3} className="pt-3 pb-0.5 text-left text-xs font-medium">
                <span className="flex items-center justify-between gap-3">
                  {d.hostSection[group.key]}
                  <span className="font-normal text-muted-foreground">{sourceText[group.source]}</span>
                </span>
              </th>
            </tr>
            {rows.length === 0 ? (
              <tr>
                <td />
                {reasons.map((reason, index) => (
                  <td key={index} className="py-1 pr-2 pl-3 text-muted-foreground">
                    {reason ?? '—'}
                  </td>
                ))}
              </tr>
            ) : (
              rows.map((row, rowIndex) => (
                <tr key={row.key} className="hover:bg-muted/40">
                  <th scope="row" className="py-1 pr-2 text-left align-top font-normal text-muted-foreground">
                    {row.label}
                  </th>
                  {sides.map(({ side, label }, index) => {
                    const value = row.value(side, nodes)
                    const reason = reasons[index] ?? null
                    return (
                      <td
                        key={label}
                        className={cn(
                          'py-1 pr-2 pl-3 align-top break-words',
                          row.mono === true && value !== null && 'font-mono text-xs leading-5',
                        )}
                      >
                        {value !== null ? (
                          value
                        ) : reason !== null && rowIndex === 0 ? (
                          <span className="text-muted-foreground">{reason}</span>
                        ) : (
                          <span className="text-faint">—</span>
                        )}
                      </td>
                    )
                  })}
                </tr>
              ))
            )}
          </tbody>
        )
      })}
    </table>
  )
  return (
    <div data-testid="hosts" className="grid grid-cols-1 gap-x-8 @5xl:grid-cols-2">
      {halves.map((subset, index) => (
        <div key={index} className="min-w-0 overflow-x-auto">
          {renderTable(subset, index === 0)}
        </div>
      ))}
    </div>
  )
}
