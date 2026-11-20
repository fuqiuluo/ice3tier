import { useQueries, useQuery } from '@tanstack/react-query'
import { Route as RouteIcon, RotateCw, Waypoints } from 'lucide-react'
import { type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'

import { q } from '@/api/queries'
import {
  type Network,
  type Node,
  type NodeDetail,
  type NodeId,
  type NodeRoute,
  type PathCandidate,
  type Route,
  type RoutingMode,
} from '@/api/types'
import { Flag } from '@/components/flag'
import { InfoTip } from '@/components/info-tip'
import { NodeLink } from '@/components/node'
import { EmptyState, ErrorState, SkeletonRows } from '@/components/states'
import { Table, Td, Th, Tr } from '@/components/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { formatBytes } from '@/lib/format'
import { peerUsesLanes } from '@/lib/lanes'
import { unmeasuredOwnRelay } from '@/lib/unmeasured'
import { nodeName } from '@/lib/nodes'
import { REPORT_INTERVAL_SECS } from '@/lib/product'
import { formatAge, formatDuration } from '@/lib/time'
import { cn } from '@/lib/utils'
import { networkPath } from '@/pages/networks/context'

import { type Leg, legOf, lengthOf, middleOf, peerLegOf } from './routeParts'
import { RouteStar } from './RouteStar'
import { pairPath } from '@/topology/pair'

const d = t.nodes.detail

/** 对端多于这么多时，另一种模式的选择不自动去算（每个对端要现问一次两端），点"重新计算"再算。 */
const AUTO_ALTERNATIVE_LIMIT = 24

/** 另一种模式那几列铺一层很淡的底色，和现在走的那几列分开，不用竖线。 */
const BAND = 'bg-muted/40'

const modeLabel = (mode: RoutingMode): string => (mode === 'direct_first' ? d.routingDirectFirst : d.routingLowestCost)

/**
 * 另一种模式会选哪条：从节点现测的候选路径里挑。延迟优先取代价最低的；默认模式能直连就直连，
 * 否则取代价最低的、只经一个中继的。只是参考：真正切换时还有迟滞（收益不够大时不换）。
 */
function chooseFor(mode: RoutingMode, candidates: readonly PathCandidate[] | null | undefined): PathCandidate | null {
  if (candidates === null || candidates === undefined || candidates.length === 0) return null
  const sorted = [...candidates].sort((a, b) => a.cost_us - b.cost_us)
  if (mode === 'lowest_cost') return sorted[0] ?? null
  return (
    sorted.find((candidate) => candidate.route.via === 'direct') ??
    sorted.find((candidate) => candidate.route.via === 'relay' && candidate.route.relays.length === 1) ??
    null
  )
}

/** 候选路径上各段的延迟加起来。 */
const candidateRtt = (candidate: PathCandidate): number =>
  Math.round(candidate.legs.reduce((sum, leg) => sum + leg.rtt_us, 0) / 1000)

/**
 * 0.1.11 起的节点自己报"另一种模式会怎么走"（`alternative`）和直连在哪一步（`direct_status`），两个一起报。
 * 报了的行不用再去问 `…/path`；`alternative` 是 `null` 时就是和现在一样（或者刚上线、还没算过）。
 */
const reportsAlternative = (entry: NodeRoute): boolean =>
  entry.direct_status !== undefined && entry.direct_status !== null

/** 另一种模式的那条路和它的延迟（不知道是 `null`；经本节点自己的中继、那一段还没量到时 `unmeasured`）。 */
interface Alternative {
  route: Route
  rtt: number | null
  unmeasured: boolean
}

/** 经中继的那一行，悬停在"中继"上说直连怎么样了；P2P 的那一行说直连是怎么通的。旧的节点不报，就没有说明。 */
function modeHint(entry: NodeRoute): string | undefined {
  if (entry.route.via === 'direct') {
    const kind = entry.direct ?? null
    return kind === null ? undefined : `${t.routes.directKind[kind]}：${t.routes.directKindHint[kind]}`
  }
  if (entry.route.via !== 'relay') return undefined
  const status = entry.direct_status ?? null
  if (status === null) return undefined
  const states = t.routes.directState
  switch (status.state) {
    case 'not_tried':
      return states.not_tried
    case 'trying':
      return states.trying
    case 'verified':
      return states.verified
    case 'failed':
      return states.failed(t.routes.directCause[status.cause?.code ?? 'unknown'])
    default:
      return states.unknown
  }
}

/** 方式：就写 P2P 或者中继，标签一样宽，上下对齐。`hint` 是悬停的说明：P2P 是怎么通的，中继时直连怎么样了。 */
function ModeBadge({ route, peerOnline, hint }: { route: Route; peerOnline: boolean; hint?: string }) {
  const width = 'w-12 justify-center'
  if (route.via === 'none') {
    return (
      <Badge tone={peerOnline ? 'danger' : 'neutral'} className={width}>
        {d.viaNone}
      </Badge>
    )
  }
  const badge = (
    <Badge
      tone={route.via === 'relay' ? 'relay' : 'ok'}
      className={cn(width, hint !== undefined && 'cursor-help')}
      tabIndex={hint === undefined ? undefined : 0}
    >
      {route.via === 'relay' ? d.routesRelay : d.routesP2P}
    </Badge>
  )
  return hint === undefined ? badge : <Tooltip content={hint}>{badge}</Tooltip>
}

const dash = <span className="text-muted-foreground">—</span>

/** 下一跳：中间经过的第一个节点；中间没有别人时是一道横线。经好几个时，悬停写出整条（路径长度也看得出来）。 */
function NextHop({ middle, nodes }: { middle: readonly NodeId[] | null; nodes: readonly Node[] }) {
  const hop = middle?.[0]
  if (middle === null || hop === undefined) return dash
  const name = <span className="whitespace-nowrap">{nodeName(nodes, hop)}</span>
  if (middle.length < 2) return name
  const chain = middle.map((id) => nodeName(nodes, id)).join(' → ')
  return (
    <Tooltip content={d.routesViaChain(chain)}>
      <span tabIndex={0} className="cursor-help rounded-sm">
        {name}
      </span>
    </Tooltip>
  )
}

/** 下一跳的虚拟 IP。 */
function NextHopIp({ middle, nodes }: { middle: readonly NodeId[] | null; nodes: readonly Node[] }) {
  const hop = middle?.[0]
  const ip = hop === undefined ? undefined : nodes.find((candidate) => candidate.id === hop)?.virtual_ip
  return ip === undefined ? dash : <span className="whitespace-nowrap tabular">{ip}</span>
}

const p = t.routes.protocol

/**
 * 协议：共用的连接是 QUIC，平常写 QUIC/UDP。到中继 UDP 不通、QUIC 的包装在 TCP 里送过去时只写 TCP（黄字，
 * 悬停有一句解释）。不知道底下是什么时只写 QUIC。这一对之间有 ice3proxy（选了它的代理经过这一对）时，下面再写一行，
 * 点了去代理页（`lane` 是那里的地址）。走不通时是一道横线。
 */
function Protocol({ route, leg, lane }: { route: Route; leg: Leg; lane: string | null }) {
  if (route.via === 'none') return <span className="text-muted-foreground">—</span>
  const quic =
    leg === 'tcp' ? (
      <Tooltip content={t.routes.relayLegHint.tcp}>
        <span tabIndex={0} className="cursor-help rounded-sm whitespace-nowrap text-warn">
          {t.routes.legTransport.tcp}
        </span>
      </Tooltip>
    ) : (
      <span className="whitespace-nowrap">{leg === 'udp' ? p.over(p.quic, t.routes.legTransport.udp) : p.quic}</span>
    )
  if (lane === null) return quic
  return (
    <span className="flex flex-col leading-[18px]">
      {quic}
      <Tooltip content={p.laneHint}>
        <Link
          to={lane}
          className="self-start rounded-sm text-xs whitespace-nowrap text-muted-foreground hover:text-foreground hover:underline"
        >
          {p.over(p.lane, t.routes.legTransport.tcp)}
        </Link>
      </Tooltip>
    </span>
  )
}

/** 一个小图标链接：悬停写它是什么，读屏读的也是这句。 */
function IconLink({ to, label, icon }: { to: string; label: string; icon: ReactNode }) {
  return (
    <Tooltip content={label}>
      <Link
        to={to}
        aria-label={label}
        className="flex size-7 items-center justify-center rounded-md text-faint hover:bg-muted hover:text-foreground [&>svg]:size-4"
      >
        {icon}
      </Link>
    </Tooltip>
  )
}

/** 路由的两种看法：表格（默认）和星状图，记在地址里（`?view=star`）。 */
type View = 'table' | 'star'

/**
 * 这个节点到其他节点怎么走，按它自己最近一次的上报。右上角在表格和星状图之间切换。
 * 表格一行一个对端，两组同样的列：
 * 现在走的、换成另一种选路模式会怎么走（方式、经过、协议、路径长度、延迟；另一种模式的延迟后面写比现在快多少、慢多少），
 * 再后面是流量、已持续多久。另一种模式从现问到的候选路径里挑；和现在一样时也照常写出来。
 * 走得通的按延迟排在前面，不可达的、对端离线的淡下去排在后面。
 */
export function RoutesTab({ network, node }: { network: Network; node: NodeDetail }) {
  const [search, setSearch] = useSearchParams()
  const view: View = search.get('view') === 'star' ? 'star' : 'table'
  const setView = (next: View) =>
    setSearch(
      (current) => {
        const params = new URLSearchParams(current)
        if (next === 'star') params.set('view', 'star')
        else params.delete('view')
        return params
      },
      { replace: true },
    )
  const routes = useQuery(q.routes(network.id, node.id))
  const nodes = useQuery(q.nodes(network.id))
  const all = nodes.data ?? []
  // 一份上报里的各行一样新；取最新的那个写在表的右上角，比它旧得多的行单独标出来。
  const reported = routes.data?.routes ?? []
  const freshest = reported.length === 0 ? null : Math.min(...reported.map((entry) => entry.age_secs))
  const online = (id: NodeId) => all.find((candidate) => candidate.id === id)?.online ?? true
  const rows = [...reported].sort((a, b) => {
    const rank = (entry: NodeRoute) => (entry.route.via === 'none' ? 2 : online(entry.peer.id) ? 0 : 1)
    return rank(a) - rank(b) || (a.rtt_ms ?? Infinity) - (b.rtt_ms ?? Infinity)
  })

  const mode: RoutingMode = node.routing ?? network.routing
  const other: RoutingMode = mode === 'direct_first' ? 'lowest_cost' : 'direct_first'
  const auto = rows.length <= AUTO_ALTERNATIVE_LIMIT
  const paths = useQueries({
    queries: rows.map((entry) => ({
      ...q.path(network.id, node.id, entry.peer.id),
      enabled: view === 'table' && auto && !reportsAlternative(entry) && entry.route.via !== 'none',
    })),
  })
  const recompute = () => {
    for (const path of paths) void path.refetch()
  }
  const computing = paths.some((path) => path.isFetching)
  // 和它之间有 ice3proxy 的对端：只有它们之间有选了 ice3proxy 的代理时才有，点了去代理页。
  const lanes = new Set((node.lanes?.peers ?? []).filter(peerUsesLanes).map((peer) => peer.peer))
  const laneTo = (peer: NodeId) => (lanes.has(peer) ? networkPath(network.id, 'proxies') : null)
  // 都是自己报的新节点时不用重新算：每次上报都是新的。
  const asksPaths = view === 'table' && rows.some((entry) => !reportsAlternative(entry))
  const empty = routes.isSuccess && (!routes.data.online || routes.data.routes.length === 0)

  return (
    <div className={view === 'star' && !empty ? 'flex flex-1 flex-col gap-4' : 'space-y-4'}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 text-[13px] text-muted-foreground">
        <p data-testid="routes-mode" className="flex items-center gap-2">
          {d.routesModeLabel}
          <Badge tone="outline">{modeLabel(mode)}</Badge>
        </p>
        <div className="flex items-center gap-2">
          <p data-testid="routes-updated">
            {freshest === null
              ? t.common.updatedEvery(REPORT_INTERVAL_SECS)
              : t.common.reportedAgo(formatAge(freshest))}
          </p>
          {asksPaths ? (
            <Tooltip content={d.routesRecompute(modeLabel(other))}>
              <Button
                variant="ghost"
                size="icon-sm"
                className="text-muted-foreground"
                onClick={recompute}
                disabled={computing}
                aria-label={d.routesRecompute(modeLabel(other))}
              >
                <RotateCw className={cn(computing && 'animate-spin')} aria-hidden />
              </Button>
            </Tooltip>
          ) : null}
          <Segmented
            aria-label={d.routesView}
            size="sm"
            value={view}
            onChange={setView}
            options={[
              { value: 'table', label: d.routesViewTable },
              { value: 'star', label: d.routesViewStar },
            ]}
            className="ml-1"
          />
        </div>
      </div>
      {routes.isError ? (
        <ErrorState title={d.routesLoadFailed} error={routes.error} onRetry={() => void routes.refetch()} />
      ) : routes.isSuccess && !routes.data.online ? (
        <EmptyState icon={RouteIcon} title={d.routesOffline} />
      ) : routes.isSuccess && routes.data.routes.length === 0 ? (
        <EmptyState icon={RouteIcon} title={d.routesEmpty} />
      ) : view === 'star' ? (
        routes.isPending ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <RouteStar
            network={network}
            node={node}
            nodes={all}
            spokes={rows.map((entry) => ({
              entry,
              peer: all.find((candidate) => candidate.id === entry.peer.id),
              leg: legOf(entry.route, node.id, entry.relay_leg ?? null, peerLegOf(node, entry.peer.id)),
              middle: middleOf(entry.route, node.id, entry.peer.id),
            }))}
          />
        )
      ) : (
        // 窄的地方一个对端排成一块：只写现在走的路（方式、协议、延迟，经中继时再写下一跳）、流量和持续了多久；
        // 换一种选路模式会怎么走那一组不写。
        <Table stack>
          <thead>
            {/* 两组列的名字：现在走的、换成另一种模式。后一组的底色一直铺到表格底。 */}
            <tr>
              <th aria-hidden />
              <th colSpan={6} scope="colgroup" className="px-3 pt-2 text-left text-xs font-medium text-foreground">
                {d.routesGroupNow(modeLabel(mode))}
              </th>
              <th
                colSpan={6}
                scope="colgroup"
                className={cn('px-3 pt-2 text-left text-xs font-medium text-foreground', BAND)}
              >
                <span className="inline-flex items-center gap-1">
                  {d.routesColOther(modeLabel(other))}
                  <InfoTip>{d.routesGroupOtherTip}</InfoTip>
                </span>
              </th>
              <th colSpan={3} aria-hidden />
            </tr>
            <tr>
              <Th>{d.colPeer}</Th>
              <Th>{d.routesColMode}</Th>
              <Th>{d.routesColVia}</Th>
              <Th>{d.routesColNextHopIp}</Th>
              <Th>{d.routesColProtocol}</Th>
              <Th>{d.routesColLength}</Th>
              <Th>{d.colRtt}</Th>
              <Th className={BAND}>{d.routesColMode}</Th>
              <Th className={BAND}>{d.routesColVia}</Th>
              <Th className={BAND}>{d.routesColNextHopIp}</Th>
              <Th className={BAND}>{d.routesColProtocol}</Th>
              <Th className={BAND}>{d.routesColLength}</Th>
              <Th className={BAND}>{d.colRtt}</Th>
              <Th>{d.routesColTraffic}</Th>
              <Th>
                <span className="inline-flex items-center gap-1">
                  {d.colSince}
                  <InfoTip>{d.colSinceTip}</InfoTip>
                </span>
              </Th>
              <Th>
                <span className="sr-only">{t.common.moreActions}</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {routes.isPending ? <SkeletonRows columns={16} rows={3} /> : null}
            {rows.map((entry, index) => {
              const peer = all.find((candidate) => candidate.id === entry.peer.id)
              const peerOnline = peer?.online ?? true
              const path = paths[index]
              let alternative: Alternative | null
              let pending = false
              if (reportsAlternative(entry)) {
                const reportedAlt = entry.alternative ?? null
                alternative =
                  reportedAlt !== null
                    ? {
                        route: reportedAlt.route,
                        rtt: reportedAlt.rtt_ms,
                        unmeasured: unmeasuredOwnRelay(
                          reportedAlt.route,
                          node.id,
                          reportedAlt.rtt_ms === null ? null : reportedAlt.rtt_ms * 1000,
                        ),
                      }
                    : entry.route.via === 'none'
                      ? null
                      : { route: entry.route, rtt: entry.rtt_ms, unmeasured: false }
              } else {
                const chosen = entry.route.via === 'none' ? null : chooseFor(other, path?.data?.forward.candidates)
                alternative =
                  chosen === null
                    ? null
                    : {
                        route: chosen.route,
                        rtt: candidateRtt(chosen),
                        unmeasured: unmeasuredOwnRelay(chosen.route, node.id, chosen.cost_us),
                      }
                pending = path?.isPending === true && auto && entry.route.via !== 'none'
              }
              // 走不通、对端离线的行淡下去：名字和"不可达"照常能看清。
              const dim = entry.route.via === 'none' || peer?.online === false
              const fade = cn(dim && 'opacity-50')
              const peerLeg = peerLegOf(node, entry.peer.id)
              const nowLeg = legOf(entry.route, node.id, entry.relay_leg ?? null, peerLeg)
              const nowMiddle = middleOf(entry.route, node.id, entry.peer.id)
              const directHint = modeHint(entry)

              // 没有内容的格子每列一道横线，和左边一组一样，不合并成一格。
              const dashes = [0, 1, 2, 3, 4, 5].map((column) => (
                <Td key={column} cell="hide" className={cn(BAND, 'text-muted-foreground', fade)}>
                  —
                </Td>
              ))
              let otherCells: ReactNode
              if (pending) {
                otherCells = (
                  <Td colSpan={6} cell="hide" className={BAND}>
                    <Skeleton className="h-3.5 w-40" />
                  </Td>
                )
              } else if (alternative === null) {
                otherCells = dashes
              } else {
                const altRoute = alternative.route
                // 另一条路不说传输：经的第一个中继和现在一样时，传输也一样；否则不知道。
                const sameFirst =
                  altRoute.via === 'relay' &&
                  entry.route.via === 'relay' &&
                  altRoute.relays[0] === entry.route.relays[0]
                const altLeg = legOf(altRoute, node.id, sameFirst ? (entry.relay_leg ?? null) : null, peerLeg)
                const altMiddle = middleOf(altRoute, node.id, entry.peer.id)
                const rtt = alternative.unmeasured ? null : alternative.rtt
                const delta = rtt === null || entry.rtt_ms === null ? null : rtt - entry.rtt_ms
                otherCells = (
                  <>
                    <Td cell="hide" className={BAND}>
                      <ModeBadge route={altRoute} peerOnline={peerOnline} />
                    </Td>
                    <Td cell="hide" className={cn(BAND, 'text-sm')}>
                      <NextHop middle={altMiddle} nodes={all} />
                    </Td>
                    <Td cell="hide" className={cn(BAND, 'text-[13px]')}>
                      <NextHopIp middle={altMiddle} nodes={all} />
                    </Td>
                    <Td cell="hide" className={cn(BAND, 'text-[13px]')}>
                      <Protocol route={altRoute} leg={altLeg} lane={laneTo(entry.peer.id)} />
                    </Td>
                    <Td cell="hide" className={BAND}>
                      <span className="text-sm tabular">{lengthOf(altMiddle) ?? '—'}</span>
                    </Td>
                    <Td cell="hide" className={cn(BAND, 'whitespace-nowrap')}>
                      {alternative.unmeasured ? (
                        <Tooltip content={t.routes.unmeasuredHint}>
                          <span tabIndex={0} className="cursor-help rounded-sm text-[13px] text-muted-foreground">
                            {t.routes.unmeasured}
                          </span>
                        </Tooltip>
                      ) : rtt === null ? (
                        <span className="text-muted-foreground">—</span>
                      ) : (
                        <span className="text-sm font-medium tabular">{t.common.ms(rtt)}</span>
                      )}
                      {delta !== null && delta !== 0 ? (
                        <span className={cn('ml-1.5 text-xs tabular', delta < 0 ? 'text-ok' : 'text-warn')}>
                          {d.routesDelta(delta)}
                        </span>
                      ) : null}
                    </Td>
                  </>
                )
              }

              return (
                <Tr key={entry.peer.id} className="h-14">
                  <Td cell="main">
                    <span className="inline-flex items-center gap-2">
                      <NodeLink network={network.id} node={entry.peer} online={peer?.online} />
                      <Flag code={peer?.country} />
                    </span>
                    <div className="text-xs text-muted-foreground tabular">{entry.peer.virtual_ip}</div>
                  </Td>
                  <Td cell="inline">
                    <ModeBadge route={entry.route} peerOnline={peerOnline} hint={directHint} />
                  </Td>
                  <Td
                    cell={entry.route.via === 'relay' ? 'row' : 'hide'}
                    label={d.routesColVia}
                    className={cn('text-sm', fade)}
                  >
                    <NextHop middle={nowMiddle} nodes={all} />
                  </Td>
                  <Td cell="hide" className={cn('text-[13px]', fade)}>
                    <NextHopIp middle={nowMiddle} nodes={all} />
                  </Td>
                  <Td cell="inline" className={cn('text-[13px]', fade)}>
                    <Protocol route={entry.route} leg={nowLeg} lane={laneTo(entry.peer.id)} />
                  </Td>
                  <Td cell="hide" className={fade}>
                    <span className="text-sm tabular">{lengthOf(nowMiddle) ?? '—'}</span>
                  </Td>
                  <Td cell="inline" className={fade}>
                    {entry.rtt_ms === null ? (
                      <span className="text-muted-foreground">—</span>
                    ) : (
                      <span className="text-sm font-medium tabular">{t.common.ms(entry.rtt_ms)}</span>
                    )}
                  </Td>
                  {otherCells}
                  <Td
                    cell="row"
                    label={d.routesColTraffic}
                    className={cn('text-xs whitespace-nowrap text-muted-foreground', fade)}
                  >
                    <span className="tabular">
                      ↑ {formatBytes(entry.tx_bytes ?? 0)} ↓ {formatBytes(entry.rx_bytes ?? 0)}
                    </span>
                  </Td>
                  <Td
                    cell="row"
                    label={d.colSince}
                    className={cn('text-xs whitespace-nowrap text-muted-foreground tabular', fade)}
                    data-testid={`route-since-${entry.peer.id}`}
                  >
                    {formatDuration(entry.since_secs)}
                    {freshest !== null && entry.age_secs - freshest > 2 * REPORT_INTERVAL_SECS ? (
                      <span className="block text-warn">{d.rowStale(formatAge(entry.age_secs))}</span>
                    ) : null}
                  </Td>
                  <Td cell="end">
                    <span className="flex items-center justify-end gap-0.5">
                      <IconLink
                        to={pairPath(network.id, 'topology', node.id, entry.peer.id)}
                        label={d.routesOnTopology}
                        icon={<Waypoints />}
                      />
                      <IconLink
                        to={pairPath(network.id, 'diagnosis', node.id, entry.peer.id)}
                        label={d.routesDiagnose}
                        icon={<RouteIcon />}
                      />
                    </span>
                  </Td>
                </Tr>
              )
            })}
          </tbody>
        </Table>
      )}
    </div>
  )
}
