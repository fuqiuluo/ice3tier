import {
  type DirectKind,
  type EntryLanes,
  type LegTransport,
  type MatrixEntry,
  type MatrixNode,
  type NodeId,
  type RouteMatrix,
} from '@/api/types'

import { cellKey, hopsOf, indexEntries } from './route'

/**
 * 把路由矩阵整理成拓扑图要画的点和线。纯函数，不依赖画图的库，方便测试。
 *
 * - 每个节点一个点，按名字排，位置不随数据变。relay 少、别的节点多时 relay 排在中间一圈、其余排在外面一圈；
 *   不然全部排成一圈。
 *   两圈都横向拉宽成椭圆（画布是宽的）；外圈转一个角度，让外圈的点不和里圈的点对齐，线就少从点上穿过。
 * - 一条线笔直连过去会压到别的点时，弯成一道弧绕开（`bend`）。
 * - 线只画现在有连接的：两个节点之间每一种连法一条线，直连一条，经某几个 relay 一条（线连着这两个节点，
 *   写着经谁）。两个方向走同一种连法时合成一条，不一样时各一条、带方向，并排弯开。
 *   所以几十个节点时线的数量跟"有连接的对数"走，不是节点数的平方。
 * - 两端都在线、两个方向却都是"无路可走"的一对，画一条表示不可达的线。
 * - 选中了一对（A、B）时，另外给出这两个方向的路，一段一段带方向，画在最上面。
 */

/** 节点卡片的大小：relay 和别的节点一样大，靠卡片上的标签分。 */
export const NODE_BOX = { width: 176, height: 56 } as const
export const RELAY_BOX = NODE_BOX

const NODE_GAP = 30
const RELAY_GAP = 48
/** 外圈和里圈之间至少留这么宽，线才看得清。 */
const RING_GAP = 190
const MIN_OUTER = 170
/** 横向拉宽：圆变成椭圆，配合宽的画布。 */
export const STRETCH_X = 1.6
/** 不拉宽，就是圆：画布不比高宽多少时（手机）用它，缩进画布时点才不至于太小。 */
export const STRETCH_NONE = 1
/** 线离别的卡片至少这么远，近了就弯开。 */
const LINE_CLEARANCE = 18

export const pointId = (id: NodeId): string => `n:${id}`

export interface TopoPoint {
  id: string
  node: MatrixNode
  relay: boolean
  /** 中心的坐标。 */
  x: number
  y: number
  width: number
  height: number
  /** 选中的 A 或 B。 */
  picked: 'a' | 'b' | null
}

/**
 * 两个节点之间的一种连法。`source` 是编号小的那个节点；`forward` 是 source 到 target 这个方向走它，`reverse` 反过来。
 */
export interface TopoLink {
  id: string
  source: string
  target: string
  /** `lane` 是 ice3proxy：两个节点之间单独的 TCP 连接，带它们之间的 TCP 流。 */
  kind: 'direct' | 'relay' | 'lane'
  /** 经过的 relay，从 source 一侧数起；直连是空的。 */
  relays: NodeId[]
  forward: boolean
  reverse: boolean
  /**
   * 经的 relay 就是两端之一（一端自己是 relay，另一端在它上面有会话）：中间没有别的节点，流量直接走这条会话。
   * 发送方就是那个 relay 时，节点报不出到 relay 那一段的传输和延迟。
   */
  session: boolean
  /** 走它的每一格都是过期的。 */
  stale: boolean
  /** 两个方向里低的那个全程延迟。 */
  rtt: number | null
  /** 直连是怎么建立的（两个方向里先报出来的那个）。 */
  directKind: DirectKind | null
  /** 经 relay 时到第一个 relay 那一段的传输；有一个方向走 TCP 就是 TCP。不知道是 `null`。 */
  transport: LegTransport | null
  /** 走它的格子（一个方向算一格），source 到 target 的在前。 */
  entries: MatrixEntry[]
  /**
   * 经 relay 时每一段（从 source 数起）：两头之间直连的延迟，取两个方向里低的；那一段两头之间不是直连、没有数时是 `null`。
   * 直连是空的。
   */
  legs: { from: NodeId; to: NodeId; rtt: number | null }[]
  /** ice3proxy 的连接：两头各自报的里取大的（同一批连接两头都看得到，不相加）。不是 `lane` 时是 `null`。 */
  lanes: EntryLanes | null
  /** 同一对节点之间的第几条、一共几条：几条时各自弯开。 */
  index: number
  siblings: number
  /** 绕开别的卡片要弯多少（见 `bendAround`）；0 是直线。 */
  bend: number
}

export interface Unreachable {
  id: string
  source: string
  target: string
  stale: boolean
  bend: number
}

export interface HighlightHop {
  id: string
  source: string
  target: string
  direction: 'forward' | 'reverse'
  kind: 'direct' | 'relay'
  stale: boolean
  /** 两个方向走同一段时各自弯向一侧。 */
  index: number
  siblings: number
  /** 这个方向的第几段，从 0 起。 */
  step: number
  bend: number
}

export interface Selection {
  a: NodeId
  b: NodeId
}

export interface TopologyShape {
  points: TopoPoint[]
  links: TopoLink[]
  unreachable: Unreachable[]
  /** 选中的那一对两个方向的路。没有选、或者矩阵里没有这个方向时是空的。 */
  highlight: HighlightHop[]
  forward: MatrixEntry | null
  reverse: MatrixEntry | null
  /** 选中的那一对的路经过的点，图上其余的变暗。 */
  involved: Set<string>
  /** 排的时候横向拉宽了多少（`STRETCH_X` 或 `STRETCH_NONE`）。 */
  stretch: number
}

function ring(count: number, width: number, gap: number, minRadius: number): number {
  if (count <= 1) return minRadius
  // 相邻两个点的中心相距 2r·sin(π/n)，要放得下一个点再加上间隔。
  return Math.max(minRadius, Math.ceil((width + gap) / (2 * Math.sin(Math.PI / count))))
}

const TOP = -Math.PI / 2

function angleOf(count: number, index: number, start: number): number {
  return start + (2 * Math.PI * index) / Math.max(1, count)
}

function place(count: number, radius: number, index: number, stretch: number, start = TOP): { x: number; y: number } {
  if (count === 1 && radius === 0) return { x: 0, y: 0 }
  // 从 start 开始顺时针排，横向拉宽。
  const angle = angleOf(count, index, start)
  return { x: Math.round(radius * stretch * Math.cos(angle)), y: Math.round(radius * Math.sin(angle)) }
}

/** 两个角度相差多少（0 到 π）。 */
function angleGap(a: number, b: number): number {
  const gap = Math.abs(a - b) % (2 * Math.PI)
  return gap > Math.PI ? 2 * Math.PI - gap : gap
}

/**
 * 外圈从哪个角度开始排：离里圈每个点的方向都尽量远（里圈的点挡在外圈的点和圆心之间时，线会从它上面穿过）；
 * 一样远时挑外圈的点更靠左右两边的（画布是宽的，上下没那么多地方）。
 */
function outerStart(outer: number, inner: number): number {
  if (outer === 0) return TOP
  const innerAngles = inner <= 1 ? [] : Array.from({ length: inner }, (_, index) => angleOf(inner, index, TOP))
  const step = (2 * Math.PI) / outer
  let best = { start: TOP, gap: -1, upright: Number.POSITIVE_INFINITY }
  for (let k = 0; k < 24; k += 1) {
    const start = TOP + (step * k) / 24
    const angles = Array.from({ length: outer }, (_, index) => angleOf(outer, index, start))
    const gap = Math.min(Math.PI, ...angles.flatMap((angle) => innerAngles.map((other) => angleGap(angle, other))))
    const upright = angles.reduce((total, angle) => total + Math.abs(Math.sin(angle)), 0)
    if (gap > best.gap + 1e-6 || (Math.abs(gap - best.gap) <= 1e-6 && upright < best.upright - 1e-6)) {
      best = { start, gap, upright }
    }
  }
  return best.start
}

const byName = (a: MatrixNode, b: MatrixNode) => a.name.localeCompare(b.name, undefined, { numeric: true })

/** 两个点之间的线不分方向，编号按节点编号小的在前。 */
function segment(x: NodeId, y: NodeId): { key: string; source: NodeId; target: NodeId } {
  const [source, target] = x < y ? [x, y] : [y, x]
  return { key: `${source}-${target}`, source, target }
}

/**
 * relay 少、别的节点多时，relay 是中心：排在里圈，别的节点围着它。relay 和别的节点差不多多时（大家多半互相直连），
 * 全部排成一圈：点都在圈上，两点之间的线不会从第三个点上穿过。
 */
function asHub(relays: number, others: number): boolean {
  return relays > 0 && others >= Math.max(3, 2 * relays)
}

function layout(
  matrix: RouteMatrix,
  relays: ReadonlySet<NodeId>,
  selection: Selection | null,
  stretch: number,
): TopoPoint[] {
  const hub = asHub(
    matrix.nodes.filter((node) => relays.has(node.id)).length,
    matrix.nodes.filter((node) => !relays.has(node.id)).length,
  )
  const inner = hub ? matrix.nodes.filter((node) => relays.has(node.id)).sort(byName) : []
  const outer = (hub ? matrix.nodes.filter((node) => !relays.has(node.id)) : [...matrix.nodes]).sort(byName)
  const innerRadius = inner.length <= 1 ? 0 : ring(inner.length, RELAY_BOX.width, RELAY_GAP, 110)
  const outerRadius = ring(
    outer.length,
    NODE_BOX.width,
    NODE_GAP,
    inner.length === 0 ? MIN_OUTER : innerRadius + RING_GAP,
  )
  const picked = (id: NodeId): TopoPoint['picked'] => (selection?.a === id ? 'a' : selection?.b === id ? 'b' : null)
  const start = outerStart(outer.length, inner.length)
  return [
    ...inner.map((node, index) => ({
      id: pointId(node.id),
      node,
      relay: true,
      ...place(inner.length, innerRadius, index, stretch),
      ...RELAY_BOX,
      picked: picked(node.id),
    })),
    ...outer.map((node, index) => ({
      id: pointId(node.id),
      node,
      relay: relays.has(node.id),
      ...place(outer.length, outer.length === 1 && inner.length === 0 ? 0 : outerRadius, index, stretch, start),
      ...NODE_BOX,
      picked: picked(node.id),
    })),
  ]
}

/**
 * 一条线笔直连过去会不会压到别的卡片；会的话弯多少。返回的是二次贝塞尔曲线控制点离两端中点的距离，
 * 沿"从坐标小的一端指向大的一端"的方向左手边的法线算（和 `curveBetween` 一个方向），负数弯向另一边。
 * 只看压得最深的那一张卡片；弯开之后曲线在它那里离它至少 `LINE_CLEARANCE`。
 */
export function bendAround(points: readonly TopoPoint[], sourceId: string, targetId: string): number {
  const source = points.find((point) => point.id === sourceId)
  const target = points.find((point) => point.id === targetId)
  if (source === undefined || target === undefined) return 0
  const [low, high] =
    source.x < target.x || (source.x === target.x && source.y < target.y) ? [source, target] : [target, source]
  const dx = high.x - low.x
  const dy = high.y - low.y
  const length = Math.hypot(dx, dy)
  if (length === 0) return 0
  const nx = -dy / length
  const ny = dx / length
  let bend = 0
  for (const point of points) {
    if (point === source || point === target) continue
    const along = ((point.x - low.x) * dx + (point.y - low.y) * dy) / (length * length)
    if (along <= 0.05 || along >= 0.95) continue
    const side = (point.x - low.x) * nx + (point.y - low.y) * ny
    // 卡片在法线方向上伸出多远。
    const reach = (Math.abs(nx) * point.width) / 2 + (Math.abs(ny) * point.height) / 2
    const short = reach + LINE_CLEARANCE - Math.abs(side)
    if (short <= 0) continue
    // 曲线在 along 处离直线 2·t·(1−t)·控制点的距离；朝卡片的另一边弯。
    const needed = (short / (2 * along * (1 - along))) * (side >= 0 ? -1 : 1)
    if (Math.abs(needed) > Math.abs(bend)) bend = needed
  }
  const limit = length * 0.9
  return Math.round(Math.max(-limit, Math.min(limit, bend)))
}

function highlightOf(
  forward: MatrixEntry | null,
  reverse: MatrixEntry | null,
  known: ReadonlySet<NodeId>,
  points: readonly TopoPoint[],
): HighlightHop[] {
  const legs = [
    { direction: 'forward' as const, entry: forward },
    { direction: 'reverse' as const, entry: reverse },
  ]
  const hops: Omit<HighlightHop, 'index' | 'siblings' | 'bend'>[] = []
  for (const { direction, entry } of legs) {
    if (entry === null) continue
    const path = hopsOf(entry.from, entry.to, entry.route)
    // 无路可走，或者经过一个不在这个网络里的节点：没有可画的。
    if (!path?.every((id) => known.has(id))) continue
    for (let step = 0; step < path.length - 1; step += 1) {
      const from = path[step] ?? 0
      const to = path[step + 1] ?? 0
      hops.push({
        id: `hl:${direction}:${step}`,
        source: pointId(from),
        target: pointId(to),
        direction,
        kind: entry.route.via === 'direct' ? 'direct' : 'relay',
        stale: entry.stale,
        step,
      })
    }
  }
  // 两个方向走同一段（例如两边都是直连）时，一条往一侧弯，一条往另一侧弯，不叠在一起。
  const uses = new Map<string, number>()
  for (const hop of hops) {
    const key = [hop.source, hop.target].sort().join('|')
    uses.set(key, (uses.get(key) ?? 0) + 1)
  }
  const seen = new Map<string, number>()
  return hops.map((hop) => {
    const key = [hop.source, hop.target].sort().join('|')
    const index = seen.get(key) ?? 0
    seen.set(key, index + 1)
    return { ...hop, index, siblings: uses.get(key) ?? 1, bend: bendAround(points, hop.source, hop.target) }
  })
}

/**
 * `relays` 是启用了 relay 的节点（取自节点列表）。路由里作为中间一跳出现过的节点也当作 relay 画：
 * 它可能刚被关掉，但路还是经它走的。
 */
export function buildTopology(
  matrix: RouteMatrix,
  relays: ReadonlySet<NodeId>,
  selection: Selection | null,
  stretch: number = STRETCH_X,
): TopologyShape {
  const known = new Set(matrix.nodes.map((node) => node.id))
  const relayIds = new Set([...relays].filter((id) => known.has(id)))
  for (const entry of matrix.entries) {
    if (entry.route.via === 'relay') for (const id of entry.route.relays) if (known.has(id)) relayIds.add(id)
  }
  const points = layout(matrix, relayIds, selection, stretch)

  const links = new Map<string, TopoLink>()
  /** 每一对节点之间有没有哪个方向是有路的。 */
  const connected = new Set<string>()
  const noneEntries = new Map<string, MatrixEntry[]>()

  for (const entry of matrix.entries) {
    const pair = segment(entry.from, entry.to)
    const path = hopsOf(entry.from, entry.to, entry.route)
    if (path === null) {
      noneEntries.set(pair.key, [...(noneEntries.get(pair.key) ?? []), entry])
      continue
    }
    // 经过一个不在这个网络里的节点（刚被删掉）的路画不出来，矩阵里照样有它。
    if (!path.every((id) => known.has(id))) continue
    connected.add(pair.key)
    const forward = entry.from === pair.source
    // 经过的 relay 按从 source 到 target 的顺序写，两个方向经同一串 relay 时是同一条线。
    const relaysOf =
      entry.route.via === 'relay' ? (forward ? [...entry.route.relays] : [...entry.route.relays].reverse()) : []
    const kind = entry.route.via === 'direct' ? 'direct' : 'relay'
    const key = `${pair.key}:${kind === 'direct' ? 'direct' : relaysOf.join('.')}`
    const link = links.get(key) ?? {
      id: `link:${key}`,
      source: pointId(pair.source),
      target: pointId(pair.target),
      kind,
      relays: relaysOf,
      forward: false,
      reverse: false,
      session: kind === 'relay' && relaysOf.every((id) => id === pair.source || id === pair.target),
      stale: true,
      rtt: null,
      directKind: null,
      transport: null,
      entries: [],
      legs: [],
      lanes: null,
      index: 0,
      siblings: 1,
      bend: 0,
    }
    if (forward) link.forward = true
    else link.reverse = true
    link.stale &&= entry.stale
    if (entry.rtt_ms !== null) link.rtt = link.rtt === null ? entry.rtt_ms : Math.min(link.rtt, entry.rtt_ms)
    link.directKind ??= entry.direct ?? null
    const leg = entry.relay_leg ?? null
    if (leg === 'tcp' || (leg !== null && link.transport === null)) link.transport = leg
    if (forward) link.entries.unshift(entry)
    else link.entries.push(entry)
    links.set(key, link)
  }

  // ice3proxy：一对节点之间有连接（在用的、空闲的、或者控制连接）时，另画一条。
  for (const entry of matrix.entries) {
    const report = entry.lanes ?? null
    if (report === null || entry.stale) continue
    if (!report.control && report.in_use === 0 && report.idle === 0) continue
    if (!known.has(entry.from) || !known.has(entry.to)) continue
    const pair = segment(entry.from, entry.to)
    const key = `${pair.key}:lane`
    const link = links.get(key) ?? {
      id: `link:${key}`,
      source: pointId(pair.source),
      target: pointId(pair.target),
      kind: 'lane' as const,
      relays: [],
      forward: false,
      reverse: false,
      session: false,
      stale: false,
      rtt: null,
      directKind: null,
      transport: 'tcp' as const,
      entries: [],
      legs: [],
      lanes: { control: false, in_use: 0, idle: 0 },
      index: 0,
      siblings: 1,
      bend: 0,
    }
    // 连接是两头共用的：两个方向都算。
    link.forward = true
    link.reverse = true
    const seen = link.lanes ?? { control: false, in_use: 0, idle: 0 }
    link.lanes = {
      control: seen.control || report.control,
      in_use: Math.max(seen.in_use, report.in_use),
      idle: Math.max(seen.idle, report.idle),
    }
    if (entry.from === pair.source) link.entries.unshift(entry)
    else link.entries.push(entry)
    links.set(key, link)
  }

  // 同一对节点之间有几条：直连在前，再是经 relay 的（按经过的 relay 排），ice3proxy 最后；几条时并排弯开。
  const byPair = new Map<string, TopoLink[]>()
  for (const link of [...links.values()].sort((a, b) => a.id.localeCompare(b.id))) {
    const pair = `${link.source}|${link.target}`
    byPair.set(pair, [...(byPair.get(pair) ?? []), link])
  }
  const cells = indexEntries(matrix.entries)
  const directRtt = (from: NodeId, to: NodeId): number | null => {
    const values = [cells.get(cellKey(from, to)), cells.get(cellKey(to, from))]
      .filter((entry) => entry?.route.via === 'direct' && entry.rtt_ms !== null)
      .map((entry) => entry?.rtt_ms ?? 0)
    return values.length === 0 ? null : Math.min(...values)
  }
  const legsOf = (link: TopoLink) => {
    if (link.kind !== 'relay' || link.session) return []
    const ends = [link.entries[0]?.from, link.entries[0]?.to].sort((a, b) => (a ?? 0) - (b ?? 0))
    const path = [ends[0] ?? 0, ...link.relays, ends[1] ?? 0]
    // 经的 relay 就是终点自己时（连对端自己的 relay），没有"自己到自己"那一段。
    return path
      .slice(1)
      .map((to, step) => {
        const from = path[step] ?? 0
        return { from, to, rtt: directRtt(from, to) }
      })
      .filter((leg) => leg.from !== leg.to)
  }
  const laidOut: TopoLink[] = []
  for (const group of byPair.values()) {
    const rank = { direct: 0, relay: 1, lane: 2 }
    group.sort((a, b) =>
      a.kind === b.kind ? a.relays.join('.').localeCompare(b.relays.join('.')) : rank[a.kind] - rank[b.kind],
    )
    group.forEach((link, index) =>
      laidOut.push({
        ...link,
        index,
        siblings: group.length,
        bend: bendAround(points, link.source, link.target),
        legs: legsOf(link),
      }),
    )
  }

  // 和总览的"不可达的节点对"一个口径：两端都在线、却没有路。一端离线时没有路是理所当然的，
  // 画成红线只会让图上满是红线（矩阵里那一格照样是"不可达"）。
  const online = new Set(matrix.nodes.filter((node) => node.online).map((node) => node.id))
  const unreachable: Unreachable[] = []
  for (const [key, entries] of noneEntries) {
    if (connected.has(key)) continue
    const first = entries[0]
    if (first === undefined) continue
    const pair = segment(first.from, first.to)
    if (!online.has(pair.source) || !online.has(pair.target)) continue
    unreachable.push({
      id: `none:${key}`,
      source: pointId(pair.source),
      target: pointId(pair.target),
      stale: entries.every((entry) => entry.stale),
      bend: bendAround(points, pointId(pair.source), pointId(pair.target)),
    })
  }

  const index = indexEntries(matrix.entries)
  const forward = selection === null ? null : (index.get(cellKey(selection.a, selection.b)) ?? null)
  const reverse = selection === null ? null : (index.get(cellKey(selection.b, selection.a)) ?? null)
  const highlight = highlightOf(forward, reverse, known, points)
  const involved = new Set<string>()
  if (selection !== null) {
    involved.add(pointId(selection.a))
    involved.add(pointId(selection.b))
    for (const hop of highlight) {
      involved.add(hop.source)
      involved.add(hop.target)
    }
  }

  return {
    points,
    links: laidOut.sort((a, b) => a.id.localeCompare(b.id)),
    unreachable: unreachable.sort((a, b) => a.id.localeCompare(b.id)),
    highlight,
    forward,
    reverse,
    involved,
    stretch,
  }
}

/** 布局的指纹：节点和 relay 的集合不变、拉宽的程度不变，点的位置就不变，画布不用重新缩放。 */
export function layoutSignature(shape: TopologyShape): string {
  const points = shape.points.map((point) => `${point.id}${point.relay ? 'r' : ''}`).join(',')
  return shape.stretch === STRETCH_X ? points : `${points}@${shape.stretch}`
}
