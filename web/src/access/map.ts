import { type AccessGraph, type Direction, type GroupId, type GroupRef, type Rule } from '@/api/types'

/**
 * 总览的访问地图要画的东西。纯函数，不依赖画图的库，方便测试。
 *
 * 三列：左边是看的那一个（一个节点，或者一个分组）；中间是和它有关的规则，一条一个胶囊；
 * 右边是规则另一头的分组，写着有几个节点。左边连到每个胶囊，每个胶囊连到它另一头的分组。
 *
 * 一条规则和"它"有关：规则的一头是它所在的分组。节点在它自己的每个分组里，也总在 All 里。
 * 流向从"它"这边看：`out` 是它能访问对面，`in` 是对面能访问它，`both` 是双向。
 */

export type MapFlow = 'out' | 'in' | 'both'

export interface MapRule {
  /** 图上的编号。 */
  id: string
  rule: Rule
  flow: MapFlow
  /** 规则另一头的分组。 */
  other: GroupRef
}

export interface MapTarget {
  id: string
  group: GroupRef
  /** 分组里有几个节点。 */
  members: number
}

export interface AccessMap {
  rules: MapRule[]
  targets: MapTarget[]
}

export const mapTargetId = (group: GroupId): string => `target:${group}`

/** `groups` 是"它"所在的分组的编号：节点的分组加上 All（`nodeGroupIds`），或者只是那一个分组。 */
export function buildAccessMap(graph: AccessGraph, groups: ReadonlySet<GroupId>): AccessMap {
  const rules: MapRule[] = []
  for (const rule of graph.rules) {
    const fromHere = groups.has(rule.src.id)
    const toHere = groups.has(rule.dst.id)
    if (!fromHere && !toHere) continue
    const other = fromHere ? rule.dst : rule.src
    const flow: MapFlow = rule.direction === 'both' ? 'both' : fromHere ? 'out' : 'in'
    rules.push({ id: `rule:${rule.id}`, rule, flow, other })
  }
  // 启用的在前；同样启用或停用的，保持规则列表的顺序。
  rules.sort((a, b) => Number(b.rule.enabled) - Number(a.rule.enabled))

  const members = new Map(graph.groups.map((group) => [group.id, group.nodes.length]))
  const targets: MapTarget[] = []
  for (const entry of rules) {
    if (targets.some((target) => target.group.id === entry.other.id)) continue
    targets.push({ id: mapTargetId(entry.other.id), group: entry.other, members: members.get(entry.other.id) ?? 0 })
  }
  return { rules, targets }
}

/** 画图用的尺寸。胶囊的宽度按名字估一个，画的时候就用这个宽度，估短了名字截断。 */
export const MAP_SIZE = {
  subject: { width: 260, height: 64 },
  target: { width: 240, height: 64 },
  pill: { height: 36, min: 150, max: 300 },
  gapY: { pill: 16, target: 18 },
  /** 列与列之间留的横向距离。 */
  gapX: 150,
} as const

/** 估一段文字有多宽（13 像素的字）：汉字一个字宽，其余大约一半多。 */
function textWidth(text: string): number {
  let width = 0
  for (const char of text) width += /[⺀-￿]/u.test(char) ? 13 : 7.4
  return width
}

/** 胶囊的宽度：圆点、名字、分隔线、方向（双向、单向），加上左右的留白。 */
export function pillWidth(name: string, directionLabel: string): number {
  const width = Math.ceil(12 + 8 + 8 + textWidth(name) + 10 + 1 + 10 + textWidth(directionLabel) + 12)
  return Math.min(MAP_SIZE.pill.max, Math.max(MAP_SIZE.pill.min, width))
}

export interface Placed {
  x: number
  y: number
  width: number
}

export interface MapLayout {
  subject: Placed
  pills: Map<string, Placed>
  targets: Map<string, Placed>
}

/**
 * 窄的地方（手机）另一种排法用的尺寸：三列横着放不下，改成竖着排——看的那一个在最上面、和画布一样宽，
 * 下面一个目标分组一段：左边是连着它的胶囊，右边是这个分组；从上面那一块的左下角垂下一根线，分到每个胶囊。
 */
export const NARROW_MAP = {
  /** 垂下来的那根线离左边多远。 */
  trunk: 14,
  /** 胶囊从这里开始。 */
  indent: 30,
  /** 胶囊和分组之间。 */
  gapX: 22,
  /** 上面那一块和第一段之间。 */
  top: 26,
  /** 胶囊那一列占剩下宽度的几成，其余是分组。 */
  pillShare: 0.52,
  target: { height: 56 },
  gapY: { pill: 10, group: 16 },
} as const

export interface NarrowMapLayout extends MapLayout {
  /** 整张图有多高：画布要知道能往下拖多远。 */
  height: number
  targetWidth: number
}

/** 窄的排法里每一块左上角的位置。`width` 是整张图的宽度（画布的宽度减去两边的留白）。 */
export function layoutAccessMapNarrow(map: AccessMap, width: number): NarrowMapLayout {
  const { indent, gapX, top, pillShare, target, gapY } = NARROW_MAP
  const pillHeight = MAP_SIZE.pill.height
  const rest = Math.max(0, width - indent - gapX)
  const pillWidth = Math.round(rest * pillShare)
  const targetWidth = rest - pillWidth
  const targetX = indent + pillWidth + gapX

  const pills = new Map<string, Placed>()
  const targets = new Map<string, Placed>()
  let y = MAP_SIZE.subject.height + top
  for (const entry of map.targets) {
    const rules = map.rules.filter((rule) => rule.other.id === entry.group.id)
    const pillsHeight = rules.length * pillHeight + Math.max(0, rules.length - 1) * gapY.pill
    const block = Math.max(target.height, pillsHeight)
    rules.forEach((rule, index) => {
      pills.set(rule.id, {
        x: indent,
        y: y + (block - pillsHeight) / 2 + index * (pillHeight + gapY.pill),
        width: pillWidth,
      })
    })
    targets.set(entry.id, { x: targetX, y: y + (block - target.height) / 2, width: targetWidth })
    y += block + gapY.group
  }
  return {
    subject: { x: 0, y: 0, width },
    pills,
    targets,
    height: map.targets.length === 0 ? MAP_SIZE.subject.height : y - gapY.group,
    targetWidth,
  }
}

/** 一列里的东西竖着排开，整体以 0 为中心。 */
function column(count: number, height: number, gap: number): number[] {
  const step = height + gap
  const top = -((count - 1) * step) / 2 - height / 2
  return Array.from({ length: count }, (_, index) => top + index * step)
}

/** 每一块左上角的位置（画图的库按左上角放）。 */
export function layoutAccessMap(map: AccessMap, directionLabel: (direction: Direction) => string): MapLayout {
  const { subject, target, pill, gapY, gapX } = MAP_SIZE
  const widths = new Map(
    map.rules.map((entry) => [entry.id, pillWidth(entry.rule.name, directionLabel(entry.rule.direction))]),
  )
  const pillColumn = Math.max(MAP_SIZE.pill.min, ...widths.values())
  const pillCenter = subject.width + gapX + pillColumn / 2
  const targetX = subject.width + gapX + pillColumn + gapX

  const pillYs = column(map.rules.length, pill.height, gapY.pill)
  const targetYs = column(map.targets.length, target.height, gapY.target)

  return {
    subject: { x: 0, y: -subject.height / 2, width: subject.width },
    pills: new Map(
      map.rules.map((entry, index) => {
        const width = widths.get(entry.id) ?? MAP_SIZE.pill.min
        return [entry.id, { x: pillCenter - width / 2, y: pillYs[index] ?? 0, width }]
      }),
    ),
    targets: new Map(
      map.targets.map((entry, index) => [entry.id, { x: targetX, y: targetYs[index] ?? 0, width: target.width }]),
    ),
  }
}
