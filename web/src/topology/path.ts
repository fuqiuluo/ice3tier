import { type NodeId, type PathCandidate, type PathLeg, type PathSource } from '@/api/types'
import { type Tone } from '@/components/status'
import { t } from '@/i18n'
import { formatAge } from '@/lib/time'
import { UNMEASURED_US, unmeasuredOwnRelay } from '@/lib/unmeasured'

import {
  CLASS_TONE,
  classify,
  formatMicros,
  formatPermille,
  type RouteClass,
  routeDetail,
  routeDetailHint,
  routeText,
  textFor,
} from './route'

const p = t.path

/**
 * `GET /path` 一个方向的应答在界面上怎么说。纯函数。
 *
 * 四种来源分得很清楚：刚问到的（现在的结论）、最近一次上报（可能过时，标出多久之前）、
 * 不是对端（访问规则没有把它们连通）、没有数据。
 */

export type LegState = PathSource

export interface LegView {
  state: LegState
  /** 来源的短语和颜色。 */
  sourceLabel: string
  sourceTone: Tone
  sourceHint: string
  /** 路；没有数据时是 `null`。 */
  route: {
    cls: RouteClass
    tone: Tone
    text: string
    /** 经过的节点的名字，从发送方到接收方。 */
    hops: string[]
    /** 直连时对端的地址。 */
    addr: string | null
    /** 直连的方式、或者到第一个 relay 的传输；不知道时是 `null`。 */
    detail: string | null
    detailHint: string | null
  } | null
  /** 选路模式的名字（"默认"）和它的说明。只有现问到、发送方的版本会说时才有。 */
  mode: { label: string; hint: string } | null
  /** 发送方的路由层说的"为什么是这条"，是节点的原话，原样显示。有没有同 `mode`。 */
  reason: string | null
  rtt: string | null
  /** "6 秒前的数据"。刚问到的不写（是现在）；没有数据时是 `null`。 */
  age: string | null
  /** 这条路是什么时候换上的："5 分钟前"；现问到、启动以来没换过时是"启动以来没有切换"。 */
  since: string | null
  /** 换上它的原因：节点的原话，作为 `since` 下面的补充。 */
  sinceReason: string | null
}

const SOURCE_TONE: Record<PathSource, Tone> = {
  query: 'ok',
  report: 'idle',
  not_peers: 'warn',
  none: 'idle',
  unknown: 'idle',
}

export function describeLeg(leg: PathLeg, name: (id: NodeId) => string): LegView {
  // 更新的 controller 可能给出这里还不认识的来源。
  const state: LegState = leg.source in SOURCE_TONE ? leg.source : 'unknown'
  const route =
    leg.route === null
      ? null
      : {
          cls: classify(leg.route),
          tone: CLASS_TONE[classify(leg.route)],
          text: routeText(leg.route, name),
          hops: [
            leg.from.name,
            ...(leg.route.via === 'relay' ? leg.route.relays.map(name) : []),
            ...(leg.route.via === 'none' ? [] : [leg.to.name]),
          ],
          addr: leg.route.via === 'direct' ? leg.route.addr : null,
          detail: routeDetail(leg.route, leg),
          detailHint: routeDetailHint(leg.route, leg),
        }
  const age = leg.age_secs === null || state === 'query' ? null : p.age(formatAge(leg.age_secs))
  let since: string | null = null
  if (leg.since !== null) since = formatAge(leg.since.secs_ago)
  else if (state === 'query' && route !== null) since = p.sinceUnknown
  const sinceReason = leg.since === null || leg.since.reason === '' ? null : leg.since.reason
  const mode = leg.mode ?? null
  const reason = leg.reason ?? null
  return {
    state,
    mode: mode === null ? null : { label: textFor(p.mode, mode) ?? mode, hint: textFor(p.modeHint, mode) ?? '' },
    reason: reason === null || reason === '' ? null : reason,
    sourceLabel: textFor(p.source, state) ?? p.source.unknown,
    sourceTone: SOURCE_TONE[state],
    sourceHint: textFor(p.sourceHint, state) ?? p.sourceHint.unknown,
    route,
    rtt: leg.rtt_ms === null ? null : t.routes.rtt(leg.rtt_ms),
    age,
    since,
    sinceReason,
  }
}

export interface CandidateRow {
  key: string
  text: string
  tone: Tone
  /** 代价，写成毫秒。 */
  cost: string
  /** 每一段一句："laptop → hk：21.3 ms · ±0.40 ms · 丢包 0.2%"。 */
  legs: string[]
  /** 路径上负载最高的 relay 的带宽占用；直连写"—"。 */
  load: string
  current: boolean
}

export type CandidatesView =
  /** 不知道：不是现问到的，或者发送方的版本不会说。 */
  | { state: 'unknown' }
  /** 问到了，但它手上还没有任何测量值。 */
  | { state: 'empty' }
  | { state: 'list'; rows: CandidateRow[] }

/** 一个方向的候选路径表。按 controller 给的顺序（代价从低到高），现在走的那条标出来。 */
export function describeCandidates(leg: PathLeg, name: (id: NodeId) => string): CandidatesView {
  const candidates: PathCandidate[] | null = leg.candidates ?? null
  if (candidates === null) return { state: 'unknown' }
  if (candidates.length === 0) return { state: 'empty' }
  return {
    state: 'list',
    rows: candidates.map((candidate, index) => {
      const cls = classify(candidate.route)
      const unmeasured = unmeasuredOwnRelay(candidate.route, leg.from.id, candidate.cost_us)
      return {
        key: `${index}:${routeText(candidate.route, String)}`,
        text: routeText(candidate.route, name),
        tone: CLASS_TONE[cls],
        cost: unmeasured ? t.routes.unmeasured : formatMicros(candidate.cost_us),
        legs: candidate.legs.map((segment) =>
          unmeasured && segment.rtt_us >= UNMEASURED_US
            ? `${name(segment.from)} → ${name(segment.to)}：${t.routes.unmeasured}`
            : p.legLine(
                name(segment.from),
                name(segment.to),
                formatMicros(segment.rtt_us),
                formatMicros(segment.jitter_us),
                formatPermille(segment.loss_permille),
              ),
        ),
        load: candidate.route.via === 'relay' ? t.routes.percent(String(candidate.load_percent)) : '—',
        current: candidate.current,
      }
    }),
  }
}
