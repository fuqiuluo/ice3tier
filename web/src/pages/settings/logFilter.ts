import { type LogEntry, type LogQuery, type LogRef, type LogRefKind, type NetworkId } from '@/api/types'
import { t } from '@/i18n'
import { formatList } from '@/lib/format'
import { networkPath } from '@/pages/networks/context'

/**
 * 操作记录的筛选。网络、操作和对象交给 controller 筛（`GET /log` 的 `network`、`action`、`ref`），
 * 所以翻页拿到的每一页都是符合条件的；搜索只在已经取回来的记录里找说明文字，controller 没有全文搜索。
 *
 * 筛选条件写在地址里（`?network=1&action=node&ref=node:3&q=…`），浏览器的前进后退能还原，链接也能分享。
 */
export interface LogFilter {
  network: NetworkId | null
  /** 一种操作（`credential.revoke`），或者一类操作的前缀（`node` 包括 `node.relay.enable`）。 */
  action: string | null
  ref: LogRef | null
  search: string
}

export const EMPTY_LOG_FILTER: LogFilter = { network: null, action: null, ref: null, search: '' }

/** `credential` 只在 0.1.15 之前的记录里有；监听器的记录在 0.1.15 迁移成了 `proxy`。 */
export const LOG_REF_KINDS = ['network', 'node', 'group', 'token', 'rule', 'credential', 'proxy', 'forward'] as const

export function isRefKind(kind: string): kind is LogRefKind {
  return (LOG_REF_KINDS as readonly string[]).includes(kind)
}

/** `node:3` 这样的写法，和 controller 认的一样。种类不认识、编号不是正整数时返回 `null`。 */
export function parseRef(text: string): LogRef | null {
  const match = /^([a-z_]+):(\d{1,9})$/.exec(text.trim())
  if (match === null) return null
  const [, kind = '', id = ''] = match
  if (!isRefKind(kind) || Number(id) < 1) return null
  return { kind, id: Number(id) }
}

export function formatRef(ref: LogRef): string {
  return `${ref.kind}:${ref.id}`
}

/** 地址里的筛选条件。写法不对的条件当作没写，而不是报错：链接可能是手改过的。 */
export function parseLogFilter(params: URLSearchParams): LogFilter {
  const network = Number(params.get('network'))
  const action = params.get('action')?.trim() ?? ''
  return {
    network: Number.isInteger(network) && network > 0 ? network : null,
    action: /^[a-z_]+(\.[a-z_]+)*$/.test(action) ? action : null,
    ref: parseRef(params.get('ref') ?? ''),
    search: params.get('q') ?? '',
  }
}

export function logFilterToParams(filter: LogFilter): URLSearchParams {
  const params = new URLSearchParams()
  if (filter.network !== null) params.set('network', String(filter.network))
  if (filter.action !== null) params.set('action', filter.action)
  if (filter.ref !== null) params.set('ref', formatRef(filter.ref))
  if (filter.search !== '') params.set('q', filter.search)
  return params
}

/** 交给 controller 的那几个条件。搜索不在里面。 */
export function logFilterToQuery(filter: LogFilter): Omit<LogQuery, 'before' | 'limit'> {
  return {
    network: filter.network ?? undefined,
    action: filter.action ?? undefined,
    ref: filter.ref === null ? undefined : formatRef(filter.ref),
  }
}

/** 有没有交给 controller 的条件。 */
export function hasServerFilter(filter: LogFilter): boolean {
  return filter.network !== null || filter.action !== null || filter.ref !== null
}

export function isFiltered(filter: LogFilter): boolean {
  return hasServerFilter(filter) || filter.search.trim() !== ''
}

/**
 * 一种操作在界面上的名字，按当前的语言。比界面新的 controller 记下的、这里不认识的操作返回 `null`，
 * 调用的地方原样写操作的代码。
 */
export function logActionLabel(action: string): string | null {
  return t.settings.log.actions[action] ?? null
}

/** 参数里的一个数（编号、个数）：非负的整数才算。 */
function paramNumber(params: Record<string, unknown>, key: string): number | null {
  const value = params[key]
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null
}

function paramText(params: Record<string, unknown>, key: string): string | null {
  const value = params[key]
  return typeof value === 'string' && value !== '' ? value : null
}

/**
 * 只用 `action` 和 `params` 就写得出整句话的操作（MCP 令牌的几种），按当前的语言写。
 * 这几种操作说的东西（MCP 令牌）不在 `refs` 里，光写操作的名字看不出是哪一个；参数里有它的编号、名字、权限。
 *
 * 别的操作、参数不全的记录返回 `null`，调用的地方写操作的名字。
 */
export function logSentence(entry: LogEntry): string | null {
  const params = entry.params ?? {}
  const say = t.settings.log.sentences
  switch (entry.action) {
    case 'mcp.token.create': {
      const id = paramNumber(params, 'token')
      const name = paramText(params, 'name')
      const scopes = params.scopes
      if (id === null || name === null || !Array.isArray(scopes)) return null
      // 只限一个网络的写网络当时的名字；名字没有记下来时写编号。
      const network = paramNumber(params, 'network')
      const limit = network === null ? null : (paramText(params, 'network_name') ?? `#${network}`)
      const codes = scopes.filter((scope): scope is string => typeof scope === 'string')
      return say.mcpTokenCreate(id, name, formatList(codes), limit)
    }
    case 'mcp.token.revoke': {
      const id = paramNumber(params, 'token')
      const name = paramText(params, 'name')
      return id === null || name === null ? null : say.mcpTokenRevoke(id, name)
    }
    case 'mcp.key.rotate': {
      const revoked = paramNumber(params, 'revoked')
      return revoked === null ? null : say.mcpKeyRotate(revoked)
    }
    default:
      return null
  }
}

/**
 * 一条记录是谁做的，写成一小段：经 MCP 做的写"MCP 令牌"加令牌的名字；比界面新的 controller 报来的别的种类，
 * 原样写种类和名字。管理员自己做的、节点引起的、controller 自己做的没有这一项，返回 `null`。
 */
export function actorLabel(entry: LogEntry): string | null {
  const actor = entry.actor
  if (actor === undefined || actor === null) return null
  return actor.kind === 'mcp' ? t.settings.log.actor.mcp(actor.name) : `${actor.kind} ${actor.name}`
}

/**
 * 界面给一条记录写的字之外，搜索还要找得到的：做这件事的令牌的 jti，和这条记录说的那个 MCP 令牌的 jti。
 * 名字可以重复，jti 不会；它在界面上只在悬停时出现，照样要能搜到。
 */
export function logJtis(entry: LogEntry): string[] {
  const issued = paramText(entry.params ?? {}, 'jti')
  return [entry.actor?.jti, issued].filter((jti): jti is string => typeof jti === 'string' && jti !== '')
}

/** 在取回来的记录里找：界面写的那些字（操作的名字、对象）、操作的代码和 controller 的原话，不分大小写。 */
export function matchesSearch(entry: LogEntry, search: string, labels: string): boolean {
  const needle = search.trim().toLowerCase()
  if (needle === '') return true
  return `${labels} ${entry.action} ${entry.detail}`.toLowerCase().includes(needle)
}

/** 操作的名字可以是 `credential.revoke`；它属于哪一类（`credential`），给筛选的下拉分组用。 */
export function actionKind(action: string): string {
  return action.split('.')[0] ?? action
}

/**
 * 记录里提到的一样东西，点了去哪里。网络里的东西要知道是哪个网络：记录自己的 `network`。
 * 列表页带上 `focus`，打开时那一行亮出来；东西已经删掉了的，页面上说一句。
 * 不认识的种类、和网络无关却提到网络里的东西时返回 `null`，界面上不做成链接。
 */
export function refTarget(ref: LogRef, network: NetworkId | null): string | null {
  const kind = ref.kind
  if (!isRefKind(kind)) return null
  if (kind === 'network') return networkPath(ref.id, 'network')
  if (network === null) return null
  switch (kind) {
    case 'node':
      return networkPath(network, `nodes/${ref.id}`)
    case 'group':
      return `${networkPath(network, 'groups')}?focus=${ref.id}`
    case 'rule':
      return `${networkPath(network, 'access')}?rule=${ref.id}`
    case 'token':
      // 令牌没有自己的页面了（在「添加节点」里生成、吊销），记录里只写它是哪一个。
      return null
    case 'credential':
      // 凭据没有了：以前的记录点过去是代理页（认证现在在代理上）。
      return networkPath(network, 'proxies')
    case 'proxy':
      return networkPath(network, 'proxies')
    case 'forward':
      return `${networkPath(network, 'forwards')}?focus=${ref.id}`
  }
}

/** 一样东西的操作记录在哪里看：设置里的操作记录，按这样东西筛。 */
export function logPathFor(ref: LogRef, network?: NetworkId): string {
  const params = logFilterToParams({ ...EMPTY_LOG_FILTER, network: network ?? null, ref })
  return `/settings/log?${params.toString()}`
}
