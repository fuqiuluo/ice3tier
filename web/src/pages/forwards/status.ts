import { type Forward, type ForwardStatus, type Node } from '@/api/types'
import { type Tone } from '@/components/status'
import { t } from '@/i18n'
import { listenView, type ListenView } from '@/lib/listenState'
import { nodeName } from '@/lib/nodes'

export interface ForwardStatusView {
  tone: Tone
  /** 短的：圆点旁边的那几个字。 */
  label: string
  /** 原因，先说对象和状态。停用时就是那几个字：列表里不另起一行说它。 */
  detail: string
  /** 这种状态要用户去做点什么。 */
  needsAttention: boolean
  /** 去访问规则页能解决。 */
  linkToRules: boolean
  /** 监听一侧的情况：实际的地址（端口写 0 时是节点挑的）、连接数和流量。没有下发时是 `null`。 */
  listen: ListenView | null
}

const s = t.forwards.status

/**
 * 一条转发的状态怎么写：状态、原因、下一步。原因里带具体的节点名。
 *
 * 先看 controller 知道的（`status`）；已经下发、两端都在线时再看监听节点报的监听情况（`listen`）：
 * "端口被占用""没有绑上"在那里。"目标连不上"节点还不上报，所以这里没有。
 */
export function forwardStatusView(
  forward: Forward,
  nodes: readonly Pick<Node, 'id' | 'name' | 'online'>[],
): ForwardStatusView {
  const listenName = nodeName(nodes, forward.listen_node)
  const target = nodeName(nodes, forward.target_node)
  const status: ForwardStatus = forward.status
  const base = { needsAttention: false, linkToRules: false, listen: null }
  switch (status) {
    case 'active': {
      const listen = listenView(forward.listen, { node: listenName, bind: forward.bind, online: true })
      if (listen.needsAttention || forward.listen === null || listen.tone === 'idle') {
        return {
          ...base,
          tone: listen.tone,
          label: listen.label,
          detail: listen.detail ?? s.activeDetail,
          needsAttention: listen.needsAttention,
          listen,
        }
      }
      return { ...base, tone: 'ok', label: s.active, detail: s.activeDetail, listen }
    }
    case 'disabled':
      return { ...base, tone: 'idle', label: s.disabled, detail: s.disabled }
    case 'forward_target_off':
      return {
        ...base,
        tone: 'warn',
        label: s.targetOff,
        detail: s.targetOffDetail(target),
        needsAttention: true,
      }
    case 'target_not_declared':
      return {
        ...base,
        tone: 'warn',
        label: s.targetNotDeclared,
        detail: s.targetNotDeclaredDetail(target),
        needsAttention: true,
      }
    case 'access_denied':
      return {
        ...base,
        tone: 'danger',
        label: s.accessDenied,
        detail: s.accessDeniedDetail(listenName, target),
        needsAttention: true,
        linkToRules: true,
      }
    case 'target_not_allowed':
      return {
        ...base,
        tone: 'danger',
        label: s.targetNotAllowed,
        detail: s.targetNotAllowedDetail,
        needsAttention: true,
      }
    case 'listener_offline':
      return { ...base, tone: 'idle', label: s.listenerOffline, detail: s.listenerOfflineDetail(listenName) }
    case 'target_offline':
      return {
        ...base,
        tone: 'idle',
        label: s.targetOffline,
        detail: s.targetOfflineDetail(target),
        listen: listenView(forward.listen, { node: listenName, bind: forward.bind, online: true }),
      }
  }
  // 比界面新的 controller 报的、这里还不认识的状态。
  return { ...base, tone: 'idle', label: s.unknown, detail: s.unknown }
}

/** 转发在文字里的叫法：有名字用名字，没有就写监听地址。 */
export function forwardLabel(forward: Pick<Forward, 'name' | 'bind'>): string {
  return forward.name.trim() === '' ? forward.bind : forward.name
}

/** 访问地址：节点挑了端口的用实际的那个，否则是配置里写的。 */
export function forwardAddress(forward: Pick<Forward, 'bind'>, view: ForwardStatusView): string {
  return view.listen?.local ?? forward.bind
}
