import { useQuery } from '@tanstack/react-query'
import { ChevronRight } from 'lucide-react'
import { type ReactNode, useState } from 'react'
import { Link } from 'react-router'

import { q } from '@/api/queries'
import { type Network, type Node } from '@/api/types'
import { StatusDot } from '@/components/status'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { t } from '@/i18n'
import { nodePath } from '@/lib/nodes'
import { proxyStatus } from '@/lib/proxy'
import { quotaView } from '@/lib/usage'
import { exitHealthView } from '@/lib/exitView'
import { forwardLabel, forwardStatusView } from '@/pages/forwards/status'
import { networkPath } from '@/pages/networks/context'
import { AddNodeDialog } from '@/pages/nodes/AddNodeDialog'

const o = t.overview

interface AttentionItem {
  key: string
  text: string
  action: ReactNode
  detail?: ReactNode
}

/** 一条"需要处理"后面的那个动作：安静的文字按钮，带一个向右的小箭头。 */
function GoLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Button asChild size="sm" variant="ghost" className="text-muted-foreground hover:text-foreground">
      <Link to={to}>
        {children}
        <ChevronRight aria-hidden />
      </Link>
    </Button>
  )
}

/** 没有 relay 时两端互不可达：这是唯一需要用户再做事的情况，展开两种做法。 */
function RelayFix({ network, onAddNode }: { network: Network; onAddNode: () => void }) {
  return (
    <div className="mt-3 space-y-2 border-l-2 pl-4 text-[13px]">
      <ul className="list-disc space-y-1 pl-4 text-muted-foreground">
        <li>{o.fix.optionA}</li>
        <li>{o.fix.optionB}</li>
      </ul>
      <div className="flex gap-2 pt-1">
        <Button asChild size="sm">
          <Link to={networkPath(network.id, 'nodes')}>{o.fix.goNodes}</Link>
        </Button>
        <Button size="sm" onClick={onAddNode}>
          {o.fix.addNode}
        </Button>
      </div>
    </div>
  )
}

/**
 * 总览右上角的状态：一句话（一切正常、所有节点离线、几个问题），浮在访问地图上。
 * 有问题时点开是那几件事，每件事后面一个去处理它的链接。
 */
export function AttentionChip({ network, nodes }: { network: Network; nodes: readonly Node[] }) {
  const [adding, setAdding] = useState(false)
  const [fixOpen, setFixOpen] = useState<string | null>(null)
  const overview = useQuery(q.overview(network.id))
  const forwards = useQuery(q.forwards(network.id))
  const exits = useQuery(q.exits(network.id))
  const proxies = useQuery(q.proxies(network.id))

  const data = overview.data
  if (data === undefined) return null

  const all = nodes
  const attention: AttentionItem[] = []

  for (const pair of data.unreachable_pairs) {
    const key = `pair:${pair.a.id}:${pair.b.id}`
    if (data.relays === 0) {
      attention.push({
        key,
        text: o.unreachableNoRelay(pair.a.name, pair.b.name),
        action: (
          <Button
            size="sm"
            variant="ghost"
            className="text-muted-foreground hover:text-foreground"
            aria-expanded={fixOpen === key}
            onClick={() => setFixOpen(fixOpen === key ? null : key)}
          >
            {fixOpen === key ? o.hideFix : o.howToFix}
          </Button>
        ),
        detail: fixOpen === key ? <RelayFix network={network} onAddNode={() => setAdding(true)} /> : undefined,
      })
    } else {
      attention.push({
        key,
        text: o.unreachableWithRelay(pair.a.name, pair.b.name),
        action: <GoLink to={`${nodePath(network.id, pair.a.id)}?tab=routes`}>{o.viewRoutes}</GoLink>,
      })
    }
  }
  for (const node of all) {
    if (node.online) continue
    if (node.relay !== null || node.exit !== null) {
      attention.push({
        key: `offline:${node.id}`,
        text: node.relay !== null ? o.relayOffline(node.name) : o.exitOffline(node.name),
        action: <GoLink to={nodePath(network.id, node.id)}>{o.viewNode}</GoLink>,
      })
    }
  }
  for (const exit of exits.data ?? []) {
    const quota = exit.usage?.quota
    const view = quota === undefined || quota === null ? null : quotaView(quota)
    const health = exitHealthView(exit)
    const text =
      view?.exhausted === true
        ? o.quotaExhausted(exit.node.name)
        : view?.nearly === true
          ? o.quotaNearly(exit.node.name, view.percent ?? 0)
          : exit.health === 'degraded'
            ? o.exitDegraded(exit.node.name, health.label)
            : null
    if (text === null) continue
    attention.push({
      key: `exit:${exit.node.id}`,
      text,
      action: <GoLink to={`${nodePath(network.id, exit.node.id)}?tab=exit`}>{o.view}</GoLink>,
    })
  }
  for (const proxy of proxies.data ?? []) {
    const status = proxyStatus(proxy)
    if (!status.needsAttention) continue
    attention.push({
      key: `proxy:${proxy.id}`,
      text: o.proxyBroken(proxy.name, t.proxies.status[status.code]),
      action: <GoLink to={networkPath(network.id, 'proxies')}>{o.view}</GoLink>,
    })
  }
  for (const forward of forwards.data ?? []) {
    const view = forwardStatusView(forward, all)
    if (!view.needsAttention) continue
    attention.push({
      key: `forward:${forward.id}`,
      text: o.forwardBlocked(forwardLabel(forward), view.label),
      action: (
        <GoLink
          to={
            view.linkToRules
              ? networkPath(network.id, 'access')
              : `${networkPath(network.id, 'forwards')}?focus=${forward.id}`
          }
        >
          {view.linkToRules ? o.viewRules : o.view}
        </GoLink>
      ),
    })
  }

  const healthy = attention.length === 0
  const allOffline = data.online === 0
  const tone = !healthy ? 'warn' : allOffline ? 'idle' : 'ok'
  const text = !healthy ? o.statusIssues(attention.length) : allOffline ? o.statusAllOffline : o.statusOk

  const chip =
    'inline-flex h-8 items-center gap-2 rounded-full bg-card px-3 text-[13px] font-medium shadow-nav transition-colors'

  return (
    <>
      {healthy ? (
        <span className={chip}>
          <StatusDot tone={tone} />
          <span data-testid="overview-status">{text}</span>
        </span>
      ) : (
        <Popover>
          <PopoverTrigger
            className={`${chip} outline-none hover:bg-card/80 focus-visible:ring-2 focus-visible:ring-ring`}
          >
            <StatusDot tone={tone} />
            <span data-testid="overview-status">{text}</span>
            <ChevronRight className="size-3.5 text-faint" aria-hidden />
          </PopoverTrigger>
          <PopoverContent align="end" className="w-[440px] max-w-[calc(100vw-1.5rem)] p-1.5">
            <h2 className="px-2.5 pt-1.5 pb-1 text-xs font-medium text-faint">{o.attention}</h2>
            <ul>
              {attention.map((item) => (
                <li key={item.key} className="rounded-lg px-2.5 py-1.5">
                  <div className="flex items-center justify-between gap-4">
                    <p className="flex min-w-0 items-baseline gap-2.5 text-[13px]">
                      <StatusDot tone="warn" className="relative -top-px" />
                      <span className="min-w-0">{item.text}</span>
                    </p>
                    <div className="shrink-0">{item.action}</div>
                  </div>
                  {item.detail !== undefined ? <div className="pl-4.5">{item.detail}</div> : null}
                </li>
              ))}
            </ul>
          </PopoverContent>
        </Popover>
      )}
      <AddNodeDialog network={network} open={adding} onClose={() => setAdding(false)} />
    </>
  )
}
