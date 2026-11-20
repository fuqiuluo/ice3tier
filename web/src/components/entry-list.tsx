import { ChevronRight, type LucideIcon } from 'lucide-react'
import { type ComponentProps, Fragment, type ReactNode } from 'react'
import { Link } from 'react-router'

import { type NetworkId, type NodeId } from '@/api/types'
import { NodeLink } from '@/components/node'
import { StatusText, type Tone } from '@/components/status'
import { Tr } from '@/components/table'
import { TrafficText } from '@/components/usage'
import { t } from '@/i18n'
import { cn } from '@/lib/utils'
import { networkPath } from '@/pages/networks/context'

/*
 * 「接入」下面两个列表（代理、端口转发）共用的格子，两页一个样子：
 * 名称（开关在名字前面）| 一端 | 另一端 | …… | 状态和一句原因 | 用量 | ⋯，每行一样高。
 */

/** 一行：每行一样高，两行字的格子刚好放下。 */
export function EntryRow({ className, ...props }: ComponentProps<typeof Tr>) {
  return <Tr className={cn('h-16', className)} {...props} />
}

/** 名称那一格：开关在前，名字在后。 */
export function NameCell({ toggle, children }: { toggle: ReactNode; children: ReactNode }) {
  return (
    <span className="flex min-w-0 items-center gap-3">
      {toggle}
      <span className="truncate font-medium">{children}</span>
    </span>
  )
}

/** 一端的节点：名字带在线圆点，点了去节点详情；下面一行小字放协议和地址。 */
export function NodeCell({
  network,
  node,
  online,
  children,
}: {
  network: NetworkId
  node: { id: NodeId; name: string }
  online: boolean | undefined
  children?: ReactNode
}) {
  return (
    <>
      <NodeLink network={network} node={node} online={online} />
      {children !== undefined && children !== null ? (
        <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 text-xs whitespace-nowrap text-muted-foreground">
          {children}
        </div>
      ) : null}
    </>
  )
}

/** 协议的小标签，放在地址前面：TCP、UDP、SOCKS5 + HTTP。 */
export function ProtocolTag({ children }: { children: ReactNode }) {
  return <span className="rounded-sm bg-muted px-1.5 leading-5">{children}</span>
}

/** 地址：等宽字。 */
export function Address({ children }: { children: ReactNode }) {
  return <span className="font-mono">{children}</span>
}

/**
 * 状态那一格：圆点和几个字，下面一行原因（带具体的节点名，后面可以跟一个链接）。
 * 原因太长时截断，悬停看全文；节点报的原话也在悬停里。正常、停用的不写原因。
 */
export function StatusCell({
  tone,
  label,
  detail,
  action,
  reported,
  narrow = false,
}: {
  tone: Tone
  label: string
  detail?: string | null
  action?: ReactNode
  reported?: string | null
  /** 表里列多的时候（代理开着 ice3proxy 那一列）：原因那一行窄一些，悬停看全文。 */
  narrow?: boolean
}) {
  const line = detail ?? reported ?? null
  const full = [detail, reported].filter((text) => text !== undefined && text !== null).join('\n')
  return (
    <>
      <StatusText tone={tone} className="text-[13px] whitespace-nowrap">
        {label}
      </StatusText>
      {line !== null ? (
        <div
          // 一行排成一块时（窄的地方）没有悬停：原因写全，折行。
          className={cn(
            'mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground @max-2xl/table:max-w-none @max-2xl/table:flex-wrap',
            narrow ? 'max-w-48' : 'max-w-64',
          )}
        >
          <span className="truncate @max-2xl/table:whitespace-normal" title={full}>
            {line}
          </span>
          {action}
        </div>
      ) : null}
    </>
  )
}

/** 原因后面的"查看策略"：策略不允许时，去策略页。 */
export function PoliciesLink({ network, children }: { network: NetworkId; children: ReactNode }) {
  return (
    <Link
      to={networkPath(network, 'access')}
      className="shrink-0 rounded-sm whitespace-nowrap text-primary underline-offset-4 hover:underline"
    >
      {children}
    </Link>
  )
}

/** 用量那一格：连接数（UDP 是会话数），下面上下行的字节数。没有上报时一道横线。 */
export function UsageCell({
  usage,
  udp = false,
}: {
  usage: { connections: number; up: number; down: number } | null
  udp?: boolean
}) {
  if (usage === null) return <span className="text-muted-foreground">—</span>
  return (
    <span className="text-xs whitespace-nowrap text-muted-foreground">
      <span className="block tabular">
        {udp ? t.listen.sessions(usage.connections) : t.listen.connections(usage.connections)}
      </span>
      <TrafficText up={usage.up} down={usage.down} tip={t.listen.trafficTip} />
    </span>
  )
}

export interface FlowStop {
  icon: LucideIcon
  label: string
}

/**
 * 列表还是空的时候：虚线框铺满标题下面剩下的地方；里面的东西靠上、居中：
 * 标题，一句话，一行图说明流量怎么走，再是按钮。
 */
export function FlowEmpty({
  stops,
  title,
  body,
  children,
}: {
  stops: readonly FlowStop[]
  title: string
  body: string
  children?: ReactNode
}) {
  return (
    <div className="flex flex-1 flex-col items-center rounded-xl border border-dashed px-6 pt-16 pb-12 text-center">
      <h2 className="text-base font-semibold">{title}</h2>
      <p className="mt-1.5 max-w-md text-[13px] leading-relaxed text-muted-foreground">{body}</p>
      <div aria-hidden className="mt-8 flex flex-wrap items-center justify-center gap-2">
        {stops.map(({ icon: Icon, label }, index) => (
          <Fragment key={label}>
            {index > 0 ? <ChevronRight className="size-4 shrink-0 text-faint" /> : null}
            <span className="inline-flex items-center gap-2 rounded-lg border bg-card px-3 py-2 text-[13px] whitespace-nowrap">
              <Icon className="size-4 text-muted-foreground" />
              {label}
            </span>
          </Fragment>
        ))}
      </div>
      <div className="mt-8 flex w-full flex-col items-center gap-5">{children}</div>
    </div>
  )
}
