import { Check } from 'lucide-react'
import { Link } from 'react-router'

import { type Network, type Node } from '@/api/types'
import { nodePath } from '@/lib/nodes'
import { Notice } from '@/components/notice'
import { Page, PageHeader } from '@/components/page'
import { OnlineDot } from '@/components/status'
import { t } from '@/i18n'
import { cn } from '@/lib/utils'
import { AddNodeFlow } from '@/pages/nodes/AddNodeFlow'

const g = t.overview.guide

type StepState = 'done' | 'current' | 'upcoming'

/**
 * 引导走到哪了：三个名字横着排成一行，做完的打勾，正在做的加粗。
 * 不编号：下面添加节点的流程自己有 1、2、3，两套编号叠在一起分不清。
 */
function Progress({ current }: { current: number }) {
  const titles = [g.step1, g.step2, g.step3]
  return (
    <ol className="flex flex-wrap items-center gap-x-3 gap-y-2 text-sm">
      {titles.map((title, position) => {
        const index = position + 1
        const state: StepState = index < current ? 'done' : index === current ? 'current' : 'upcoming'
        return (
          <li key={title} aria-current={state === 'current' ? 'step' : undefined} className="flex items-center gap-x-3">
            {position > 0 ? <span aria-hidden className="h-px w-4 bg-border-strong @xl:w-8" /> : null}
            <span className="flex items-center gap-2">
              <span aria-hidden className="flex size-4 items-center justify-center">
                {state === 'done' ? (
                  <span className="flex size-4 items-center justify-center rounded-full bg-ok-soft text-ok">
                    <Check className="size-3" style={{ strokeWidth: 3 }} />
                  </span>
                ) : (
                  <span
                    className={cn(
                      'size-2 rounded-full',
                      state === 'current' ? 'bg-primary ring-4 ring-primary/20' : 'bg-border-strong',
                    )}
                  />
                )}
              </span>
              <span className={state === 'current' ? 'font-semibold' : 'text-muted-foreground'}>{title}</span>
              {state === 'done' ? <span className="sr-only">{g.done}</span> : null}
              {state === 'current' ? <span className="sr-only">{g.current}</span> : null}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

/** 画布上的一个节点：节点没来时是虚线框，来了之后变成实卡。 */
function Slot({
  network,
  label,
  node,
  waiting,
}: {
  network: Network
  label: string
  node: Node | undefined
  waiting: string
}) {
  const box = 'flex min-h-24 w-full max-w-60 flex-col justify-center rounded-lg px-4 py-3'
  if (node === undefined) {
    return (
      <div className={cn(box, 'items-center border border-dashed border-border-strong text-center')}>
        <span className="text-xs text-muted-foreground">{label}</span>
        <span className="mt-1 text-[13px] text-muted-foreground">{waiting}</span>
      </div>
    )
  }
  return (
    <Link
      to={nodePath(network.id, node.id)}
      className={cn(
        box,
        'animate-rise border border-border-strong bg-card transition-colors hover:border-foreground/30',
      )}
      data-testid={`guide-node-${node.name}`}
    >
      <span className="flex items-center gap-2 text-sm font-semibold">
        <OnlineDot online={node.online} />
        {node.name}
      </span>
      <span className="mt-0.5 font-mono text-xs text-muted-foreground">
        {node.virtual_ip} · {node.platform}
      </span>
      <span className="mt-1 text-xs text-muted-foreground">{node.online ? g.joinedOnline : g.joinedOffline}</span>
    </Link>
  )
}

/**
 * 节点不足两个时，总览页就是引导：不另做一个全屏向导。
 * 左边是添加节点的流程，宽度到一行命令放得下为止，不跟着窗口拉长；右边的画布占掉剩下的地方（窄的时候排在流程下面），
 * 上面是这两个节点的实况：没来的是虚线框，来了变成实卡。画布宽的时候两个节点横着排，窄的时候竖着排。
 * 用户走开再回来它还在原地，进度由数据决定，不需要记"做到第几步"；用命令行加的节点这里一样会发现。
 */
export function GettingStarted({ network, nodes }: { network: Network; nodes: readonly Node[] }) {
  const ordered = [...nodes].sort((a, b) => a.created_at - b.created_at || a.id - b.id)
  const [first, second] = ordered
  const current = first === undefined ? 1 : 2

  return (
    <Page fill>
      <PageHeader title={g.title} description={g.step3Body} />
      {/* 窄的时候两块上下排：流程在上，实况在下。 */}
      <div className="grid flex-1 grid-cols-1 gap-8 @4xl:grid-cols-[minmax(0,54rem)_minmax(16rem,1fr)] @4xl:gap-10">
        <div className="min-w-0 space-y-7">
          <Progress current={current} />
          {/* 换了一个节点就是一份新的流程：上一个节点的令牌不留在这里。 */}
          <AddNodeFlow
            key={current}
            network={network}
            intro={current === 2 ? <Notice>{g.step2Tip(t.capability.relay.full)}</Notice> : undefined}
          />
        </div>

        <section
          aria-label={g.live}
          className="@container flex min-h-56 flex-col rounded-xl bg-sidebar p-5 @4xl:min-h-72"
        >
          <h2 className="text-xs font-medium text-muted-foreground">{g.live}</h2>
          <div aria-live="polite" className="flex flex-1 flex-col items-center justify-center py-6 @2xl:flex-row">
            <Slot network={network} label={g.slotFirst} node={first} waiting={g.waiting} />
            <span
              aria-hidden
              className="h-8 w-0 shrink-0 border-l border-dashed border-border-strong @2xl:h-0 @2xl:w-20 @2xl:border-t @2xl:border-l-0"
            />
            <Slot
              network={network}
              label={g.slotSecond}
              node={second}
              waiting={first === undefined ? g.notYet : g.waiting}
            />
          </div>
        </section>
      </div>
    </Page>
  )
}
