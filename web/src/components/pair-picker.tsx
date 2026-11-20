import { ArrowLeftRight, X } from 'lucide-react'

import { type Node, type NodeId } from '@/api/types'
import { NodeSelect } from '@/components/node'
import { Button } from '@/components/ui/button'
import { Tooltip } from '@/components/ui/tooltip'
import { type Pair } from '@/topology/pair'

interface PairPickerProps {
  nodes: readonly Node[]
  pair: Pair
  onChange: (pair: Pair) => void
  labels: { a: string; b: string; swap: string }
  /** 给了就多一个"不再看这一对"的按钮。 */
  clearLabel?: string
}

/** 选两个节点：A、B 和中间的交换按钮。拓扑和路径诊断共用，选中的那一对写在地址里。 */
export function PairPicker({ nodes, pair, onChange, labels, clearLabel }: PairPickerProps) {
  const set = (key: 'a' | 'b', id: NodeId) => onChange({ ...pair, [key]: id })
  return (
    // 窄的地方 A、B 各占一半，排成一行；宽了各是固定的宽度。
    <div className="flex w-full flex-wrap items-end gap-2 @2xl:w-auto @2xl:gap-3">
      <label className="flex min-w-0 flex-1 basis-28 flex-col gap-1.5 text-[13px] font-medium @2xl:w-60 @2xl:flex-none @2xl:basis-auto">
        {labels.a}
        <NodeSelect nodes={nodes} value={pair.a} onChange={(id) => set('a', id)} aria-label={labels.a} />
      </label>
      <Tooltip content={labels.swap}>
        <Button variant="ghost" size="icon" onClick={() => onChange({ a: pair.b, b: pair.a })} aria-label={labels.swap}>
          <ArrowLeftRight aria-hidden />
        </Button>
      </Tooltip>
      <label className="flex min-w-0 flex-1 basis-28 flex-col gap-1.5 text-[13px] font-medium @2xl:w-60 @2xl:flex-none @2xl:basis-auto">
        {labels.b}
        <NodeSelect nodes={nodes} value={pair.b} onChange={(id) => set('b', id)} aria-label={labels.b} />
      </label>
      {clearLabel !== undefined && (pair.a !== null || pair.b !== null) ? (
        <Button variant="ghost" onClick={() => onChange({ a: null, b: null })}>
          <X aria-hidden />
          {clearLabel}
        </Button>
      ) : null}
    </div>
  )
}
