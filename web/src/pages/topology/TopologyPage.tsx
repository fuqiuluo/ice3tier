import { useQuery } from '@tanstack/react-query'
import { Plus, Waypoints } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router'

import { q } from '@/api/queries'
import { type NodeId } from '@/api/types'
import { Notice } from '@/components/notice'
import { Canvas, Page, PageHeader } from '@/components/page'
import { PairPicker } from '@/components/pair-picker'
import { EmptyState, ErrorState, SkeletonBlock } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { t } from '@/i18n'
import { REPORT_INTERVAL_SECS } from '@/lib/product'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { cn } from '@/lib/utils'
import { useNetwork } from '@/pages/networks/context'
import { AddNodeDialog } from '@/pages/nodes/AddNodeDialog'
import { useLineColors } from '@/topology/colors'
import { LineSample } from '@/topology/line-edge'
import { buildTopology, type Selection } from '@/topology/graph'
import { nextPick, type Pair, readPair, writePair } from '@/topology/pair'

import { BackboneView } from './BackboneView'
import { MatrixView } from './MatrixView'
import { PairPanel } from './PairPanel'
import { LANE_DASH, TopologyGraph } from './TopologyGraph'

const g = t.topology

type View = 'graph' | 'matrix' | 'backbone'

const VIEWS: readonly View[] = ['graph', 'matrix', 'backbone']

function GraphLegend() {
  const colors = useLineColors()
  const line = (color: string, dash?: string, width?: number) => <LineSample color={color} dash={dash} width={width} />
  return (
    <ul
      className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-muted-foreground"
      aria-label={t.routes.legendLabel}
    >
      <li className="flex items-center gap-1.5">
        {line(colors.direct)}
        {g.legendDirect}
      </li>
      <li className="flex items-center gap-1.5">
        {line(colors.relay)}
        {g.legendRelay}
      </li>
      <li className="flex items-center gap-1.5">
        {line(colors.lane, LANE_DASH)}
        {g.legendLane}
      </li>
      <li className="flex items-center gap-1.5">
        {line(colors.stale, '5 4')}
        {g.legendStale}
      </li>
      <li className="flex items-center gap-1.5">
        {line(colors.none, '2 4')}
        {g.legendNone}
      </li>
      <li className="flex items-center gap-1.5">
        {line(colors.neutral, undefined, 2.6)}
        {g.legendForward}
      </li>
      <li className="flex items-center gap-1.5">
        {line(colors.neutral, '7 5', 2.6)}
        {g.legendReverse}
      </li>
      <li className="flex items-center gap-1.5">
        <span className="h-3 w-5 rounded-sm border border-dashed border-border-strong bg-card" aria-hidden />
        {g.legendOffline}
      </li>
    </ul>
  )
}

/**
 * 拓扑：整个网络。节点、relay 和它们之间现在走的路。两种看法共用同一份路由矩阵：
 * 实时图（看得快）和路由矩阵（精确）。选中的一对节点写在地址里，两种看法之间、和路径诊断之间来回切换时跟着走。
 * 另一个视图"骨干"是别的数据：relay 之间测的延迟，每次现问节点。
 */
export function TopologyPage() {
  useDocumentTitle(g.title)
  const network = useNetwork()
  const [params, setParams] = useSearchParams()
  const [adding, setAdding] = useState(false)
  const view: View = VIEWS.find((candidate) => candidate === params.get('view')) ?? 'graph'
  const pair = readPair(params)

  const matrix = useQuery(q.matrix(network.id))
  const nodes = useQuery(q.nodes(network.id))
  const relays = useMemo(
    () => new Set((nodes.data ?? []).filter((node) => node.relay !== null).map((node) => node.id)),
    [nodes.data],
  )
  const looks = useMemo(
    () =>
      new Map((nodes.data ?? []).map((node) => [node.id, { country: node.country ?? null, platform: node.platform }])),
    [nodes.data],
  )
  const known = (id: NodeId | null) => id !== null && matrix.data?.nodes.some((node) => node.id === id) === true
  const selection: Selection | null =
    pair.a !== null && pair.b !== null && pair.a !== pair.b && known(pair.a) && known(pair.b)
      ? { a: pair.a, b: pair.b }
      : null
  const shape = useMemo(
    () => (matrix.data === undefined ? null : buildTopology(matrix.data, relays, selection)),
    // selection 由 pair 算出，按两个编号比较就够了。
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [matrix.data, relays, selection?.a, selection?.b],
  )

  const setPair = (next: Pair) => setParams(writePair(params, next), { replace: true })
  const setView = (next: View) => {
    const updated = new URLSearchParams(params)
    if (next === 'graph') updated.delete('view')
    else updated.set('view', next)
    setParams(updated, { replace: true })
  }

  const names = new Map((matrix.data?.nodes ?? []).map((node) => [node.id, node.name]))
  const name = (id: NodeId) => names.get(id) ?? t.common.nodeMissing(id)
  const nodeA = matrix.data?.nodes.find((node) => node.id === selection?.a)
  const nodeB = matrix.data?.nodes.find((node) => node.id === selection?.b)

  const tooFew = matrix.data !== undefined && matrix.data.nodes.length < 2
  const noRoutes = matrix.data?.entries.length === 0

  const panel =
    shape !== null && nodeA !== undefined && nodeB !== undefined ? (
      <PairPanel network={network.id} a={nodeA} b={nodeB} forward={shape.forward} reverse={shape.reverse} name={name} />
    ) : null

  return (
    <Page fill>
      <PageHeader
        title={g.title}
        description={g.subtitle}
        actions={
          <Segmented<View>
            aria-label={g.viewLabel}
            value={view}
            onChange={setView}
            options={[
              { value: 'graph', label: g.viewGraph },
              { value: 'matrix', label: g.viewMatrix },
              { value: 'backbone', label: g.viewBackbone },
            ]}
          />
        }
      />

      {view === 'backbone' ? (
        // 骨干是另一份数据（relay 之间测的），和选中的那一对节点无关，也不看路由矩阵。
        <BackboneView network={network} name={name} looks={looks} />
      ) : (
        <>
          {/* 选两个节点（也可以在图上、矩阵里点），右边一句多久更新一次。 */}
          <div className="mb-6 flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
            <PairPicker
              nodes={nodes.data ?? []}
              pair={pair}
              onChange={setPair}
              labels={{ a: g.pickA, b: g.pickB, swap: g.swap }}
              clearLabel={g.clearPair}
            />
            <p className="flex h-9 items-center text-xs text-muted-foreground">
              {selection === null ? `${g.pickHint} · ` : null}
              {t.common.updatedEvery(REPORT_INTERVAL_SECS)}
            </p>
          </div>

          {matrix.isError && matrix.data === undefined ? (
            <ErrorState title={g.loadFailed} error={matrix.error} onRetry={() => void matrix.refetch()} />
          ) : shape === null || matrix.data === undefined ? (
            <SkeletonBlock lines={8} />
          ) : tooFew ? (
            <EmptyState
              icon={Waypoints}
              title={g.emptyTitle}
              action={
                <Button variant="primary" onClick={() => setAdding(true)}>
                  <Plus aria-hidden />
                  {g.addNode}
                </Button>
              }
            />
          ) : (
            <div className="flex flex-1 flex-col gap-4">
              {noRoutes ? <Notice title={g.noRoutesTitle}>{g.noRoutesBody}</Notice> : null}
              {view === 'graph' ? (
                <div
                  className={cn(
                    'grid flex-1 grid-cols-1 gap-10',
                    panel !== null && '@4xl:grid-cols-[minmax(0,1fr)_16rem]',
                  )}
                >
                  <div className="flex flex-col gap-3">
                    <Canvas data-testid="topology-graph">
                      <TopologyGraph
                        shape={shape}
                        looks={looks}
                        rtt={{ forward: shape.forward?.rtt_ms ?? null, reverse: shape.reverse?.rtt_ms ?? null }}
                        onPick={(id) => setPair(nextPick(pair, id))}
                      />
                    </Canvas>
                    <GraphLegend />
                  </div>
                  {panel}
                </div>
              ) : (
                // 格子里用字写怎么走，不要图例；矩阵横竖铺满剩下的地方。
                <div
                  className={cn(
                    'grid flex-1 grid-cols-1 gap-10',
                    panel !== null && '@4xl:grid-cols-[minmax(0,1fr)_16rem]',
                  )}
                >
                  <div className="flex min-w-0 flex-col">
                    <MatrixView matrix={matrix.data} pair={pair} looks={looks} onPick={(a, b) => setPair({ a, b })} />
                  </div>
                  {panel}
                </div>
              )}
            </div>
          )}
        </>
      )}
      <AddNodeDialog network={network} open={adding} onClose={() => setAdding(false)} />
    </Page>
  )
}
