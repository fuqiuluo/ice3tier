import { useQuery } from '@tanstack/react-query'
import { ArrowLeftRight, Link2, RotateCcw } from 'lucide-react'
import { useCallback, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type Node, type PairCongestion, type PairView } from '@/api/types'
import { NodeLink } from '@/components/node'
import { Page, PageHeader } from '@/components/page'
import { SearchBox } from '@/components/search-box'
import { EmptyState, ErrorState, NoMatches, SkeletonRows } from '@/components/states'
import { RowsTotal, Table, TableFooter, Td, Th, Tr } from '@/components/table'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { allPairs, pairKey, pairStored } from '@/lib/pairs'
import { nodeName } from '@/lib/nodes'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { FOCUSED_ROW } from '@/lib/useFocusRow'
import { cn } from '@/lib/utils'
import { useNetwork } from '@/pages/networks/context'
import { readPair } from '@/topology/pair'

const p = t.pairs

/** 拥塞控制的下拉：节点的默认（`null`）、BBR、CUBIC。`<select>` 的值不能是 `null`，默认写成空串。 */
const CONGESTION: readonly (PairCongestion | null)[] = [null, 'bbr', 'cubic']
const congestionLabel = (value: PairCongestion | null | undefined) => p.congestion[value ?? 'default']
const congestionValue = (raw: string): PairCongestion | null => (raw === '' ? null : (raw as PairCongestion))

type Show = 'all' | 'custom'

/** 表头上带解释的名字：虚线下划线，悬停或聚焦时显示。 */
function TipHeader({ label, tip }: { label: string; tip: string }) {
  return (
    <Tooltip content={tip}>
      <span tabIndex={0} className="cursor-help rounded-sm underline decoration-dotted underline-offset-4">
        {label}
      </span>
    </Tooltip>
  )
}

/** 筛选项的名字后面一个灰色的数。 */
function Counted({ label, count }: { label: string; count: number }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      {label}
      <span className="text-muted-foreground tabular">{count}</span>
    </span>
  )
}

/**
 * 节点对：网络里的每一对节点一行（0.1.28 起接口给全部；更早的 controller 只给有设置的，界面用节点列表补齐成默认）。
 * 两项设置在行里直接改、立即生效：连接常驻、拥塞控制。没有特殊设置的一对最后一列写"默认"，有的写"自定义"、
 * 能恢复默认。上面一个按节点名的搜索框和"全部 / 有设置"。从节点详情过来时地址里带着 `a`、`b`：那一对亮出来。
 */
export function PairsPage() {
  useDocumentTitle(p.title)
  const network = useNetwork()
  const [params] = useSearchParams()
  const pairs = useQuery(q.pairs(network.id))
  const nodes = useQuery(q.nodes(network.id))
  const [search, setSearch] = useState('')
  const [show, setShow] = useState<Show>('all')
  const focus = readPair(params)
  const focusKey = focus.a !== null && focus.b !== null ? pairKey(focus.a, focus.b) : null
  const scrolled = useRef(false)
  const scrollTo = useCallback((element: HTMLElement | null) => {
    if (element === null || scrolled.current) return
    scrolled.current = true
    element.scrollIntoView({ block: 'center' })
  }, [])
  const all: readonly Node[] = useMemo(() => nodes.data ?? [], [nodes.data])

  const names = (pair: Pick<PairView, 'a' | 'b'>) => [nodeName(all, pair.a), nodeName(all, pair.b)] as const

  // 开关和下拉改了立即生效：可以马上改回来，不打断任何正在跑的流。请求只带改的那一项。
  const setKeepAlive = useAction(network.id, {
    mutationFn: ({ pair, keepAlive }: { pair: PairView; keepAlive: boolean }) =>
      api.setPair(network.id, pair.a, pair.b, { keep_alive: keepAlive }),
    success: (_data, { pair, keepAlive }) => (keepAlive ? p.on(...names(pair)) : p.off(...names(pair))),
  })
  const setCongestion = useAction(network.id, {
    mutationFn: ({ pair, congestion }: { pair: PairView; congestion: PairCongestion | null }) =>
      api.setPair(network.id, pair.a, pair.b, { congestion }),
    success: (_data, { pair, congestion }) => p.congestionChanged(...names(pair), congestionLabel(congestion)),
  })
  const remove = useAction(network.id, {
    mutationFn: (pair: PairView) => api.deletePair(network.id, pair.a, pair.b),
    success: (_data, pair) => p.removed(...names(pair)),
  })

  const rows = useMemo(() => allPairs(all, pairs.data ?? []), [all, pairs.data])
  const custom = rows.filter(pairStored)
  const needle = search.trim().toLowerCase()
  const visible = rows.filter(
    (pair) =>
      (show === 'all' || pairStored(pair)) &&
      (needle === '' || names(pair).some((name) => name.toLowerCase().includes(needle))),
  )
  const loading = pairs.isPending || nodes.isPending
  const tooFew = nodes.isSuccess && all.length < 2
  // 改着的那一对的控件先不能再动：两个请求不要交叉。
  const busy = (pair: PairView) =>
    (setKeepAlive.isPending &&
      pairKey(setKeepAlive.variables.pair.a, setKeepAlive.variables.pair.b) === pairKey(pair.a, pair.b)) ||
    (setCongestion.isPending &&
      pairKey(setCongestion.variables.pair.a, setCongestion.variables.pair.b) === pairKey(pair.a, pair.b))

  return (
    <Page>
      <PageHeader title={p.title} description={p.subtitle} />
      {pairs.isError ? (
        <ErrorState title={p.loadFailed} error={pairs.error} onRetry={() => void pairs.refetch()} />
      ) : tooFew ? (
        <EmptyState icon={Link2} title={p.emptyTitle} description={p.defaultNote} />
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <SearchBox value={search} onChange={setSearch} placeholder={p.searchPlaceholder} />
            <Segmented<Show>
              aria-label={p.showLabel}
              value={show}
              onChange={setShow}
              options={[
                { value: 'all', label: <Counted label={p.showAll} count={rows.length} /> },
                { value: 'custom', label: <Counted label={p.showCustom} count={custom.length} /> },
              ]}
            />
          </div>
          <Table stack>
            <thead>
              <tr>
                <Th>{p.colPair}</Th>
                <Th>
                  <TipHeader label={p.colKeepAlive} tip={p.keepAliveHint} />
                </Th>
                <Th>
                  <TipHeader label={p.colCongestion} tip={p.congestionTip} />
                </Th>
                <Th>{p.colSetting}</Th>
              </tr>
            </thead>
            <tbody>
              {loading ? <SkeletonRows columns={4} rows={3} /> : null}
              {visible.map((pair) => {
                const [a, b] = names(pair)
                const stored = pairStored(pair)
                const key = pairKey(pair.a, pair.b)
                const focused = focusKey === key
                return (
                  <Tr
                    key={key}
                    ref={focused ? scrollTo : undefined}
                    className={cn(focused && FOCUSED_ROW)}
                    data-testid={`pair-row-${a}-${b}`}
                    data-stored={stored}
                  >
                    <Td cell="main" className="whitespace-nowrap">
                      <span className="inline-flex flex-wrap items-center gap-x-2.5 gap-y-1">
                        <NodeLink
                          network={network.id}
                          node={{ id: pair.a, name: a }}
                          online={all.find((node) => node.id === pair.a)?.online}
                        />
                        <ArrowLeftRight className="size-3.5 text-muted-foreground" aria-hidden />
                        <NodeLink
                          network={network.id}
                          node={{ id: pair.b, name: b }}
                          online={all.find((node) => node.id === pair.b)?.online}
                        />
                      </span>
                    </Td>
                    <Td cell="row" label={p.colKeepAlive}>
                      <Switch
                        aria-label={p.toggle(a, b)}
                        checked={pair.keep_alive}
                        disabled={busy(pair)}
                        onCheckedChange={(keepAlive) => setKeepAlive.mutate({ pair, keepAlive })}
                      />
                    </Td>
                    {/* 下拉框比一行字高：表头往下挪一点，和它里面的字对齐。 */}
                    <Td cell="row" label={p.colCongestion} className="[--stack-label-top:0.375rem]">
                      <NativeSelect
                        aria-label={p.congestionSelect(a, b)}
                        className="h-8 w-36 text-[13px]"
                        value={pair.congestion ?? ''}
                        disabled={busy(pair)}
                        onChange={(event) =>
                          setCongestion.mutate({ pair, congestion: congestionValue(event.target.value) })
                        }
                      >
                        {CONGESTION.map((option) => (
                          <option key={option ?? 'default'} value={option ?? ''}>
                            {congestionLabel(option)}
                          </option>
                        ))}
                      </NativeSelect>
                    </Td>
                    <Td
                      cell="row"
                      label={p.colSetting}
                      className="text-[13px] whitespace-nowrap"
                      data-testid={`pair-setting-${a}-${b}`}
                    >
                      {stored ? (
                        <span className="inline-flex items-center gap-2">
                          {p.settingCustom}
                          <Tooltip content={p.remove}>
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              aria-label={p.removeFor(a, b)}
                              disabled={remove.isPending}
                              onClick={() => remove.mutate(pair)}
                            >
                              <RotateCcw aria-hidden />
                            </Button>
                          </Tooltip>
                        </span>
                      ) : (
                        <span className="text-muted-foreground">{p.settingDefault}</span>
                      )}
                    </Td>
                  </Tr>
                )
              })}
            </tbody>
          </Table>
          {!loading && visible.length === 0 ? (
            <NoMatches
              message={p.noMatches}
              onClear={() => {
                setSearch('')
                setShow('all')
              }}
            />
          ) : null}
          {!loading ? (
            <TableFooter className="gap-3">
              <RowsTotal shown={visible.length} total={rows.length} />
              <span className="text-muted-foreground">{p.defaultNote}</span>
            </TableFooter>
          ) : null}
        </>
      )}
    </Page>
  )
}
