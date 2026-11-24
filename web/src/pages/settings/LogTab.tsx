import { keepPreviousData, useInfiniteQuery, useQueries, useQuery } from '@tanstack/react-query'
import { Bot, Filter, History, Search, X } from 'lucide-react'
import { useEffect, useMemo, useRef } from 'react'
import { Link, useSearchParams } from 'react-router'

import { q } from '@/api/queries'
import { type LogEntry, type LogRef, type Network } from '@/api/types'
import { Pagination } from '@/components/pagination'
import { EmptyState, ErrorState, NoMatches, SkeletonRows } from '@/components/states'
import { RelativeTime } from '@/components/status'
import { RowsTotal, Table, TableFooter, Td, Th, Toolbar, Tr } from '@/components/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardHeader } from '@/components/ui/card'
import { fieldBase, NativeSelect } from '@/components/ui/input'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { paginate, readPage, withPage } from '@/lib/paginate'
import { networkPath } from '@/pages/networks/context'
import { cn } from '@/lib/utils'

import {
  actionKind,
  actorLabel,
  EMPTY_LOG_FILTER,
  hasServerFilter,
  isFiltered,
  isRefKind,
  logActionLabel,
  type LogFilter,
  logFilterToParams,
  logFilterToQuery,
  logJtis,
  logSentence,
  matchesSearch,
  parseLogFilter,
  refTarget,
} from './logFilter'

const s = t.settings.log

/** 一次向 controller 取多少条：它一次最多给这么多。 */
const FETCH_SIZE = 1000
/** 一页显示多少条。 */
const PAGE_SIZE = 25

/** 一条记录里要显示的对象：不认识的种类忽略；网络本身就是"网络"那一列，不再重复。 */
function shownRefs(entry: LogEntry): LogRef[] {
  return entry.refs.filter((ref) => isRefKind(ref.kind) && !(ref.kind === 'network' && ref.id === entry.network))
}

/** 记录里提到的一样东西怎么称呼：节点能查到名字的写名字，别的写种类加编号（和说明文字里的写法一致）。 */
function refLabel(ref: LogRef, names: ReadonlyMap<string, string>, networks: readonly Network[]): string {
  switch (ref.kind) {
    case 'network':
      return s.refLabels.network(ref.id, networks.find((network) => network.id === ref.id)?.name ?? null)
    case 'node':
      return s.refLabels.node(ref.id, names.get(`node:${ref.id}`) ?? null)
    case 'group':
    case 'token':
    case 'rule':
    case 'credential':
    case 'proxy':
    case 'forward':
      return s.refLabels[ref.kind](ref.id)
    default:
      return `${ref.kind} #${ref.id}`
  }
}

interface RefsProps {
  entry: LogEntry
  names: ReadonlyMap<string, string>
  networks: readonly Network[]
  onFilter: (ref: LogRef) => void
}

/** 一条记录说的那些东西：每样一个链接，去它所在的页面；旁边一个小按钮，只看和它有关的记录。 */
function Refs({ entry, names, networks, onFilter }: RefsProps) {
  const refs = shownRefs(entry)
  if (refs.length === 0) return null
  return (
    <ul aria-label={s.refsLabel} className="flex flex-wrap gap-1.5">
      {refs.map((ref) => {
        const label = refLabel(ref, names, networks)
        const target = refTarget(ref, entry.network)
        return (
          <li
            key={`${ref.kind}:${ref.id}`}
            className="inline-flex h-6 items-center rounded-md border bg-card text-xs"
            data-testid={`log-ref-${ref.kind}-${ref.id}`}
          >
            {target === null ? (
              <span className="px-2">{label}</span>
            ) : (
              <Link to={target} className="rounded-l-md px-2 text-primary underline-offset-4 hover:underline">
                {label}
              </Link>
            )}
            <Tooltip content={s.filterByRef(label)}>
              <button
                type="button"
                onClick={() => onFilter(ref)}
                aria-label={s.filterByRef(label)}
                className="flex h-full items-center rounded-r-md border-l px-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                <Filter className="size-3" aria-hidden />
              </button>
            </Tooltip>
          </li>
        )
      })}
    </ul>
  )
}

/**
 * 经 MCP 做的操作旁边注明是哪个令牌做的：一枚小标签写令牌的名字，悬停看它的 jti（名字可以重复，jti 不会）。
 * 管理员自己做的、节点引起的、controller 自己做的不注。
 */
function Actor({ entry }: { entry: LogEntry }) {
  const label = actorLabel(entry)
  const jti = entry.actor?.jti
  if (label === null || jti === undefined) return null
  return (
    <Tooltip content={s.actor.jti(jti)}>
      <Badge tone="accent" tabIndex={0} data-testid="log-actor">
        <Bot aria-hidden />
        {label}
      </Badge>
    </Tooltip>
  )
}

/**
 * 操作记录，分页显示。网络、操作、对象交给 controller 筛；搜索在取回来的全部记录里找。
 * 筛选条件和页码写在地址里，改了条件回到第一页。
 *
 * 分页要知道一共几页，controller 不给总数，所以符合条件的记录全部取回来：一次一千条接着取，
 * 它最多留一万条。第一批到了就显示，剩下的在后面取，取完之前写"已加载 N 条"。
 *
 * 每一行先写界面自己按 `action` 和 `refs` 写的话（操作的名字、对象的链接），按当前的语言；
 * controller 记下的说明（`detail`，中文原话）放在下面一行，字小一号，作为补充。
 * 界面自己写得出整句话的操作（`logSentence`，MCP 令牌的几种）写那一句，原话说的是同一件事，不再重复。
 * 经 MCP 做的操作后面注明是哪个令牌做的。
 */
export function LogTab() {
  const [params, setParams] = useSearchParams()
  const filter = parseLogFilter(params)
  const query = logFilterToQuery(filter)
  const log = useInfiniteQuery({ ...q.logPages(query, FETCH_SIZE), placeholderData: keepPreviousData })
  const networks = useQuery(q.networks())
  const toolbar = useRef<HTMLDivElement>(null)

  const setFilter = (next: LogFilter) => setParams(logFilterToParams(next), { replace: true })
  const setPage = (next: number) => setParams(withPage(logFilterToParams(filter), next), { replace: true })

  // 还有更早的就接着取，直到取完。取失败了停下，页脚上有「重试」。
  const { hasNextPage, isFetching, isFetchNextPageError, fetchNextPage } = log
  useEffect(() => {
    if (hasNextPage && !isFetching && !isFetchNextPageError) void fetchNextPage()
  }, [hasNextPage, isFetching, isFetchNextPageError, fetchNextPage])

  const entries = useMemo(() => log.data?.pages.flat() ?? [], [log.data])

  // 节点的名字：只查记录里出现过的网络，多数时候只有一两个。
  const networkIds = useMemo(
    () => [...new Set(entries.map((entry) => entry.network).filter((id): id is number => id !== null))],
    [entries],
  )
  const nodeLists = useQueries({
    queries: networkIds.map((id) => ({ ...q.nodes(id), refetchInterval: false as const })),
  })
  const names = useMemo(() => {
    const map = new Map<string, string>()
    for (const list of nodeLists) for (const node of list.data ?? []) map.set(`node:${node.id}`, node.name)
    return map
  }, [nodeLists])

  const allNetworks = networks.data ?? []
  // 搜索也找界面写的字（操作的名字、对象），所以每次渲染现算：换了语言就按新的语言找。
  const matched = entries.filter((entry) =>
    matchesSearch(
      entry,
      filter.search,
      [
        logActionLabel(entry.action) ?? '',
        logSentence(entry) ?? '',
        ...shownRefs(entry).map((ref) => refLabel(ref, names, allNetworks)),
        actorLabel(entry) ?? '',
        ...logJtis(entry),
      ].join(' '),
    ),
  )
  const { page, pages, rows } = paginate(matched, readPage(params), PAGE_SIZE)
  const kinds = Object.entries(s.kinds).filter((entry): entry is [string, string] => entry[1] !== undefined)
  const actions = Object.keys(s.actions)

  const networkLabel = (id: number | null) => {
    if (id === null) return <span className="text-muted-foreground">{s.global}</span>
    const found = allNetworks.find((candidate) => candidate.id === id)
    return found === undefined ? (
      <span className="text-muted-foreground">{s.deletedNetwork(id)}</span>
    ) : (
      <Link to={networkPath(found.id)} className="rounded-sm hover:text-primary hover:underline">
        {found.name}
      </Link>
    )
  }

  const nothingYet = log.isSuccess && entries.length === 0 && !hasServerFilter(filter)

  return (
    <Card>
      <CardHeader title={s.title} />
      {log.isError && log.data === undefined ? (
        <ErrorState title={s.loadFailed} error={log.error} onRetry={() => void log.refetch()} />
      ) : nothingYet ? (
        <EmptyState icon={History} title={s.emptyTitle} />
      ) : (
        <>
          <Toolbar ref={toolbar}>
            <div className="relative w-full sm:w-60">
              <Search
                className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-faint"
                aria-hidden
              />
              <input
                type="search"
                value={filter.search}
                onChange={(event) => setFilter({ ...filter, search: event.target.value })}
                placeholder={s.searchPlaceholder}
                aria-label={s.searchPlaceholder}
                autoComplete="off"
                className={cn(fieldBase, 'h-9 pr-3 pl-8.5')}
              />
            </div>
            <NativeSelect
              value={filter.network ?? ''}
              onChange={(event) =>
                setFilter({ ...filter, network: event.target.value === '' ? null : Number(event.target.value) })
              }
              aria-label={s.filterNetwork}
              className="min-w-0 flex-1 sm:w-40 sm:flex-none"
            >
              <option value="">{s.allNetworks}</option>
              {allNetworks.map((candidate) => (
                <option key={candidate.id} value={candidate.id}>
                  {candidate.name}
                </option>
              ))}
            </NativeSelect>
            <NativeSelect
              value={filter.action ?? ''}
              onChange={(event) =>
                setFilter({ ...filter, action: event.target.value === '' ? null : event.target.value })
              }
              aria-label={s.filterAction}
              className="min-w-0 flex-1 sm:w-52 sm:flex-none"
            >
              <option value="">{s.allActions}</option>
              {kinds.map(([kind, label]) => (
                <optgroup key={kind} label={label}>
                  <option value={kind}>{s.kindAll(label)}</option>
                  {actions
                    .filter((action) => actionKind(action) === kind)
                    .map((action) => (
                      <option key={action} value={action}>
                        {logActionLabel(action) ?? action}
                      </option>
                    ))}
                </optgroup>
              ))}
              {/* 地址里带来的、这个界面不认识的操作，也要能显示出来。 */}
              {filter.action !== null &&
              !actions.includes(filter.action) &&
              !kinds.some(([kind]) => kind === filter.action) ? (
                <option value={filter.action}>{filter.action}</option>
              ) : null}
            </NativeSelect>
            {filter.ref !== null ? (
              <span
                className="inline-flex h-7 items-center gap-1 rounded-md bg-muted pr-1 pl-2.5 text-[13px]"
                data-testid="log-ref-filter"
              >
                {s.refChip(refLabel(filter.ref, names, allNetworks))}
                <button
                  type="button"
                  onClick={() => setFilter({ ...filter, ref: null })}
                  aria-label={s.refRemove(refLabel(filter.ref, names, allNetworks))}
                  className="flex size-5 items-center justify-center rounded text-muted-foreground hover:bg-foreground/10 hover:text-foreground"
                >
                  <X className="size-3.5" aria-hidden />
                </button>
              </span>
            ) : null}
            {isFiltered(filter) ? (
              <Button variant="ghost" size="sm" onClick={() => setFilter(EMPTY_LOG_FILTER)}>
                {t.common.clearFilters}
              </Button>
            ) : null}
          </Toolbar>
          <Table stack aria-busy={log.isFetching && !log.isFetchingNextPage ? true : undefined}>
            <thead>
              <tr>
                <Th className="w-32">{s.colTime}</Th>
                <Th className="w-32">{s.colNetwork}</Th>
                <Th>{s.colEvent}</Th>
              </tr>
            </thead>
            <tbody>
              {log.isPending ? <SkeletonRows columns={3} rows={6} /> : null}
              {rows.map((entry) => {
                const sentence = logSentence(entry)
                return (
                  <Tr key={entry.id} data-testid={`log-row-${entry.id}`}>
                    <Td cell="inline" className="align-top text-[13px] whitespace-nowrap text-muted-foreground">
                      <RelativeTime at={entry.at} />
                    </Td>
                    <Td cell="inline" className="align-top text-[13px]">
                      {networkLabel(entry.network)}
                    </Td>
                    <Td cell="full" className="text-[13px]">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                        <span className="font-medium" data-testid="log-action">
                          {sentence ?? logActionLabel(entry.action) ?? (
                            <code className="font-mono text-xs font-normal">{entry.action}</code>
                          )}
                        </span>
                        <Refs
                          entry={entry}
                          names={names}
                          networks={allNetworks}
                          onFilter={(ref) => setFilter({ ...filter, ref, network: entry.network ?? filter.network })}
                        />
                        <Actor entry={entry} />
                      </div>
                      {sentence === null && entry.detail !== '' ? (
                        <p className="mt-1 text-xs break-words text-muted-foreground" data-testid="log-detail">
                          {entry.detail}
                        </p>
                      ) : null}
                    </Td>
                  </Tr>
                )
              })}
            </tbody>
          </Table>
          {log.isSuccess && !hasNextPage && matched.length === 0 ? (
            <NoMatches message={s.noMatches} onClear={() => setFilter(EMPTY_LOG_FILTER)} />
          ) : null}
          {matched.length > 0 || hasNextPage ? (
            <TableFooter className="gap-4">
              <span className="flex items-center gap-2" data-testid="log-count">
                {hasNextPage ? (
                  <>
                    <span className="tabular">{s.loaded(entries.length)}</span>
                    {isFetchNextPageError && !isFetching ? (
                      <Button variant="link" size="sm" onClick={() => void fetchNextPage()}>
                        {t.common.retry}
                      </Button>
                    ) : null}
                  </>
                ) : (
                  <RowsTotal shown={matched.length} total={entries.length} />
                )}
              </span>
              <Pagination page={page} pages={pages} onPage={setPage} top={toolbar} />
            </TableFooter>
          ) : null}
        </>
      )}
    </Card>
  )
}
