import { useQuery } from '@tanstack/react-query'
import { Plus, ScanSearch, ShieldOff, X } from 'lucide-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type AccessGraph, type GroupId, type Network, type NodeId, type Rule } from '@/api/types'
import { isAllToAll } from '@/access/reach'
import { GroupChip } from '@/components/groups'
import { NodeSelect } from '@/components/node'
import { Notice } from '@/components/notice'
import { SearchBox } from '@/components/search-box'
import { RowsTotal, TableFooter, Toolbar } from '@/components/table'
import { Canvas, Page, PageHeader } from '@/components/page'
import { EmptyState, ErrorState, SkeletonBlock } from '@/components/states'
import { Button } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { t } from '@/i18n'
import { formatList } from '@/lib/format'
import { allGroupId } from '@/lib/groups'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { useNetwork } from '@/pages/networks/context'

import { AccessCheck } from './AccessCheck'
import { GroupGraphView } from './GroupGraphView'
import { NodeGraphView } from './NodeGraphView'
import { RuleDialog, type RuleDraft } from './RuleDialog'
import { RuleList } from './RuleList'

const g = t.access.graph

type View = 'groups' | 'node'
type Editor = { rule: Rule | null; draft?: RuleDraft } | null

function numberParam(params: URLSearchParams, key: string): number | null {
  const raw = params.get(key)
  if (raw === null) return null
  const value = Number(raw)
  return Number.isInteger(value) && value > 0 ? value : null
}

interface NodeViewProps {
  network: Network
  graph: AccessGraph
  focus: NodeId | null
  onFocus: (node: NodeId) => void
}

function NodeView({ network, graph, focus, onFocus }: NodeViewProps) {
  const nodes = useQuery(q.nodes(network.id))
  const access = useQuery({ ...q.nodeAccess(network.id, focus ?? 0), enabled: focus !== null })
  const [expanded, setExpanded] = useState({ left: false, right: false })

  return (
    <>
      <div className="mb-3 w-72">
        <NodeSelect nodes={nodes.data ?? []} value={focus} onChange={onFocus} aria-label={g.nodePickLabel} />
      </div>
      {focus !== null && access.data !== undefined && !access.data.acknowledged ? (
        <Notice tone="warn" className="mb-3">
          {g.nodePending}
        </Notice>
      ) : null}
      <Canvas data-testid="node-graph" className="border bg-card">
        {focus === null ? (
          <EmptyState icon={ScanSearch} title={g.nodePick} className="h-full justify-center" />
        ) : access.isError ? (
          <ErrorState title={g.loadFailed} error={access.error} onRetry={() => void access.refetch()} />
        ) : access.data === undefined ? (
          <SkeletonBlock lines={4} />
        ) : (
          <NodeGraphView
            access={access.data}
            rules={graph.rules}
            expanded={expanded}
            onExpand={(side) => setExpanded((current) => ({ ...current, [side]: true }))}
            onFocus={(node) => {
              setExpanded({ left: false, right: false })
              onFocus(node.id)
            }}
          />
        )}
      </Canvas>
      {/* 图的文字版：两侧各是谁。 */}
      {focus !== null && access.data !== undefined ? (
        <dl className="grid grid-cols-2 gap-x-6 pt-4 text-[13px]">
          <div>
            <dt className="font-medium">{g.reachableBy(access.data.reachable_by.length)}</dt>
            <dd className="mt-0.5 text-muted-foreground">
              {access.data.reachable_by.length === 0
                ? g.nobody
                : formatList(access.data.reachable_by.map((edge) => edge.node.name))}
            </dd>
          </div>
          <div>
            <dt className="font-medium">{g.canReach(access.data.can_reach.length)}</dt>
            <dd className="mt-0.5 text-muted-foreground">
              {access.data.can_reach.length === 0
                ? g.nobody
                : formatList(access.data.can_reach.map((edge) => edge.node.name))}
            </dd>
          </div>
        </dl>
      ) : null}
    </>
  )
}

/**
 * 策略：上面一行搜索和"列表 / 关系图"的切换，下面是占满宽度的策略表（照 NetBird 的样子），或者关系图。
 * 从操作记录点过来的（`?rule=<编号>`）那条策略一开始就亮着；`?group=<编号>` 只列出用到这个分组的策略；
 * `?show=graph` 打开关系图，`?view=node&node=<编号>` 是关系图的按节点看（出口页的链接用它）。
 */
export function AccessPage() {
  useDocumentTitle(t.access.title)
  const network = useNetwork()
  const graph = useQuery(q.graph(network.id))
  const nodes = useQuery(q.nodes(network.id))
  const [params, setParams] = useSearchParams()

  const graphView: View = params.get('view') === 'node' ? 'node' : 'groups'
  const show: 'list' | 'graph' = params.get('show') === 'graph' || graphView === 'node' ? 'graph' : 'list'
  const focus = numberParam(params, 'node')
  const checking = params.get('check') === '1'
  const checkFrom = numberParam(params, 'from')
  const checkTo = numberParam(params, 'to')
  const groupFilter = numberParam(params, 'group')

  const [editor, setEditor] = useState<Editor>(null)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<number | null>(() => numberParam(params, 'rule'))

  const update = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params)
    for (const [key, value] of Object.entries(changes)) {
      if (value === null) next.delete(key)
      else next.set(key, value)
    }
    setParams(next, { replace: true })
  }

  const restore = useAction(network.id, {
    mutationFn: (all: GroupId) =>
      api.createRule(network.id, { name: 'default', src: all, dst: all, direction: 'both', enabled: true }),
    success: t.access.restored,
  })

  const data = graph.data
  const all = allGroupId(data?.groups)
  const filterGroup = data?.groups.find((group) => group.id === groupFilter)
  const needle = search.trim().toLowerCase()
  const rules = (data?.rules ?? []).filter(
    (rule) =>
      (groupFilter === null || rule.src.id === groupFilter || rule.dst.id === groupFilter) &&
      (needle === '' || [rule.name, rule.src.name, rule.dst.name].some((text) => text.toLowerCase().includes(needle))),
  )
  const pending = (data?.unacknowledged ?? []).filter(
    (node) => nodes.data?.find((candidate) => candidate.id === node.id)?.online !== false,
  )
  // 文档里的那句提醒要出现在界面上：All ⇄ All 开着时，别的策略看不出效果。
  const allOpen = data?.rules.some((rule) => rule.enabled && isAllToAll(rule)) ?? false
  const othersEnabled = data?.rules.some((rule) => rule.enabled && !isAllToAll(rule)) ?? false

  return (
    <Page fill>
      <PageHeader
        title={t.access.title}
        description={t.access.subtitle}
        actions={
          <>
            <Button onClick={() => update({ check: '1' })}>
              <ScanSearch aria-hidden />
              {t.access.check}
            </Button>
            <Button variant="primary" onClick={() => setEditor({ rule: null })} disabled={data === undefined}>
              <Plus aria-hidden />
              {t.access.newRule}
            </Button>
          </>
        }
      />

      {checking ? (
        <AccessCheck
          network={network}
          nodes={nodes.data ?? []}
          all={all}
          from={checkFrom}
          to={checkTo}
          onChange={(from, to) =>
            update({ from: from === null ? null : String(from), to: to === null ? null : String(to) })
          }
          onClose={() => update({ check: null, from: null, to: null })}
          onCreateRule={(draft) => {
            // 先关掉检查，再打开新建策略：不叠两层对话框。
            update({ check: null, from: null, to: null })
            setEditor({ rule: null, draft })
          }}
        />
      ) : null}

      {graph.isError && data === undefined ? (
        <ErrorState title={t.access.loadFailed} error={graph.error} onRetry={() => void graph.refetch()} />
      ) : data === undefined ? (
        <SkeletonBlock lines={6} />
      ) : (
        <>
          <Toolbar>
            {show === 'list' ? (
              <SearchBox value={search} onChange={setSearch} placeholder={t.access.searchPlaceholder} />
            ) : (
              <Segmented
                aria-label={g.viewLabel}
                value={graphView}
                onChange={(next) => update({ view: next === 'groups' ? null : next })}
                options={[
                  { value: 'groups', label: g.byGroup },
                  { value: 'node', label: g.byNode },
                ]}
              />
            )}
            {filterGroup !== undefined && show === 'list' ? (
              <span className="inline-flex h-9 items-center gap-1.5 rounded-md border px-2.5 text-[13px]">
                <GroupChip name={filterGroup.name} builtin={filterGroup.builtin} />
                <button
                  type="button"
                  aria-label={t.access.clearGroupFilter(filterGroup.name)}
                  className="rounded-sm text-muted-foreground hover:text-foreground"
                  onClick={() => update({ group: null })}
                >
                  <X className="size-3.5" aria-hidden />
                </button>
              </span>
            ) : null}
            <Segmented
              aria-label={t.access.viewLabel}
              value={show}
              onChange={(next) => update({ show: next === 'list' ? null : next, view: null, node: null })}
              options={[
                { value: 'list', label: t.access.viewList },
                { value: 'graph', label: t.access.viewGraph },
              ]}
              className="ml-auto"
            />
          </Toolbar>

          <div className="mb-4 space-y-2 empty:hidden">
            {/* 离线的节点上线时才拿新配置，不算"没确认"：只说在线却还没确认的。 */}
            {pending.length > 0 ? (
              <Notice tone="warn">{g.unacked(formatList(pending.map((node) => node.name)))}</Notice>
            ) : null}
            {allOpen && othersEnabled ? <Notice tone="warn">{t.access.allOpenNotice}</Notice> : null}
            {/* 只在有节点没被任何策略连通时出现：它们互相到不了，也到不了别人。 */}
            {data.unconnected.length > 0 ? (
              <div data-testid="unconnected">
                <Notice tone="warn">
                  {t.access.unconnectedNotice(
                    data.unconnected.length,
                    formatList(data.unconnected.map((node) => node.name)),
                  )}
                </Notice>
              </div>
            ) : null}
          </div>

          {show === 'list' ? (
            data.rules.length === 0 ? (
              <EmptyState
                icon={ShieldOff}
                title={t.access.emptyTitle}
                action={
                  <>
                    <Button
                      pending={restore.isPending}
                      disabled={all === undefined}
                      onClick={() => all !== undefined && restore.mutate(all)}
                    >
                      {t.access.restoreDefault}
                    </Button>
                    <Button variant="primary" onClick={() => setEditor({ rule: null })}>
                      <Plus aria-hidden />
                      {t.access.newRule}
                    </Button>
                  </>
                }
              />
            ) : rules.length === 0 ? (
              <EmptyState icon={ScanSearch} title={t.access.noMatch} />
            ) : (
              <>
                <RuleList
                  network={network}
                  graph={data}
                  rules={rules}
                  focused={selected}
                  onEdit={(rule) => setEditor({ rule })}
                />
                <TableFooter>
                  <RowsTotal shown={rules.length} total={data.rules.length} />
                </TableFooter>
              </>
            )
          ) : graphView === 'groups' ? (
            <div className="flex flex-1 flex-col">
              <Canvas data-testid="group-graph" className="border bg-card">
                <GroupGraphView
                  graph={data}
                  online={(id) => nodes.data?.find((node) => node.id === id)?.online}
                  highlightedRule={selected}
                  activeGroup={groupFilter}
                  onRuleClick={setSelected}
                  onRuleOpen={(id) => {
                    const rule = data.rules.find((candidate) => candidate.id === id)
                    if (rule !== undefined) setEditor({ rule })
                  }}
                  onRuleHover={() => undefined}
                  onGroupClick={(group) => update({ show: null, view: null, group: String(group) })}
                />
              </Canvas>
            </div>
          ) : (
            <div className="flex flex-1 flex-col">
              <NodeView network={network} graph={data} focus={focus} onFocus={(id) => update({ node: String(id) })} />
            </div>
          )}
        </>
      )}

      {editor !== null && data !== undefined ? (
        <RuleDialog
          key={editor.rule?.id ?? 'new'}
          network={network}
          graph={data}
          rule={editor.rule}
          draft={editor.draft}
          open
          onClose={() => setEditor(null)}
        />
      ) : null}
    </Page>
  )
}
