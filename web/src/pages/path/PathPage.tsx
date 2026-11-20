import { useQuery } from '@tanstack/react-query'
import { Waypoints } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type NodeId } from '@/api/types'
import { Notice } from '@/components/notice'
import { Page, PageHeader } from '@/components/page'
import { ErrorState } from '@/components/states'
import { Button } from '@/components/ui/button'
import { t } from '@/i18n'
import { isBoolean, readStored, writeStored } from '@/lib/storage'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { useNow } from '@/lib/useNow'
import { networkPath, useNetwork } from '@/pages/networks/context'
import { checks, type ReportSection, verdict } from '@/topology/checks'
import { type DiagnosisInput, hostOf, measuredPaths } from '@/topology/diagnosis'
import { type Pair, pairPath, readPair, writePair } from '@/topology/pair'
import { reportJson, reportText } from '@/topology/report'

import {
  CandidatesTable,
  CPU_LEGEND,
  CpuChart,
  MEMORY_LEGEND,
  MemoryChart,
  PathChart,
  PathsLegend,
  PathsTable,
} from './charts'
import { FocusContext } from './focus'
import { HostsTab } from './HostsTab'
import { NodeGrid } from './NodeGrid'
import { Output } from './OutputTab'
import { PairRow } from './PairHero'
import { ReportSectionBlock, ResultBlock } from './Report'
import { RunRow } from './RunBar'
import { Legend } from './viz'

const p = t.path
const d = t.diagnosis
const c = t.diagnosis.chart

/**
 * 路径诊断：两个节点的互诊断，结果是一份报告。
 *
 * - 顶上一张卡片：这一对（左 A 右 B，点一端换节点；中间两个方向现在怎么走）和诊断的状态、按钮（默认量吞吐）。
 *   没选好两个节点时下面是一格一格的节点。
 * - 报告一节一块面板，每块占满一行，宽度一样、边对齐：诊断结果（总评、建议、分三组的逐项检查，量不到的写为什么），
 *   路径（两个方向一张表，像 mtr 一样一段一行，瀑布条看延迟在哪一段累起来），各条路（测了的每条路一行：延迟的分布、
 *   吞吐的条画在格子里，数字成列），选路（候选路径的代价、两种模式各会走哪条），两端主机（CPU、内存的图和对照表），
 *   原始数据（文本报告和 JSON）。没有数据的节不出现，结果里写着为什么。
 * - 联动：鼠标停在任何一处的一条路上，所有表和图里同一条路亮着，别的淡下去（`focus.ts`）。
 * - 数据是一次诊断（主动测试）量的，默认显示这一对最近的一次；路径、候选路径、节点的上报是现在的。
 *
 * 选的两个节点、看的那次诊断写在地址里（`?a=&b=&test=`）。
 */
export function PathPage() {
  useDocumentTitle(p.title)
  const network = useNetwork()
  const now = useNow()
  const [params, setParams] = useSearchParams()
  const pair = readPair(params)
  const rawTest = Number(params.get('test'))
  const testParam = Number.isInteger(rawTest) && rawTest > 0 ? rawTest : null
  const same = pair.a !== null && pair.a === pair.b
  const ready = pair.a !== null && pair.b !== null && !same
  const a = pair.a ?? 0
  const b = pair.b ?? 0

  const nodes = useQuery(q.nodes(network.id))
  const detailA = useQuery({ ...q.node(network.id, a), enabled: ready })
  const detailB = useQuery({ ...q.node(network.id, b), enabled: ready })
  const routesA = useQuery({ ...q.routes(network.id, a), enabled: ready })
  const routesB = useQuery({ ...q.routes(network.id, b), enabled: ready })
  const path = useQuery({ ...q.path(network.id, a, b), enabled: ready })
  const history = useQuery({ ...q.tests(network.id, { a, b }), enabled: ready })
  const shown = testParam ?? history.data?.[0]?.id ?? null
  const current = useQuery({ ...q.test(network.id, shown ?? 0), enabled: ready && shown !== null })
  const test = current.data

  // 完整的诊断默认连吞吐一起量；取消了记在浏览器里。
  const [throughput, setThroughput] = useState(() => readStored('diagnosis.throughput', true, isBoolean))
  const start = useAction(network.id, {
    mutationFn: (body: { a: NodeId; b: NodeId; throughput: boolean }) => api.createTest(network.id, body),
    success: (created) => d.started(created.a.name, created.b.name),
  })
  const stop = useAction(network.id, {
    mutationFn: (id: number) => api.cancelTest(network.id, id),
    success: d.stopped,
  })

  // 换了节点，原来看的那次诊断就不是这一对的了。
  const setPair = (next: Pair) => {
    const updated = writePair(params, next)
    updated.delete('test')
    setParams(updated, { replace: true })
  }
  const openTest = (id: number) => {
    const next = new URLSearchParams(params)
    next.set('test', String(id))
    setParams(next, { replace: true })
  }
  // 延迟和吞吐在同一节（各条路）。
  const goTo = (section: ReportSection) =>
    document
      .getElementById(`report-${section === 'throughput' ? 'latency' : section}`)
      ?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  const [focus, setFocus] = useState<string | null>(null)
  const focusValue = useMemo(() => ({ focus, setFocus }), [focus])

  const list = useMemo(() => nodes.data ?? [], [nodes.data])
  const byId = new Map(list.map((node) => [node.id, node]))
  const named = useMemo(() => [...list, ...(test === undefined ? [] : [test.a, test.b])], [list, test])
  const name = (id: NodeId) => byId.get(id)?.name ?? t.common.nodeMissing(id)
  const input: DiagnosisInput = { a: detailA.data, b: detailB.data, path: path.data, test, nodes: named }
  const notPeers =
    path.data !== undefined && [path.data.forward, path.data.reverse].some((leg) => leg.source === 'not_peers')
  const queriedAgo = path.data === undefined ? null : Math.max(0, now - Math.floor(path.dataUpdatedAt / 1000))
  const stamp = new Date(now * 1000).toISOString().slice(0, 19).replace(/[-:T]/g, '')
  const fileBase = `ice3tier-${name(a)}-${name(b)}-${stamp}`

  const results = checks(input)
  const paths = measuredPaths(test)
  const hosts = (test?.hosts ?? []).filter((host) => host.state === 'done')

  return (
    <Page>
      <PageHeader
        title={p.title}
        description={p.subtitle}
        actions={
          <Button asChild variant="ghost">
            <Link to={pairPath(network.id, 'topology', pair.a, pair.b)}>
              <Waypoints aria-hidden />
              {p.toTopology}
            </Link>
          </Button>
        }
      />
      <div className="space-y-3">
        {/* 这一对和诊断的按钮。 */}
        <section className="rounded-lg border bg-card">
          <PairRow
            nodes={list}
            pair={pair}
            onChange={setPair}
            a={detailA.data ?? byId.get(a)}
            b={detailB.data ?? byId.get(b)}
            path={ready ? path.data : undefined}
            ready={ready}
            name={name}
            fetching={path.isFetching}
            queriedAgo={queriedAgo}
            onRequery={() => void path.refetch()}
          />
          {ready ? (
            <RunRow
              test={test}
              throughput={throughput}
              onThroughput={(on) => {
                setThroughput(on)
                writeStored('diagnosis.throughput', on)
              }}
              starting={start.isPending}
              stopping={stop.isPending}
              onStart={() => start.mutate({ a, b, throughput }, { onSuccess: (created) => openTest(created.id) })}
              onStop={() => {
                if (test !== undefined) stop.mutate(test.id)
              }}
            />
          ) : null}
        </section>

        {!ready ? (
          <NodeGrid nodes={list} loading={nodes.isPending} pair={pair} onChange={setPair} />
        ) : (
          <>
            {path.isError && path.data === undefined ? (
              <ErrorState title={p.loadFailed} error={path.error} onRetry={() => void path.refetch()} />
            ) : null}
            {notPeers ? (
              <Notice
                tone="warn"
                title={p.notPeersTitle}
                action={
                  <Button asChild size="sm">
                    <Link to={`${networkPath(network.id, 'access')}?check=1&from=${a}&to=${b}`}>{p.toAccess}</Link>
                  </Button>
                }
              />
            ) : null}
            {[a, b].map((id) => {
              const node = byId.get(id)
              return node === undefined || node.online ? null : <Notice key={id}>{p.offline(node.name)}</Notice>
            })}
            {current.isError && shown !== null ? <Notice tone="warn">{t.tests.testGone(shown)}</Notice> : null}

            <FocusContext value={focusValue}>
              <ReportSectionBlock id="report-result" title={d.sections.result}>
                <ResultBlock checks={results} verdict={verdict(results, test, named)} onOpen={goTo} />
              </ReportSectionBlock>
              <ReportSectionBlock id="report-path" title={d.sections.path}>
                <PathChart path={path.data} test={test} nodes={named} />
              </ReportSectionBlock>
              {paths.length > 0 ? (
                <ReportSectionBlock id="report-latency" title={d.sections.paths} action={<PathsLegend test={test} />}>
                  <PathsTable test={test} nodes={named} />
                </ReportSectionBlock>
              ) : null}
              <ReportSectionBlock id="report-routing" title={d.sections.routing}>
                <CandidatesTable path={path.data} test={test} nodes={named} />
              </ReportSectionBlock>
              <ReportSectionBlock id="report-hosts" title={d.sections.hosts}>
                {hosts.length > 0 ? (
                  <div className="mb-3 grid grid-cols-1 gap-x-8 gap-y-3 @4xl:grid-cols-2">
                    <div className="flex flex-col">
                      <p className="mb-1 flex items-center justify-between gap-3 text-xs text-muted-foreground">
                        {c.cpuTitle}
                        <Legend items={CPU_LEGEND()} />
                      </p>
                      <div className="flex-1">
                        <CpuChart hosts={hosts} nodes={named} empty="" />
                      </div>
                    </div>
                    <div className="flex flex-col">
                      <p className="mb-1 flex items-center justify-between gap-3 text-xs text-muted-foreground">
                        {c.memoryTitle}
                        <Legend items={MEMORY_LEGEND()} />
                      </p>
                      <div className="flex-1">
                        <MemoryChart hosts={hosts} nodes={named} empty="" />
                      </div>
                    </div>
                  </div>
                ) : null}
                <HostsTab
                  network={network.id}
                  tested={test !== undefined}
                  nodes={named}
                  a={{
                    id: a,
                    name: name(a),
                    detail: detailA.data,
                    host: hostOf(test, a),
                    toPeer: routesA.data?.routes.find((route) => route.peer.id === b),
                    direct: test?.direct?.sides.find((side) => side.node === a),
                  }}
                  b={{
                    id: b,
                    name: name(b),
                    detail: detailB.data,
                    host: hostOf(test, b),
                    toPeer: routesB.data?.routes.find((route) => route.peer.id === a),
                    direct: test?.direct?.sides.find((side) => side.node === b),
                  }}
                />
              </ReportSectionBlock>
              <Output
                fileBase={fileBase}
                report={() => ({ text: reportText(input, now), json: reportJson(input, now) })}
              />
            </FocusContext>
          </>
        )}
      </div>
    </Page>
  )
}
