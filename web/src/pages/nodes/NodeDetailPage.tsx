import { useQuery } from '@tanstack/react-query'
import { ChevronRight, EllipsisVertical, History, Pencil, Replace, Server, ServerOff, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'

import { ApiError } from '@/api/client'
import { q } from '@/api/queries'
import { type Network, type NodeDetail } from '@/api/types'
import { CopyText } from '@/components/copy'
import { Page } from '@/components/page'
import { EmptyState, ErrorState, SkeletonBlock } from '@/components/states'
import { IssueIcon, StatusText } from '@/components/status'
import { OsIcon } from '@/components/os-icon'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { nodeIssues } from '@/lib/nodeIssues'
import { attachedCount } from '@/lib/nodes'
import { isUpdating } from '@/lib/nodeUpdate'
import { LIVE_INTERVAL, WAITING_INTERVAL } from '@/lib/polling'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { networkPath, useNetwork } from '@/pages/networks/context'
import { logPathFor } from '@/pages/settings/logFilter'

import { RenameNodeDialog } from './actions'
import { useDeleteNode } from './hooks'
import { ExitTab, ForwardTab, RelayTab } from './detail/Capabilities'
import { EditIpDialog, SucceedDialog } from './detail/dialogs'
import { OverviewTab } from './detail/OverviewTab'
import { RoutesTab } from './detail/RoutesTab'
import { RoleBadges } from './NodesPage'

const d = t.nodes.detail

/** 名字下面那一行里的分隔：一道细竖线。 */
function MetaDivider() {
  return <span aria-hidden className="h-3 w-px bg-border-strong" />
}

const TABS = ['overview', 'relay', 'exit', 'forward', 'routes'] as const
type Tab = (typeof TABS)[number]

/**
 * 名字旁边的角色标记，大一档、带图标。悬停写出有多少节点可以经它中继、经它访问互联网
 * （能当出口用的节点数由访问规则算，只在它是出口时才去取）。
 */
function HeaderBadges({ network, node, attached }: { network: Network; node: NodeDetail; attached: number }) {
  const access = useQuery({ ...q.nodeAccess(network.id, node.id), enabled: node.exit !== null })
  return <RoleBadges node={node} attached={attached} exitUsers={access.data?.reachable_by.length} size="md" />
}

/**
 * 节点详情：独立的页面，有自己的地址。字段多、关联多的对象不用抽屉。
 * 侧栏里没有它自己的入口，打开时"节点"那一项保持高亮。
 */
export function NodeDetailPage() {
  const network = useNetwork()
  const navigate = useNavigate()
  const params = useParams()
  const nodeId = Number(params.node)
  const [search, setSearch] = useSearchParams()
  const requested = search.get('tab') as Tab | null
  const tab: Tab = requested !== null && TABS.includes(requested) ? requested : 'overview'

  // 有一行能力正在等节点上报声明、或者它正在更新时，取得勤一些：用户这时正看着它变。
  const [waiting, setWaiting] = useState(false)
  const detail = useQuery({
    ...q.node(network.id, nodeId),
    refetchInterval: (query) =>
      waiting || (query.state.data !== undefined && isUpdating(query.state.data.update))
        ? WAITING_INTERVAL
        : LIVE_INTERVAL,
    enabled: Number.isInteger(nodeId),
  })
  const nodes = useQuery(q.nodes(network.id))
  const deleteNode = useDeleteNode(network)
  const [dialog, setDialog] = useState<'rename' | 'ip' | 'succeed' | null>(null)

  const node = detail.data
  useDocumentTitle(node?.name ?? t.nodes.title)

  const listPath = networkPath(network.id, 'nodes')

  if (
    !Number.isInteger(nodeId) ||
    (detail.isError && detail.error instanceof ApiError && detail.error.is('not_found'))
  ) {
    return (
      <Page>
        <EmptyState
          icon={ServerOff}
          title={d.notFoundTitle}
          action={
            <Button asChild variant="primary">
              <Link to={listPath}>{d.backToList}</Link>
            </Button>
          }
        />
      </Page>
    )
  }
  if (detail.isError && node === undefined) {
    return (
      <Page>
        <ErrorState title={d.loadFailed} error={detail.error} onRetry={() => void detail.refetch()} />
      </Page>
    )
  }
  if (node === undefined) {
    return (
      <Page>
        <SkeletonBlock lines={8} />
      </Page>
    )
  }

  const issue = nodeIssues(node, nodes.data ?? [])[0]

  return (
    // 竖着排、占满面板：路由的星状图要铺满下面剩下的高度。
    <Page fill>
      <nav
        aria-label={t.nav.breadcrumb}
        className="mb-4 flex min-w-0 items-center gap-1.5 text-base text-muted-foreground @xl:mb-5"
      >
        <Link to={listPath} className="shrink-0 rounded-sm hover:text-foreground hover:underline">
          {t.nodes.title}
        </Link>
        <ChevronRight className="size-4 shrink-0 text-faint" aria-hidden />
        <span className="truncate font-medium text-foreground" aria-current="page">
          {node.name}
        </span>
      </nav>

      {/* 窄的时候：名字占满一行，角色徽标放不下就换到下一行，域名单独一行，「更多」只剩图标。 */}
      <header className="mb-5 flex items-start justify-between gap-2 @xl:mb-8 @xl:items-center @xl:gap-6">
        <div className="flex min-w-0 items-start gap-3 @xl:items-center @xl:gap-4">
          {/* 左边一块是它的系统，和下面两行一样高，名字和状态都从它右边对齐开始。 */}
          <span
            aria-hidden
            className="flex size-11 shrink-0 items-center justify-center rounded-xl border bg-muted/60 text-foreground/80 @xl:size-[52px]"
          >
            <OsIcon platform={node.platform} className="size-6" fallback={<Server className="size-6" />} />
          </span>
          <div className="min-w-0">
            <div className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-1">
              <h1 className="min-w-0 truncate text-xl leading-7 font-bold tracking-tight @xl:text-[22px] @xl:leading-[30px]">
                {node.name}
              </h1>
              <Tooltip content={t.nodes.rename}>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="size-7 shrink-0 text-faint hover:text-foreground [&_svg]:size-3.5"
                  onClick={() => setDialog('rename')}
                  aria-label={t.nodes.rename}
                >
                  <Pencil aria-hidden />
                </Button>
              </Tooltip>
              <span className="flex shrink-0 items-center gap-1.5 @xl:ml-1">
                <HeaderBadges network={network} node={node} attached={attachedCount(nodes.data ?? [], node.id)} />
                {issue !== undefined ? <IssueIcon message={issue.message} tone={issue.tone} /> : null}
              </span>
            </div>
            {/* 名字下面一行：状态、虚拟 IP、域名，同一种字、同一个颜色，细竖线隔开。点值就复制（悬停有说明），不另画复制图标，间距才匀。 */}
            <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[13px] leading-5 text-muted-foreground">
              <span className="flex items-center gap-3">
                <StatusText tone={node.online ? 'ok' : 'idle'} className="gap-1.5 text-muted-foreground">
                  {node.online ? t.common.online : t.common.offline}
                </StatusText>
                <MetaDivider />
                <CopyText value={node.virtual_ip} mono={false} className="tabular [&>svg]:hidden" />
              </span>
              <span className="hidden @xl:block">
                <MetaDivider />
              </span>
              <CopyText value={node.fqdn} mono={false} className="max-w-full [&>svg]:hidden" />
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" aria-label={d.more} className="@max-xl:size-9 @max-xl:px-0">
                <EllipsisVertical aria-hidden />
                <span className="@max-xl:hidden">{d.more}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onSelect={() => setDialog('rename')}>
                <Pencil aria-hidden />
                {t.nodes.menuRename}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setDialog('succeed')}>
                <Replace aria-hidden />
                {d.succeed}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => void navigate(logPathFor({ kind: 'node', id: node.id }, network.id))}>
                <History aria-hidden />
                {d.nodeLog}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                danger
                onSelect={() =>
                  void deleteNode(node).then((deleted) => {
                    if (deleted) void navigate(listPath, { replace: true })
                  })
                }
              >
                <Trash2 aria-hidden />
                {t.nodes.menuDelete}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      <Tabs
        className="flex flex-1 flex-col"
        value={tab}
        onValueChange={(next) => {
          setSearch(next === 'overview' ? {} : { tab: next }, { replace: true })
        }}
      >
        <TabsList>
          <TabsTrigger value="overview">{d.tabOverview}</TabsTrigger>
          <TabsTrigger value="relay">{d.tabRelay}</TabsTrigger>
          <TabsTrigger value="exit">{d.tabExit}</TabsTrigger>
          <TabsTrigger value="forward">{d.tabForward}</TabsTrigger>
          <TabsTrigger value="routes">{d.tabRoutes}</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <OverviewTab network={network} node={node} onEditIp={() => setDialog('ip')} />
        </TabsContent>
        {/* 表单不铺满整个宽度：开关和"修改"离名字太远就对不上了。 */}
        <TabsContent value="relay">
          <RelayTab network={network} node={node} onWaiting={setWaiting} />
        </TabsContent>
        <TabsContent value="exit">
          <ExitTab network={network} node={node} onWaiting={setWaiting} />
        </TabsContent>
        <TabsContent value="forward" className="max-w-5xl">
          <ForwardTab network={network} node={node} onWaiting={setWaiting} />
        </TabsContent>
        <TabsContent value="routes" className="flex-col data-[state=active]:flex data-[state=active]:flex-1">
          <RoutesTab network={network} node={node} />
        </TabsContent>
      </Tabs>

      {dialog === 'rename' ? (
        <RenameNodeDialog network={network} node={node} open onClose={() => setDialog(null)} />
      ) : null}
      {dialog === 'ip' ? <EditIpDialog network={network} node={node} open onClose={() => setDialog(null)} /> : null}
      {dialog === 'succeed' ? (
        <SucceedDialog network={network} node={node} open onClose={() => setDialog(null)} />
      ) : null}
    </Page>
  )
}
