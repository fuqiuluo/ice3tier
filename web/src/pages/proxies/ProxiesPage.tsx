import { useQuery } from '@tanstack/react-query'
import { Copy, DoorOpen, Globe, Pencil, Plus, Server, Smartphone, Trash2 } from 'lucide-react'
import { Fragment, useState } from 'react'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type Node, type Proxy } from '@/api/types'
import { useConfirm } from '@/components/confirm'
import {
  Address,
  EntryRow,
  FlowEmpty,
  NameCell,
  NodeCell,
  PoliciesLink,
  ProtocolTag,
  StatusCell,
  UsageCell,
} from '@/components/entry-list'
import { Page, PageHeader } from '@/components/page'
import { RowActions } from '@/components/row-actions'
import { ErrorState, SkeletonRows } from '@/components/states'
import { RowsTotal, Table, TableFooter, Td, Th } from '@/components/table'
import { Button } from '@/components/ui/button'
import { DropdownMenuItem, DropdownMenuSeparator } from '@/components/ui/dropdown-menu'
import { Switch } from '@/components/ui/switch'
import { toast } from '@/components/ui/toast'
import { t } from '@/i18n'
import { copyText } from '@/lib/clipboard'
import { parseSocketAddr } from '@/lib/cidr'
import { nodeName } from '@/lib/nodes'
import { lanesReported, proxyLane, proxyLaneView } from '@/lib/lanes'
import { proxyStatus, type ProxyStatusView, proxyUrl } from '@/lib/proxy'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { cn } from '@/lib/utils'
import { useNetwork } from '@/pages/networks/context'

import { ProxyDialog } from './ProxyDialog'
import { LaneCell, LaneDetails, LaneReasons, TipLabel } from './ProxyLane'

const s = t.proxies

/** 设备里要填的地址：监听所有地址的写成"局域网 IP"让人自己换。 */
function addressOf(proxy: Proxy): string {
  const bind = parseSocketAddr(proxy.status?.local ?? proxy.bind)
  if (bind === null) return proxy.bind
  return proxyUrl({
    protocol: proxy.protocol,
    host: bind.host === '0.0.0.0' ? `<${s.lanHost}>` : bind.host,
    port: bind.port,
    username: proxy.username,
    password: proxy.password,
  })
}

/** 状态下面那一句原因：带具体的节点名。正常、停用的不写。 */
function statusDetail(proxy: Proxy, code: ProxyStatusView['code'], entry: string, exit: string): string | null {
  switch (code) {
    case 'pending':
      return t.listen.pendingDetail(entry)
    case 'node_offline':
      return s.backOnline(entry)
    case 'port_in_use':
      return t.listen.portInUseDetail(entry, String(parseSocketAddr(proxy.bind)?.port ?? proxy.bind))
    case 'bind_failed':
      return t.listen.failedDetail(entry, proxy.bind)
    case 'exit_disabled':
      return s.exitOffDetail(exit)
    case 'exit_offline':
      return s.backOnline(exit)
    case 'access_denied':
      return s.accessDeniedDetail(entry, exit)
    case 'exit_missing':
      return s.exitMissingDetail
    case 'listening':
    case 'disabled':
    case 'unknown':
      return null
  }
}

/** 空的时候那一行图。文字在渲染时取：换了语言跟着变。 */
const flow = () => [
  { icon: Smartphone, label: s.flow.device },
  { icon: Server, label: s.flow.entry },
  { icon: DoorOpen, label: s.flow.exit },
  { icon: Globe, label: s.flow.internet },
]

/**
 * 代理：在一台节点（入口）上开 SOCKS5 / HTTP 代理端口，流量经组网从另一台节点（出口）出去，用户名和密码认证。
 * 和端口转发的列表一个排法（`components/entry-list`）：名称、启用、入口 → 出口、认证、状态和原因、用量。
 * 有代理打开了 ice3proxy 时多一列：起不起作用、为什么，两端报了计数时能展开看（以前在节点对上，0.1.26 起是代理的选项）。
 */
export function ProxiesPage() {
  useDocumentTitle(s.title)
  const network = useNetwork()
  const confirm = useConfirm()
  const proxies = useQuery(q.proxies(network.id))
  const nodes = useQuery(q.nodes(network.id))
  const all: readonly Node[] = nodes.data ?? []
  const [editing, setEditing] = useState<{ proxy: Proxy | null } | null>(null)
  const [open, setOpen] = useState<number | null>(null)
  const list = proxies.data ?? []
  // ice3proxy 那一列只在有代理打开了它时画：不然整列都是"关"。
  const laneShown = list.some((proxy) => proxyLane(proxy).on)
  const columns = 7 + (laneShown ? 1 : 0)

  const toggle = useAction(network.id, {
    mutationFn: ({ proxy, enabled }: { proxy: Proxy; enabled: boolean }) =>
      api.updateProxy(network.id, proxy.id, { enabled }),
    success: (saved) => (saved.enabled ? s.enabledToast(saved.name) : s.disabledToast(saved.name)),
  })
  const remove = useAction(network.id, {
    mutationFn: (proxy: Proxy) => api.deleteProxy(network.id, proxy.id),
    success: (_data, proxy) => s.deleted(proxy.name),
  })
  const onDelete = async (proxy: Proxy) => {
    const confirmed = await confirm({
      tone: 'danger',
      title: s.deleteTitle(proxy.name),
      body: s.deleteBody,
      confirmLabel: s.deleteConfirm,
    })
    if (confirmed) remove.mutate(proxy)
  }

  return (
    <Page fill>
      <PageHeader
        title={s.title}
        description={s.subtitle}
        actions={
          list.length > 0 ? (
            <Button variant="primary" onClick={() => setEditing({ proxy: null })}>
              <Plus aria-hidden />
              {s.create}
            </Button>
          ) : undefined
        }
      />
      {proxies.isError ? (
        <ErrorState title={s.loadFailed} error={proxies.error} onRetry={() => void proxies.refetch()} />
      ) : proxies.isSuccess && list.length === 0 ? (
        <FlowEmpty stops={flow()} title={s.emptyTitle} body={s.emptyBody}>
          <Button variant="primary" onClick={() => setEditing({ proxy: null })}>
            <Plus aria-hidden />
            {s.create}
          </Button>
        </FlowEmpty>
      ) : (
        <>
          <Table stack>
            <thead>
              <tr>
                <Th>{s.colName}</Th>
                <Th>{s.colEntry}</Th>
                <Th>{s.colExit}</Th>
                <Th>{s.colAuth}</Th>
                <Th>{s.colStatus}</Th>
                {laneShown ? (
                  <Th>
                    <TipLabel label={s.lane.title} tip={s.lane.tip} />
                  </Th>
                ) : null}
                <Th>{s.colUsage}</Th>
                <Th className="w-12">
                  <span className="sr-only">{t.common.moreActions}</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {proxies.isPending ? <SkeletonRows columns={columns} rows={3} /> : null}
              {list.map((proxy) => {
                const status = proxyStatus(proxy)
                const entry = all.find((node) => node.id === proxy.node)
                const exit = proxy.exit === null ? undefined : all.find((node) => node.id === proxy.exit)
                const entryName = nodeName(all, proxy.node)
                const exitName = proxy.exit === null ? '' : nodeName(all, proxy.exit)
                const counted = proxy.connections > 0 || proxy.bytes_up > 0 || proxy.bytes_down > 0
                const reported =
                  status.code === 'port_in_use' || status.code === 'bind_failed' ? (proxy.status?.detail ?? null) : null
                const expanded = open === proxy.id && lanesReported(proxy)
                const lane = laneShown ? proxyLaneView(proxy, all) : null
                const reasons = lane?.kind === 'blocked' ? lane.reasons : []
                return (
                  <Fragment key={proxy.id}>
                    <EntryRow
                      dimmed={!proxy.enabled}
                      className={cn((expanded || reasons.length > 0) && 'border-b-0')}
                      data-testid={`proxy-row-${proxy.name}`}
                    >
                      <Td cell="main">
                        <NameCell
                          toggle={
                            <Switch
                              aria-label={s.switchLabel(proxy.name)}
                              checked={proxy.enabled}
                              disabled={toggle.isPending && toggle.variables.proxy.id === proxy.id}
                              onCheckedChange={(enabled) => toggle.mutate({ proxy, enabled })}
                            />
                          }
                        >
                          {proxy.name}
                        </NameCell>
                      </Td>
                      <Td cell="row" label={s.colEntry}>
                        <NodeCell
                          network={network.id}
                          node={{ id: proxy.node, name: entryName }}
                          online={entry?.online}
                        >
                          <ProtocolTag>{s.protocol[proxy.protocol]}</ProtocolTag>
                          <Address>{proxy.status?.local ?? proxy.bind}</Address>
                        </NodeCell>
                      </Td>
                      <Td cell="row" label={s.colExit}>
                        {proxy.exit === null ? (
                          <span className="text-muted-foreground">—</span>
                        ) : (
                          <NodeCell
                            network={network.id}
                            node={{ id: proxy.exit, name: exitName }}
                            online={exit?.online}
                          >
                            {exit?.egress_ip != null ? (
                              <span title={s.exitIp}>
                                <Address>{exit.egress_ip}</Address>
                              </span>
                            ) : null}
                          </NodeCell>
                        )}
                      </Td>
                      <Td cell="row" label={s.colAuth} className="text-[13px] whitespace-nowrap">
                        {proxy.username === '' ? (
                          <span className="text-muted-foreground">{s.noAuth}</span>
                        ) : (
                          <span className="font-mono">{proxy.username}</span>
                        )}
                      </Td>
                      <Td cell="row" label={s.colStatus} data-keep>
                        <StatusCell
                          tone={status.tone}
                          label={s.status[status.code]}
                          detail={statusDetail(proxy, status.code, entryName, exitName)}
                          action={
                            status.code === 'access_denied' ? (
                              <PoliciesLink network={network.id}>{t.common.viewPolicies}</PoliciesLink>
                            ) : undefined
                          }
                          reported={reported}
                          narrow={laneShown}
                        />
                      </Td>
                      {laneShown ? (
                        <Td cell="row" label={s.lane.title} data-keep>
                          <LaneCell
                            proxy={proxy}
                            view={lane}
                            nodes={all}
                            expanded={expanded}
                            onToggle={() => setOpen(expanded ? null : proxy.id)}
                          />
                        </Td>
                      ) : null}
                      <Td cell="row" label={s.colUsage}>
                        <UsageCell
                          usage={
                            status.code === 'listening' || counted
                              ? { connections: proxy.connections, up: proxy.bytes_up, down: proxy.bytes_down }
                              : null
                          }
                        />
                      </Td>
                      <Td cell="end" className="pl-0 text-right" data-keep>
                        <RowActions label={t.common.actionsFor(proxy.name)}>
                          <DropdownMenuItem onSelect={() => setEditing({ proxy })}>
                            <Pencil aria-hidden />
                            {s.menuEdit}
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onSelect={() =>
                              void copyText(addressOf(proxy)).then((ok) =>
                                ok ? toast.success(s.copied) : toast.error(t.common.copyFailed),
                              )
                            }
                          >
                            <Copy aria-hidden />
                            {s.menuCopy}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem danger onSelect={() => void onDelete(proxy)}>
                            <Trash2 aria-hidden />
                            {s.menuDelete}
                          </DropdownMenuItem>
                        </RowActions>
                      </Td>
                    </EntryRow>
                    {reasons.length > 0 ? (
                      <tr className={cn(!expanded && 'border-b last:border-b-0', !proxy.enabled && 'opacity-55')}>
                        <td
                          colSpan={columns}
                          data-cell="full"
                          className="px-3 pt-0 pb-3"
                          data-testid={`proxy-lane-blocked-${proxy.name}`}
                        >
                          <LaneReasons network={network} reasons={reasons} />
                        </td>
                      </tr>
                    ) : null}
                    {expanded ? (
                      <tr className="border-b last:border-b-0">
                        <td colSpan={columns} data-cell="full" className="px-3 pt-0 pb-4">
                          <LaneDetails network={network} proxy={proxy} nodes={all} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                )
              })}
            </tbody>
          </Table>
          {list.length > 0 ? (
            <TableFooter>
              <RowsTotal shown={list.length} />
            </TableFooter>
          ) : null}
        </>
      )}
      {editing !== null ? (
        <ProxyDialog network={network} proxy={editing.proxy} onClose={() => setEditing(null)} />
      ) : null}
    </Page>
  )
}
