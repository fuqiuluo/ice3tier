import { useQuery } from '@tanstack/react-query'
import { AppWindow, Copy, Pencil, Plus, Server, Smartphone, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type Forward, type ForwardInput } from '@/api/types'
import { useConfirm } from '@/components/confirm'
import { CodeBlock } from '@/components/copy'
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
import { InfoTip } from '@/components/info-tip'
import { Notice } from '@/components/notice'
import { Page, PageHeader } from '@/components/page'
import { RowActions } from '@/components/row-actions'
import { ErrorState, SkeletonRows } from '@/components/states'
import { RowsTotal, Table, TableFooter, Td, Th } from '@/components/table'
import { Button } from '@/components/ui/button'
import { DropdownMenuItem, DropdownMenuSeparator } from '@/components/ui/dropdown-menu'
import { Switch } from '@/components/ui/switch'
import { toast } from '@/components/ui/toast'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { copyText } from '@/lib/clipboard'
import { parseSocketAddr } from '@/lib/cidr'
import { declareCommand } from '@/lib/commands'
import { canBeForwardTarget, forwardTargetBySwitch, nodeName } from '@/lib/nodes'
import { FOCUSED_ROW, useFocusRow } from '@/lib/useFocusRow'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { cn } from '@/lib/utils'
import { networkPath, useNetwork } from '@/pages/networks/context'

import { ForwardDialog } from './ForwardDialog'
import { forwardAddress, forwardLabel, forwardStatusView, type ForwardStatusView } from './status'

const f = t.forwards

type Editor = { forward: Forward | null } | null

function toInput(forward: Forward, enabled: boolean): ForwardInput {
  return {
    name: forward.name,
    protocol: forward.protocol,
    listen_node: forward.listen_node,
    bind: forward.bind,
    target_node: forward.target_node,
    target_addr: forward.target_addr,
    allow_from: forward.allow_from,
    enabled,
    // PUT 是整个替换：不写的字段回到默认值，所以开关的时候要把等级原样带上。
    class: forward.class,
  }
}

/** 监听那一端下面的一行：协议和地址（端口写 0 的写节点挑定的那个）。 */
function ListenLine({ forward, view }: { forward: Forward; view: ForwardStatusView }) {
  const port = parseSocketAddr(forward.bind)?.port
  const picked = view.listen?.picked ?? null
  return (
    <>
      <ProtocolTag>{forward.protocol === 'tcp' ? f.dialog.tcp : f.dialog.udp}</ProtocolTag>
      {port === 0 && picked !== null && view.listen?.local != null ? (
        <Tooltip content={f.pickedHint}>
          <span tabIndex={0} className="cursor-help rounded-sm" data-testid={`forward-picked-${forward.id}`}>
            <Address>{view.listen.local}</Address> · {f.picked(picked)}
          </span>
        </Tooltip>
      ) : port === 0 ? (
        <span>
          <Address>{forward.bind}</Address> · {f.pickedPending}
        </span>
      ) : (
        <Address>{forward.bind}</Address>
      )}
    </>
  )
}

/** 空的时候那一行图。文字在渲染时取：换了语言跟着变。 */
const flow = () => [
  { icon: Smartphone, label: f.flow.device },
  { icon: Server, label: f.flow.listen },
  { icon: Server, label: f.flow.target },
  { icon: AppWindow, label: f.flow.service },
]

export function ForwardsPage() {
  useDocumentTitle(f.title)
  const network = useNetwork()
  const confirm = useConfirm()
  const forwards = useQuery(q.forwards(network.id))
  const nodes = useQuery(q.nodes(network.id))
  const [editor, setEditor] = useState<Editor>(null)
  const focus = useFocusRow(forwards.data)

  // 启用和停用没有单独的接口：取出这条转发，把 enabled 改掉再整个放回去。
  const setEnabled = useAction(network.id, {
    mutationFn: ({ forward, enabled }: { forward: Forward; enabled: boolean }) =>
      api.replaceForward(network.id, forward.id, toInput(forward, enabled)),
    success: (_data, { forward, enabled }) =>
      enabled ? f.enabledToast(forwardLabel(forward)) : f.disabledToast(forwardLabel(forward)),
  })
  const remove = useAction(network.id, {
    mutationFn: (forward: Forward) => api.deleteForward(network.id, forward.id),
    success: (_data, forward) => f.deleted(forwardLabel(forward)),
  })

  const all = nodes.data ?? []
  const list = forwards.data ?? []
  const empty = forwards.isSuccess && list.length === 0
  const noNodes = nodes.isSuccess && all.length === 0
  const noTargets = nodes.isSuccess && all.length > 0 && !all.some((node) => canBeForwardTarget(node))
  const targetsBySwitch = all.some((node) => forwardTargetBySwitch(node))

  const onDelete = async (forward: Forward) => {
    const connections = forward.listen?.connections ?? 0
    const confirmed = await confirm({
      title: f.deleteTitle(forwardLabel(forward)),
      body: (
        <>
          <p>{f.deleteBody(nodeName(all, forward.listen_node), forward.bind)}</p>
          {connections > 0 ? <p>{f.deleteActive(connections)}</p> : null}
        </>
      ),
      confirmLabel: f.deleteConfirm,
    })
    if (confirmed) remove.mutate(forward)
  }

  return (
    <Page fill>
      <PageHeader
        title={f.title}
        description={f.subtitle}
        actions={
          empty ? undefined : (
            <Button variant="primary" onClick={() => setEditor({ forward: null })}>
              <Plus aria-hidden />
              {f.create}
            </Button>
          )
        }
      />
      {focus.missing ? (
        <Notice className="mb-4" tone="warn">
          {f.focusMissing(focus.focus ?? 0)}
        </Notice>
      ) : null}
      {forwards.isError ? (
        <ErrorState title={f.loadFailed} error={forwards.error} onRetry={() => void forwards.refetch()} />
      ) : empty && noNodes ? (
        <FlowEmpty stops={flow()} title={f.emptyTitle} body={f.emptyNoNodes}>
          <Button asChild variant="primary">
            <Link to={networkPath(network.id, 'nodes')}>{t.exits.goNodes}</Link>
          </Button>
        </FlowEmpty>
      ) : empty ? (
        <FlowEmpty stops={flow()} title={f.emptyTitle} body={f.emptyBody}>
          <Button variant="primary" onClick={() => setEditor({ forward: null })}>
            <Plus aria-hidden />
            {f.create}
          </Button>
          {noTargets ? (
            <div className="w-full max-w-2xl text-left">
              <Notice tone="warn" title={f.noTargets}>
                {targetsBySwitch ? (
                  f.noTargetsSwitchBody
                ) : (
                  <>
                    {f.noTargetsBody}
                    <CodeBlock copy={declareCommand('forward')} className="mt-2 bg-card/70">
                      {declareCommand('forward')}
                    </CodeBlock>
                  </>
                )}
              </Notice>
            </div>
          ) : null}
        </FlowEmpty>
      ) : (
        <>
          <Table stack>
            <thead>
              <tr>
                <Th>{f.colName}</Th>
                <Th>{f.colListen}</Th>
                <Th>{f.colTarget}</Th>
                <Th>
                  <span className="inline-flex items-center gap-1">
                    {f.colStatus}
                    <InfoTip>{f.statusCaveat}</InfoTip>
                  </span>
                </Th>
                <Th>{f.colUse}</Th>
                <Th className="w-12">
                  <span className="sr-only">{t.common.moreActions}</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {forwards.isPending ? <SkeletonRows columns={6} rows={3} /> : null}
              {list.map((forward) => {
                const view = forwardStatusView(forward, all)
                const label = forwardLabel(forward)
                const blocked = forward.status === 'target_not_declared'
                // 停用的那一行已经变淡、开关关着；正常的不用说原因。
                const hasDetail = view.tone !== 'ok' && forward.status !== 'disabled'
                const reported = view.needsAttention ? (view.listen?.reported ?? null) : null
                const traffic = view.listen?.traffic ?? null
                const listenNode = all.find((node) => node.id === forward.listen_node)
                const targetNode = all.find((node) => node.id === forward.target_node)
                return (
                  <EntryRow
                    key={forward.id}
                    ref={focus.rowRef(forward.id)}
                    dimmed={!forward.enabled}
                    className={cn(focus.focus === forward.id && FOCUSED_ROW)}
                    data-testid={`forward-row-${label}`}
                    data-status={forward.status}
                  >
                    <Td cell="main">
                      <NameCell
                        toggle={
                          <Tooltip content={blocked ? f.toggleBlocked : undefined}>
                            <span tabIndex={blocked ? 0 : undefined} className="inline-flex rounded-full">
                              <Switch
                                aria-label={f.toggle(label)}
                                checked={forward.enabled}
                                disabled={
                                  blocked || (setEnabled.isPending && setEnabled.variables.forward.id === forward.id)
                                }
                                onCheckedChange={(enabled) => setEnabled.mutate({ forward, enabled })}
                              />
                            </span>
                          </Tooltip>
                        }
                      >
                        {forward.name === '' ? (
                          <span className="font-normal text-muted-foreground">{f.unnamed}</span>
                        ) : (
                          forward.name
                        )}
                      </NameCell>
                    </Td>
                    <Td cell="row" label={f.colListen}>
                      <NodeCell
                        network={network.id}
                        node={{ id: forward.listen_node, name: nodeName(all, forward.listen_node) }}
                        online={listenNode?.online}
                      >
                        <ListenLine forward={forward} view={view} />
                      </NodeCell>
                    </Td>
                    <Td cell="row" label={f.colTarget}>
                      <NodeCell
                        network={network.id}
                        node={{ id: forward.target_node, name: nodeName(all, forward.target_node) }}
                        online={targetNode?.online}
                      >
                        <Address>{forward.target_addr}</Address>
                      </NodeCell>
                    </Td>
                    <Td cell="row" label={f.colStatus} data-keep>
                      <StatusCell
                        tone={view.tone}
                        label={view.label}
                        detail={hasDetail ? view.detail : null}
                        action={
                          hasDetail && view.linkToRules ? (
                            <PoliciesLink network={network.id}>{t.common.viewPolicies}</PoliciesLink>
                          ) : undefined
                        }
                        reported={reported}
                      />
                    </Td>
                    <Td cell="row" label={f.colUse}>
                      <UsageCell
                        udp={forward.protocol === 'udp'}
                        usage={
                          traffic === null
                            ? null
                            : { connections: traffic.connections, up: traffic.bytes_up, down: traffic.bytes_down }
                        }
                      />
                    </Td>
                    <Td cell="end" className="pl-0 text-right" data-keep>
                      <RowActions label={t.common.actionsFor(label)}>
                        <DropdownMenuItem onSelect={() => setEditor({ forward })}>
                          <Pencil aria-hidden />
                          {f.menuEdit}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onSelect={() =>
                            void copyText(forwardAddress(forward, view)).then((ok) =>
                              ok ? toast.success(f.addressCopied) : toast.error(t.common.copyFailed),
                            )
                          }
                        >
                          <Copy aria-hidden />
                          {f.menuCopy}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem danger onSelect={() => void onDelete(forward)}>
                          <Trash2 aria-hidden />
                          {f.menuDelete}
                        </DropdownMenuItem>
                      </RowActions>
                    </Td>
                  </EntryRow>
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

      {editor !== null ? (
        <ForwardDialog
          key={editor.forward?.id ?? 'new'}
          network={network}
          forward={editor.forward}
          open
          onClose={() => setEditor(null)}
        />
      ) : null}
    </Page>
  )
}
