import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Boxes, Pencil, Plus, Server, Trash2, X } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'

import { errorDetail, errorMessage } from '@/api/client'
import { api } from '@/api/endpoints'
import { fieldError, formError, formErrorDetail, groupNameFailure } from '@/api/formErrors'
import { q, useAction } from '@/api/queries'
import { type Group, type GroupId, type Network, type Node, type NodeId, type NodeRef } from '@/api/types'
import { useConfirm } from '@/components/confirm'
import { FormDialog } from '@/components/form-dialog'
import { NodeLink, NodeList, NodeSelect } from '@/components/node'
import { Notice } from '@/components/notice'
import { Page, PageHeader } from '@/components/page'
import { RowActions } from '@/components/row-actions'
import { PolicyList } from '@/components/rule'
import { SearchBox } from '@/components/search-box'
import { EmptyState, ErrorState, SkeletonRows } from '@/components/states'
import { CellButton, RowsTotal, Table, TableFooter, Td, Th, Toolbar, Tr } from '@/components/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogBody, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { DropdownMenuItem, DropdownMenuSeparator } from '@/components/ui/dropdown-menu'
import { Field } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { toast } from '@/components/ui/toast'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { FOCUSED_ROW, useFocusRow } from '@/lib/useFocusRow'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { cn } from '@/lib/utils'
import { validateGroupName } from '@/lib/validate'
import { networkPath, useNetwork } from '@/pages/networks/context'

const g = t.groups

/** 表格的列数：名字、节点、规则、操作。成员那一行横跨全部。 */
const COLUMNS = 4

interface NameDialogProps {
  network: Network
  /** 要改名的分组；新建时是 `null`。 */
  group: Group | null
  onClose: () => void
  onSaved: (group: Group) => void
}

/** 新建分组和改名是同一个表单：只有一个名字。改名不改变谁能访问谁，规则记的是编号。 */
function NameDialog({ network, group, onClose, onSaved }: NameDialogProps) {
  const [name, setName] = useState(group?.name ?? '')
  const [touched, setTouched] = useState(false)
  const save = useAction(network.id, {
    mutationFn: () =>
      group === null
        ? api.createGroup(network.id, { name: name.trim() })
        : api.updateGroup(network.id, group.id, { name: name.trim() }),
    success: (saved) => (group === null ? g.created(saved.name) : g.renamed(group.name, saved.name)),
    toastError: false,
  })
  const failure = groupNameFailure(save.error)
  const problem = validateGroupName(name)

  return (
    <FormDialog
      open
      onClose={onClose}
      title={group === null ? g.createTitle : g.renameTitle(group.name)}
      size="sm"
      dirty={group === null ? name !== '' : name.trim() !== group.name}
      requireDirty={group !== null}
      submitLabel={group === null ? g.createSubmit : g.renameSubmit}
      pending={save.isPending}
      error={formError(failure)}
      errorDetail={formErrorDetail(failure)}
      onSubmit={() => {
        setTouched(true)
        if (problem === null) save.mutate(undefined, { onSuccess: onSaved })
      }}
    >
      <Field label={g.nameLabel} error={(touched ? problem : null) ?? fieldError(failure, 'name')}>
        {(props) => (
          <Input
            {...props}
            name="name"
            value={name}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => {
              setName(event.target.value)
              save.reset()
            }}
          />
        )}
      </Field>
    </FormDialog>
  )
}

interface MembersProps {
  network: Network
  group: Group
  nodes: readonly Node[]
}

/** 一个分组的成员：每个一枚，叉号移除；下面选一个节点添加。`All` 的成员是全部节点，只能看。 */
function Members({ network, group, nodes }: MembersProps) {
  const add = useAction(network.id, {
    mutationFn: (node: Node) => api.addGroupMember(network.id, group.id, node.id),
    success: (_data, node) => g.added(node.name, group.name),
  })
  const remove = useAction(network.id, {
    mutationFn: (member: NodeRef) => api.removeGroupMember(network.id, group.id, member.id),
    success: (_data, member) => g.removed(member.name, group.name),
  })
  const pending = add.isPending || remove.isPending
  const members = new Set(group.nodes.map((member) => member.id))
  const candidates = nodes.filter((node) => !members.has(node.id))

  return (
    <div className="space-y-2.5" data-testid={`group-members-${group.name}`}>
      {group.builtin ? <p className="text-[13px] text-muted-foreground">{g.allMembers}</p> : null}
      {group.nodes.length === 0 ? (
        <p className="text-[13px] text-muted-foreground">{g.noMembers}</p>
      ) : (
        <ul aria-label={g.membersOf(group.name)} className="flex flex-wrap gap-1.5">
          {group.nodes.map((member) => (
            <li
              key={member.id}
              className={cn(
                'inline-flex h-7 items-center gap-1 rounded-md bg-muted pl-2.5 text-[13px]',
                group.builtin ? 'pr-2.5' : 'pr-1',
              )}
            >
              <NodeLink
                network={network.id}
                node={member}
                online={nodes.find((node) => node.id === member.id)?.online}
                className="font-normal"
              />
              {group.builtin ? null : (
                <button
                  type="button"
                  disabled={pending}
                  onClick={() => remove.mutate(member)}
                  aria-label={g.removeMember(member.name, group.name)}
                  className="flex size-5 items-center justify-center rounded text-muted-foreground hover:bg-foreground/10 hover:text-foreground"
                >
                  <X className="size-3.5" aria-hidden />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {group.builtin ? null : (
        <div className="w-64">
          <NodeSelect
            nodes={candidates}
            value={null}
            onChange={(id) => {
              const node = nodes.find((candidate) => candidate.id === id)
              if (node !== undefined) add.mutate(node)
            }}
            placeholder={candidates.length === 0 ? g.noCandidates : g.addMember}
            disabled={candidates.length === 0 || pending}
            aria-label={g.addMemberTo(group.name)}
          />
        </div>
      )}
    </div>
  )
}

/** 管理一个分组的成员：一个小窗口，里面是成员的小标签（叉号移除）和添加节点的下拉。改了立即生效。 */
function MembersDialog({ network, group, nodes, onClose }: MembersProps & { onClose: () => void }) {
  return (
    <Dialog open onOpenChange={(next) => (next ? undefined : onClose())}>
      <DialogContent title={g.membersOf(group.name)} size="sm">
        <DialogBody>
          <Members network={network} group={group} nodes={nodes} />
        </DialogBody>
        <DialogFooter>
          <Button onClick={onClose}>{t.common.done}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * 分组：一组节点，访问策略写在分组之间。每个网络都有内置的 `All`（全部节点），排在最前面。
 * 和节点页同一个样子：一行一个分组，成员和用到它的策略写成小标签；点成员改成员，点策略去策略页只看它的；
 * 菜单里管理成员、改名、删除。删除之前现取这个分组，说出它会从几个节点上移除、几条策略一起删掉。
 */
export function GroupsPage() {
  useDocumentTitle(g.title)
  const network = useNetwork()
  const confirm = useConfirm()
  const client = useQueryClient()
  const groups = useQuery(q.groups(network.id))
  const nodes = useQuery(q.nodes(network.id))
  const focus = useFocusRow(groups.data)
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState<{ group: Group | null } | null>(null)
  // 正在管理成员的分组。从操作记录点过来的那个分组只亮出那一行，不自动打开。
  const [members, setMembers] = useState<GroupId | null>(null)

  const remove = useAction(network.id, {
    mutationFn: (group: Group) => api.deleteGroup(network.id, group.id),
    success: (deleted) => g.deleted(deleted.name),
  })

  const onDelete = async (listed: Group) => {
    // 后果取自这个分组自己的应答，不用列表里那一份：列表可能是几秒之前的。
    let group: Group
    try {
      group = await client.query(q.group(network.id, listed.id))
    } catch (error) {
      toast.error(errorMessage(error), undefined, errorDetail(error))
      return
    }
    const confirmed = await confirm({
      tone: 'danger',
      title: g.deleteTitle(group.name),
      body: g.deleteImpact(group.nodes.length, group.rules.length) ?? undefined,
      confirmLabel: g.deleteConfirm,
    })
    if (confirmed) remove.mutate(group)
  }

  const needle = search.trim().toLowerCase()
  const all = groups.data ?? []
  const list = all.filter((group) => needle === '' || group.name.toLowerCase().includes(needle))
  const allNodes = nodes.data ?? []
  const online = (id: NodeId) => allNodes.find((node) => node.id === id)?.online
  const managing = all.find((group) => group.id === members)

  return (
    <Page>
      <PageHeader
        title={g.title}
        description={g.subtitle}
        actions={
          <Button variant="primary" onClick={() => setEditing({ group: null })}>
            <Plus aria-hidden />
            {g.create}
          </Button>
        }
      />
      {focus.missing ? (
        <Notice className="mb-4" tone="warn">
          {g.focusMissing(focus.focus ?? 0)}
        </Notice>
      ) : null}
      <Toolbar>
        <SearchBox value={search} onChange={setSearch} placeholder={g.searchPlaceholder} />
      </Toolbar>
      {groups.isError ? (
        <ErrorState title={g.loadFailed} error={groups.error} onRetry={() => void groups.refetch()} />
      ) : (
        <>
          <Table stack>
            <thead>
              <tr>
                <Th>{g.colName}</Th>
                <Th>{g.colNodes}</Th>
                <Th>{g.colRules}</Th>
                <Th className="w-0">
                  <span className="sr-only">{t.common.moreActions}</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {groups.isPending ? <SkeletonRows columns={COLUMNS} rows={3} /> : null}
              {list.map((group) => (
                <Tr
                  key={group.id}
                  ref={focus.rowRef(group.id)}
                  className={cn('h-16 hover:bg-muted/50', focus.focus === group.id && FOCUSED_ROW)}
                  data-testid={`group-row-${group.name}`}
                >
                  <Td cell="main">
                    <span className="inline-flex items-center gap-2.5">
                      <span className="font-medium">{group.name}</span>
                      {group.builtin ? (
                        <Tooltip content={g.builtinTip}>
                          <Badge tone="outline" tabIndex={0}>
                            {g.builtin}
                          </Badge>
                        </Tooltip>
                      ) : null}
                    </span>
                  </Td>
                  <Td cell="row" label={g.colNodes} className="[--stack-label-top:0.3rem]">
                    {/* 成员和节点页的"分组"一样：点开改。All 的成员是全部节点，只能看。 */}
                    {group.builtin ? (
                      <NodeList nodes={group.nodes} online={online} empty={g.noMembers} />
                    ) : (
                      <CellButton
                        onClick={() => setMembers(group.id)}
                        aria-label={g.membersOf(group.name)}
                        className={cn(group.nodes.length === 0 && 'text-[13px] text-muted-foreground')}
                      >
                        {group.nodes.length === 0 ? (
                          <span className="inline-flex items-center gap-1">
                            <Plus className="size-3" aria-hidden />
                            {g.addMember}
                          </span>
                        ) : (
                          <NodeList nodes={group.nodes} online={online} />
                        )}
                      </CellButton>
                    )}
                  </Td>
                  <Td cell="row" label={g.colRules} className="[--stack-label-top:0.3rem]">
                    <Link
                      to={`${networkPath(network.id, 'access')}?group=${group.id}`}
                      aria-label={g.rulesOf(group.name)}
                      className="-mx-1.5 inline-block rounded-md px-1.5 py-1 hover:bg-muted"
                    >
                      <PolicyList rules={group.rules} empty={g.noRules} />
                    </Link>
                  </Td>
                  <Td cell="end" className="pl-0 text-right">
                    {/* All 不能改名、删除、增减成员，没有菜单。 */}
                    {group.builtin ? null : (
                      <RowActions label={t.common.actionsFor(group.name)}>
                        <DropdownMenuItem onSelect={() => setMembers(group.id)}>
                          <Server aria-hidden />
                          {g.menuMembers}
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => setEditing({ group })}>
                          <Pencil aria-hidden />
                          {g.menuRename}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem danger onSelect={() => void onDelete(group)}>
                          <Trash2 aria-hidden />
                          {g.menuDelete}
                        </DropdownMenuItem>
                      </RowActions>
                    )}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
          {groups.isSuccess && list.length === 0 ? <EmptyState icon={Boxes} title={g.noMatch} /> : null}
          {list.length > 0 ? (
            <TableFooter>
              <RowsTotal shown={list.length} total={all.length} />
            </TableFooter>
          ) : null}
        </>
      )}

      {editing !== null ? (
        <NameDialog
          key={editing.group?.id ?? 'new'}
          network={network}
          group={editing.group}
          onClose={() => setEditing(null)}
          onSaved={(saved) => {
            setEditing(null)
            // 新建的分组还没有成员：接着打开成员，就能添加。
            if (editing.group === null) setMembers(saved.id)
          }}
        />
      ) : null}
      {managing !== undefined ? (
        <MembersDialog network={network} group={managing} nodes={allNodes} onClose={() => setMembers(null)} />
      ) : null}
    </Page>
  )
}
