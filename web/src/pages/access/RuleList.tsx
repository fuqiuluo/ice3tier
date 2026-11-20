import { Pencil, Trash2 } from 'lucide-react'
import { useEffect, useRef } from 'react'

import { type AccessGraph, type Direction, type GroupRef, type Network, type Rule } from '@/api/types'
import { isAllToAll } from '@/access/reach'
import { GroupChip } from '@/components/groups'
import { RowActions } from '@/components/row-actions'
import { DirectionMark } from '@/components/rule'
import { Table, Td, Th, Tr } from '@/components/table'
import { Badge } from '@/components/ui/badge'
import { DropdownMenuItem, DropdownMenuSeparator } from '@/components/ui/dropdown-menu'
import { Switch } from '@/components/ui/switch'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { ruleLabel } from '@/lib/rules'
import { cn } from '@/lib/utils'

import { useRuleActions } from './useRuleActions'

const a = t.access

interface RuleListProps {
  network: Network
  graph: AccessGraph
  rules: readonly Rule[]
  /** 从操作记录、关系图点过来的那条规则：这一行亮起来，滚动到看得见的地方。 */
  focused: number | null
  onEdit: (rule: Rule) => void
}

/** 一个分组：分组的小标签，悬停写它现在有几个节点。 */
function GroupCell({ group, graph }: { group: GroupRef; graph: AccessGraph }) {
  const members = graph.groups.find((candidate) => candidate.id === group.id)?.nodes.length ?? 0
  return (
    <Tooltip content={a.members(members)}>
      <span tabIndex={0} className="inline-flex rounded-md">
        <GroupChip name={group.name} builtin={group.builtin} />
      </span>
    </Tooltip>
  )
}

/** 方向：箭头加一个词，和别的表格里的文字一样大小。 */
function DirectionCell({ direction }: { direction: Direction }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[13px] whitespace-nowrap">
      <DirectionMark direction={direction} />
      {direction === 'both' ? a.directionBoth : a.directionOneWay}
    </span>
  )
}

/**
 * 策略表，和节点、分组的表一个样子：一条策略一行，名字、启用开关、来源、方向、目标、操作菜单。
 * 停用的那几格变淡，开关照样能拨。策略只有"允许"，没有顺序和优先级，所以按编号排、不给拖动。
 */
export function RuleList({ network, graph, rules, focused, onEdit }: RuleListProps) {
  const actions = useRuleActions(network, graph)
  const rows = useRef(new Map<number, HTMLTableRowElement>())

  useEffect(() => {
    if (focused !== null) rows.current.get(focused)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [focused])

  return (
    <Table stack>
      <thead>
        <tr>
          <Th>{a.colName}</Th>
          <Th className="w-20">{a.colEnabled}</Th>
          <Th>{a.colSource}</Th>
          <Th>{a.colDirection}</Th>
          <Th>{a.colTarget}</Th>
          <Th className="w-0">
            <span className="sr-only">{t.common.moreActions}</span>
          </Th>
        </tr>
      </thead>
      <tbody>
        {rules.map((rule) => {
          const label = ruleLabel(rule)
          return (
            <Tr
              key={rule.id}
              ref={(element) => {
                if (element === null) rows.current.delete(rule.id)
                else rows.current.set(rule.id, element)
              }}
              data-testid={`rule-row-${rule.id}`}
              data-highlighted={focused === rule.id || undefined}
              className={cn('h-16 hover:bg-muted/50', focused === rule.id && 'bg-accent/60 hover:bg-accent')}
            >
              <Td cell="main">
                <span className="inline-flex items-center gap-2.5">
                  {rule.name === '' ? (
                    <span className="text-muted-foreground">{a.unnamed}</span>
                  ) : (
                    <span className="font-medium">{rule.name}</span>
                  )}
                  {isAllToAll(rule) ? (
                    <Tooltip content={a.defaultTip}>
                      <Badge tone="outline" tabIndex={0}>
                        {a.defaultBadge}
                      </Badge>
                    </Tooltip>
                  ) : null}
                </span>
              </Td>
              <Td cell="end">
                <Switch
                  aria-label={a.ruleSwitch(label)}
                  checked={rule.enabled}
                  disabled={actions.pendingRuleId === rule.id}
                  onCheckedChange={(checked) => void actions.toggle(rule, checked)}
                />
              </Td>
              <Td cell="inline" className={cn(!rule.enabled && 'opacity-55')}>
                <GroupCell group={rule.src} graph={graph} />
              </Td>
              <Td cell="inline" className={cn(!rule.enabled && 'opacity-55')}>
                <DirectionCell direction={rule.direction} />
              </Td>
              <Td cell="inline" className={cn(!rule.enabled && 'opacity-55')}>
                <GroupCell group={rule.dst} graph={graph} />
              </Td>
              <Td cell="end" className="pl-0 text-right">
                <RowActions label={a.ruleActions(label)}>
                  <DropdownMenuItem onSelect={() => onEdit(rule)}>
                    <Pencil aria-hidden />
                    {a.menuEdit}
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem danger onSelect={() => void actions.destroy(rule)}>
                    <Trash2 aria-hidden />
                    {a.menuDelete}
                  </DropdownMenuItem>
                </RowActions>
              </Td>
            </Tr>
          )
        })}
      </tbody>
    </Table>
  )
}
