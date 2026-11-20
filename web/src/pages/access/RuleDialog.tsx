import { useMemo, useState } from 'react'

import { api } from '@/api/endpoints'
import { formError, formErrorDetail, formFailure } from '@/api/formErrors'
import { useAction } from '@/api/queries'
import { type AccessGraph, type Direction, type GroupId, type GroupRef, type Network, type Rule } from '@/api/types'
import { accessDiff, type RuleLike, sameRule } from '@/access/reach'
import { Combobox, type ComboOption } from '@/components/combobox'
import { FormDialog } from '@/components/form-dialog'
import { GroupChip } from '@/components/groups'
import { Notice } from '@/components/notice'
import { ruleLabel } from '@/lib/rules'
import { Field } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { t } from '@/i18n'
import { validateTitle } from '@/lib/validate'

const d = t.access.dialog

export interface RuleDraft {
  src?: GroupId
  dst?: GroupId
}

interface RuleDialogProps {
  network: Network
  graph: AccessGraph
  /** 要编辑的规则；新建时是 `null`。 */
  rule: Rule | null
  /** 新建时预填的两个分组（从访问检查的"新建规则"带过来）。 */
  draft?: RuleDraft
  open: boolean
  onClose: () => void
}

/**
 * 新建和编辑规则：一个小对话框，一屏。规则摆成一句话的形状——分组 a、方向、分组 b——
 * 下面用白话把它的意思说出来，再说保存之后有什么影响。分组只能从已有的里面选。
 */
export function RuleDialog({ network, graph, rule, draft, open, onClose }: RuleDialogProps) {
  const [src, setSrc] = useState<GroupId | null>(rule?.src.id ?? draft?.src ?? null)
  const [dst, setDst] = useState<GroupId | null>(rule?.dst.id ?? draft?.dst ?? null)
  const [direction, setDirection] = useState<Direction>(rule?.direction ?? 'both')
  const [name, setName] = useState(rule?.name ?? '')
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)
  const [touched, setTouched] = useState(false)

  const save = useAction(network.id, {
    mutationFn: (body: { src: GroupId; dst: GroupId; direction: Direction; name: string; enabled: boolean }) =>
      rule === null ? api.createRule(network.id, body) : api.updateRule(network.id, rule.id, body),
    success: (saved) => (rule === null ? d.created(ruleLabel(saved)) : d.saved(ruleLabel(saved))),
    toastError: false,
  })
  const failure = formFailure(save.error, {})

  const groupOf = (id: GroupId) => graph.groups.find((group) => group.id === id)
  const memberCount = (id: GroupId) => groupOf(id)?.nodes.length ?? 0
  // 规则写成 `a ⇄ b` 时用的名字；列表里没有（刚删掉）时写编号。
  const refOf = (id: GroupId): GroupRef => ({ id, name: groupOf(id)?.name ?? `#${id}`, builtin: groupOf(id)?.builtin })
  const options = useMemo<ComboOption<GroupId>[]>(
    () =>
      graph.groups.map((group) => ({
        value: group.id,
        label: group.name,
        hint: t.access.graph.members(group.nodes.length),
      })),
    [graph.groups],
  )

  const others = graph.rules.filter((other) => other.id !== rule?.id)
  const duplicate =
    src !== null && dst !== null
      ? others.find((other) => sameRule(other, { src: { id: src }, dst: { id: dst }, direction }))
      : undefined

  // 影响：把这条规则换成现在填的样子，前后一比。
  const impact = useMemo(() => {
    if (src === null || dst === null) return null
    const proposed: RuleLike = { src: { id: src }, dst: { id: dst }, direction, enabled }
    return accessDiff(graph.groups, graph.rules, [...others, proposed])
    // others 由 graph.rules 和 rule 推出，不必单独列。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph.groups, graph.rules, rule?.id, src, dst, direction, enabled])

  const nameProblem = validateTitle(name, false)
  const dirty =
    rule === null
      ? src !== (draft?.src ?? null) || dst !== (draft?.dst ?? null) || name !== '' || direction !== 'both'
      : src !== rule.src.id ||
        dst !== rule.dst.id ||
        direction !== rule.direction ||
        name !== rule.name ||
        enabled !== rule.enabled

  const nodesOf = (id: GroupId) =>
    groupOf(id)?.builtin === true ? d.nodesOfAll(memberCount(id)) : d.nodesOf(refOf(id).name, memberCount(id))
  let sentence: string | null = null
  if (src !== null && dst !== null) {
    const a = nodesOf(src)
    const b = nodesOf(dst)
    if (src === dst) sentence = d.sentenceSame(a)
    else sentence = direction === 'both' ? d.sentenceBoth(a, b) : d.sentenceOneWay(a, b)
  }

  let impactText: string | null = null
  if (impact !== null && duplicate === undefined) {
    if (!enabled) impactText = d.impactDisabled
    else if (impact.gained > 0 && impact.lost > 0) impactText = d.impactBoth(impact.gained, impact.lost)
    else if (impact.gained > 0) impactText = d.impactGain(impact.gained)
    else if (impact.lost > 0) impactText = d.impactLoss(impact.lost)
    else impactText = d.impactNone
  }

  const submit = () => {
    setTouched(true)
    if (src === null || dst === null || duplicate !== undefined || nameProblem !== null) return
    save.mutate({ src, dst, direction, name: name.trim(), enabled }, { onSuccess: onClose })
  }

  const fallbackName =
    src !== null && dst !== null ? ruleLabel({ name: '', src: refOf(src), dst: refOf(dst), direction }) : 'a ⇄ b'
  const emptyGroups = [...new Set([src, dst])].filter(
    (id): id is GroupId => id !== null && groupOf(id)?.builtin !== true && memberCount(id) === 0,
  )

  return (
    <FormDialog
      open={open}
      onClose={onClose}
      title={rule === null ? d.createTitle : d.editTitle}
      dirty={dirty}
      requireDirty={rule !== null}
      submitLabel={rule === null ? d.submitCreate : d.submitEdit}
      pending={save.isPending}
      canSubmit={duplicate === undefined}
      error={formError(failure)}
      errorDetail={formErrorDetail(failure)}
      onSubmit={submit}
    >
      <div className="grid grid-cols-1 items-start gap-3 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        <Field label={d.srcLabel} error={touched && src === null ? d.groupRequired : null}>
          {(props) => (
            <Combobox
              {...props}
              value={src}
              onChange={setSrc}
              options={options}
              placeholder={t.groups.picker.pickOne}
              searchPlaceholder={t.groups.picker.search}
              emptyText={t.groups.picker.noneFound}
            />
          )}
        </Field>
        <Field label={d.directionLabel}>
          {() => (
            <Segmented
              aria-label={d.directionLabel}
              value={direction}
              onChange={setDirection}
              options={[
                { value: 'both', label: d.both },
                { value: 'one_way', label: d.oneWay },
              ]}
              className="h-9 items-center"
            />
          )}
        </Field>
        <Field label={d.dstLabel} error={touched && dst === null ? d.groupRequired : null}>
          {(props) => (
            <Combobox
              {...props}
              value={dst}
              onChange={setDst}
              options={options}
              placeholder={t.groups.picker.pickOne}
              searchPlaceholder={t.groups.picker.search}
              emptyText={t.groups.picker.noneFound}
            />
          )}
        </Field>
      </div>

      {/* 两个分组都选好了才有这一块：用一句话说出规则的意思，再说保存之后的影响。 */}
      <div aria-live="polite">
        {sentence === null ? null : (
          <div className="rounded-md bg-muted/70 px-4 py-3 text-sm">
            <p className="font-medium" data-testid="rule-sentence">
              {sentence}
            </p>
            {direction === 'one_way' && src !== dst ? (
              <p className="mt-1 text-[13px] text-muted-foreground">{d.oneWayNote}</p>
            ) : null}
            {impactText !== null ? (
              <p
                className={
                  impact !== null && impact.lost > 0 && enabled
                    ? 'mt-2 text-[13px] font-medium text-warn'
                    : 'mt-2 text-[13px] text-muted-foreground'
                }
                data-testid="rule-impact"
              >
                {impactText}
              </p>
            ) : null}
          </div>
        )}
      </div>

      {duplicate !== undefined ? <Notice tone="danger">{d.duplicate(ruleLabel(duplicate))}</Notice> : null}
      {emptyGroups.map((id) => (
        <Notice key={id} tone="warn">
          <span className="inline-flex flex-wrap items-center gap-1.5">
            <GroupChip name={refOf(id).name} builtin={refOf(id).builtin} />
            {d.emptyGroup}
          </span>
        </Notice>
      ))}

      {/* 不填名字时规则写成 `a ⇄ b`：占位里就是它会显示成的样子。 */}
      <Field label={d.nameLabel} optional={t.common.optional} error={touched ? nameProblem : null}>
        {(props) => (
          <Input {...props} value={name} placeholder={fallbackName} onChange={(event) => setName(event.target.value)} />
        )}
      </Field>

      {rule !== null ? (
        <label className="flex items-center gap-2.5 text-sm">
          <Switch checked={enabled} onCheckedChange={setEnabled} />
          {d.enabledLabel}
        </label>
      ) : null}
    </FormDialog>
  )
}
