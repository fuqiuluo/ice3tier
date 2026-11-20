import { useQuery } from '@tanstack/react-query'
import { ChevronRight, DoorOpen, Globe, Plus, Server, Workflow, X } from 'lucide-react'
import { type KeyboardEvent, type ReactNode, useId, useState } from 'react'

import { q } from '@/api/queries'
import { type ExitSettings, type Network, type NodeDetail } from '@/api/types'
import { SkeletonBlock } from '@/components/states'
import { StatusText } from '@/components/status'
import { BoxCard, BoxCardHeader } from '@/components/ui/card'
import { FormError } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { Tooltip } from '@/components/ui/tooltip'
import { BytesInput, ClassSelect, UsageBar } from '@/components/usage'
import { t } from '@/i18n'
import { formatBytes } from '@/lib/format'
import { formatAge } from '@/lib/time'
import { quotaView } from '@/lib/usage'
import { COMMON_PORTS, portName } from '@/lib/ports'
import { MAX_QUOTA_RESET_DAY, splitList, validatePort } from '@/lib/validate'
import { exitHealthView } from '@/lib/exitView'

import { useSaveExit } from './exitActions'
import {
  exitFormFrom,
  type ExitFormProblems,
  exitFormProblems,
  type ExitFormState,
  exitFormToInput,
  exitFormValid,
} from './exitFormState'
import { SettingRow } from '@/components/setting-row'

/*
 * 出口页上的几块：卡片里平铺的出口设置（改了就保存，没有对话框），和旁边的两张卡片：用量、能用它的节点。
 */

const d = t.nodes.detail
const e = t.exits

type Field = keyof ExitFormProblems

/** 回车就保存（和离开输入框一样）。 */
const onEnter = (save: () => void) => (event: KeyboardEvent<HTMLInputElement>) => {
  if (event.key === 'Enter') {
    event.preventDefault()
    save()
  }
}

/**
 * 出口设置的表单：设置列表和端口限制卡片共用一份。改了就保存：开关、分段选择、下拉是一改就存；
 * 输入框在离开或回车时存。`PUT …/exit` 是整个替换，所以每次交的都是全部的设置。值不对时不交。
 */
function useExitForm(network: Network, node: NodeDetail, exit: ExitSettings) {
  const save = useSaveExit(network, node)
  const savedKey = JSON.stringify(exit)
  const [synced, setSynced] = useState(savedKey)
  const [form, setForm] = useState(() => exitFormFrom(exit))
  const [touched, setTouched] = useState<ReadonlySet<Field>>(new Set())
  // 服务器那边的设置变了（保存成功、别处改了）：表单跟着变。
  if (synced !== savedKey) {
    setSynced(savedKey)
    setForm(exitFormFrom(exit))
    setTouched(new Set())
  }
  const problems = exitFormProblems(form)

  const commit = (next: ExitFormState, field?: Field) => {
    setForm(next)
    if (field !== undefined) setTouched((prev) => new Set(prev).add(field))
    if (!exitFormValid(next)) return
    // 没变就不交：离开一个没改过的输入框不该弹"已保存"。
    if (JSON.stringify(exitFormToInput(next)) === JSON.stringify(exitFormToInput(exitFormFrom(exit)))) return
    void save.submit(next).then((ok) => {
      // 没存上（打开局域网时点了取消、或者被拒绝了）：回到服务器上的设置。
      if (!ok) setForm(exitFormFrom(exit))
    })
  }

  return {
    form,
    setForm,
    commit,
    problems,
    shown: (field: Field) => (touched.has(field) ? problems[field] : null),
    save,
  }
}

type ExitForm = ReturnType<typeof useExitForm>

/**
 * 出口的设置，都在出口卡片里，一行一项。端口限制和"二次代理"也是一行一个开关，
 * 打开之后在那一行下面填端口、代理的地址。
 */
function ExitSettingsList({ node, ctl }: { node: NodeDetail; ctl: ExitForm }) {
  const { form, setForm, commit, problems, shown, save } = ctl
  const ids = { lan: useId(), quota: useId(), family: useId(), connects: useId(), ports: useId(), upstream: useId() }
  const classId = useId()
  const upstreamInput = useId()
  const savedUpstream = node.exit?.upstream_socks5 ?? null
  // 开关打开、地址还没填时，开关要看起来开着：这个状态只在页面上，服务器上还是没有代理。
  const [upstreamOpened, setUpstreamOpened] = useState(false)
  const upstreamOn = savedUpstream !== null || upstreamOpened

  return (
    <div>
      <div className="divide-y">
        <SettingRow label={d.exitFormLan} hint={d.exitFormLanHint} htmlFor={ids.lan}>
          <Switch id={ids.lan} checked={form.lan} onCheckedChange={(lan) => commit({ ...form, lan })} />
        </SettingRow>

        <SettingRow
          label={d.exitFormQuota}
          hint={d.exitFormQuotaHint}
          htmlFor={ids.quota}
          error={shown('quota') ?? shown('resetDay')}
        >
          <div
            className="flex flex-wrap items-center gap-2"
            onBlur={(event) => {
              // 在数和单位、账期之间挪动焦点不算离开。
              if (event.relatedTarget instanceof Node && event.currentTarget.contains(event.relatedTarget)) return
              commit(form, form.quota.trim() === '' ? 'quota' : problems.quota === null ? 'resetDay' : 'quota')
            }}
          >
            <BytesInput
              id={ids.quota}
              value={form.quota}
              unit={form.quotaUnit}
              unitLabel={d.exitFormQuotaUnit}
              onChange={(quota, quotaUnit) => setForm({ ...form, quota, quotaUnit })}
            />
            {form.quota.trim() !== '' ? (
              <span className="flex items-center gap-1.5 text-[13px] text-muted-foreground whitespace-nowrap">
                {d.exitResetBefore}
                <Input
                  type="number"
                  min={1}
                  max={MAX_QUOTA_RESET_DAY}
                  inputMode="numeric"
                  aria-label={d.exitFormResetDay}
                  className="w-16 tabular"
                  value={form.resetDay}
                  onChange={(event) => setForm({ ...form, resetDay: event.target.value })}
                />
                {d.exitResetAfter}
              </span>
            ) : null}
          </div>
        </SettingRow>

        <SettingRow label={d.exitFormFamily} hint={d.exitFormFamilyHint} labelId={ids.family}>
          <Segmented
            aria-label={d.exitFormFamily}
            size="sm"
            value={form.family}
            onChange={(family) => commit({ ...form, family })}
            options={[
              { value: 'any', label: d.exitFormFamilyAny },
              { value: 'ipv4', label: d.exitFormFamilyIpv4 },
              { value: 'ipv6', label: d.exitFormFamilyIpv6 },
            ]}
          />
        </SettingRow>

        <SettingRow
          label={d.exitFormConnects}
          hint={d.exitFormConnectsHint}
          htmlFor={ids.connects}
          error={shown('connects')}
        >
          <span className="flex items-center gap-2">
            <Input
              id={ids.connects}
              inputMode="numeric"
              className="w-24 tabular"
              placeholder={t.common.unlimited}
              value={form.connects}
              onChange={(event) => setForm({ ...form, connects: event.target.value })}
              onBlur={() => commit(form, 'connects')}
              onKeyDown={onEnter(() => commit(form, 'connects'))}
            />
            <span className="text-[13px] text-muted-foreground">{d.exitFormConnectsUnit}</span>
          </span>
        </SettingRow>

        <SettingRow label={d.exitFormClass} htmlFor={classId}>
          <ClassSelect
            id={classId}
            className="w-56"
            value={form.serviceClass}
            inheritLabel={d.exitFormClassNone}
            onChange={(serviceClass) => commit({ ...form, serviceClass })}
          />
        </SettingRow>

        {/* 端口限制：默认关着（任何端口都放行）；打开之后填允许的端口。只限制互联网目标。 */}
        <div data-testid="exit-ports">
          <SettingRow label={d.exitPortsTitle} hint={d.exitPortsDesc} htmlFor={ids.ports}>
            <Switch
              id={ids.ports}
              aria-label={d.exitPortsSwitch(node.name)}
              checked={form.limitPorts}
              onCheckedChange={(on) =>
                on ? setForm({ ...form, limitPorts: true }) : commit({ ...form, limitPorts: false })
              }
            />
          </SettingRow>
          {form.limitPorts ? (
            <div className="px-5 pb-4">
              <PortsEditor ctl={ctl} />
            </div>
          ) : null}
        </div>

        {/* 二次代理：默认关着；打开之后填这台机器上另一个代理程序（如 Clash）的地址。 */}
        <div data-testid="exit-upstream">
          <SettingRow label={d.upstreamTitle} hint={d.upstreamDesc} htmlFor={ids.upstream}>
            <Switch
              id={ids.upstream}
              aria-label={d.upstreamSwitch(node.name)}
              checked={upstreamOn}
              onCheckedChange={(next) => {
                setUpstreamOpened(next)
                if (!next) commit({ ...form, upstream: '' })
              }}
            />
          </SettingRow>
          {upstreamOn ? (
            <div className="space-y-3 px-5 pb-4">
              <SettingRow
                label={d.upstreamAddr}
                hint={d.upstreamAddrHint}
                htmlFor={upstreamInput}
                error={shown('upstream')}
                className="px-0 py-0"
              >
                <Input
                  id={upstreamInput}
                  className="w-56 font-mono"
                  placeholder="127.0.0.1:7890"
                  autoFocus={savedUpstream === null}
                  value={form.upstream}
                  onChange={(event) => setForm({ ...form, upstream: event.target.value })}
                  onBlur={() => form.upstream.trim() !== '' && commit(form, 'upstream')}
                  onKeyDown={onEnter(() => commit(form, 'upstream'))}
                />
              </SettingRow>
              <UpstreamRoute node={node} proxy={savedUpstream} />
            </div>
          ) : null}
        </div>
      </div>
      <FormError message={save.error} detail={save.errorDetail} className="mx-5 mb-4" />
    </div>
  )
}

/** 列表里现在的端口：输入框里的字解析出来的，写错的那一项不算。 */
function portsOf(raw: string): number[] {
  return [
    ...new Set(
      splitList(raw)
        .filter((item) => validatePort(item) === null)
        .map(Number),
    ),
  ].sort((x, y) => x - y)
}

/**
 * 允许的端口：一个端口一个小块（旁边写着它通常是什么协议），叉号去掉；输入框里回车、逗号或空格加上；
 * 下面一排常用的端口一点就加。加了、去了都马上保存。一个都不剩时不保存，说"至少一个端口"。
 */
function PortsEditor({ ctl }: { ctl: ExitForm }) {
  const { form, commit } = ctl
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | null>(null)
  const inputId = useId()
  const ports = portsOf(form.ports)

  const save = (next: number[]) => {
    setError(next.length === 0 ? t.validate.portListEmpty : null)
    commit({ ...form, limitPorts: true, ports: next.join(', ') }, 'ports')
  }

  const addDraft = () => {
    const items = splitList(draft)
    if (items.length === 0) return
    const bad = items.find((item) => validatePort(item) !== null)
    if (bad !== undefined) {
      setError(t.validate.portListItem(bad))
      return
    }
    setDraft('')
    save([...new Set([...ports, ...items.map(Number)])].sort((x, y) => x - y))
  }

  return (
    <div className="space-y-3">
      <div className="flex min-h-9 flex-wrap items-center gap-1.5">
        <ul className="contents" aria-label={d.exitFormPorts}>
          {ports.map((port) => (
            <li
              key={port}
              className="inline-flex h-7 items-center gap-1.5 rounded-md bg-muted pr-1 pl-2 text-[13px] tabular"
            >
              <span className="font-medium">{port}</span>
              {portName(port) !== undefined ? <span className="text-muted-foreground">{portName(port)}</span> : null}
              <button
                type="button"
                onClick={() => save(ports.filter((other) => other !== port))}
                aria-label={d.exitPortsRemove(port)}
                className="flex size-5 items-center justify-center rounded text-muted-foreground hover:bg-foreground/10 hover:text-foreground"
              >
                <X className="size-3.5" aria-hidden />
              </button>
            </li>
          ))}
        </ul>
        <Input
          id={inputId}
          aria-label={d.exitPortsAdd}
          inputMode="numeric"
          autoFocus={ports.length === 0}
          placeholder={d.exitPortsAdd}
          className="h-7 w-28 tabular"
          value={draft}
          onChange={(event) => {
            setError(null)
            // 打了逗号或空格就当作一个端口写完了。
            if (/[,\s]$/.test(event.target.value)) {
              setDraft(event.target.value)
              const items = splitList(event.target.value)
              if (items.length > 0 && items.every((item) => validatePort(item) === null)) {
                setDraft('')
                save([...new Set([...ports, ...items.map(Number)])].sort((x, y) => x - y))
              }
              return
            }
            setDraft(event.target.value)
          }}
          onBlur={addDraft}
          onKeyDown={onEnter(addDraft)}
        />
      </div>
      {error !== null ? (
        <p role="alert" className="text-[13px] text-danger">
          {error}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-1.5 text-[13px]">
        <span className="mr-1 text-muted-foreground">{d.exitPortsCommon}</span>
        {COMMON_PORTS.filter((port) => !ports.includes(port)).map((port) => (
          <button
            key={port}
            type="button"
            onClick={() => save([...ports, port].sort((x, y) => x - y))}
            className="inline-flex h-7 items-center gap-1 rounded-md border border-dashed px-2 text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground"
          >
            <Plus className="size-3.5" aria-hidden />
            <span className="tabular">{port}</span>
            {portName(port) !== undefined ? <span className="text-faint">{portName(port)}</span> : null}
          </button>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">{d.exitPortsHelp}</p>
    </div>
  )
}

/**
 * 打开"二次代理"之后的一行路线：用它的节点 → 这个出口 → 二次代理 → 网站，网站看到的是代理的地址。
 * 读屏读的是下面那句话，图本身不读。
 */
function UpstreamRoute({ node, proxy }: { node: NodeDetail; proxy: string | null }) {
  const stop = (icon: ReactNode, label: string) => (
    <span className="inline-flex items-center gap-1.5 rounded-md border bg-card px-2 py-1 text-xs whitespace-nowrap [&>svg]:size-3.5 [&>svg]:text-muted-foreground">
      {icon}
      {label}
    </span>
  )
  const arrow = <ChevronRight aria-hidden className="size-3.5 shrink-0 text-faint" />
  return (
    <figure className="flex flex-wrap items-center gap-1.5 rounded-lg bg-muted/50 px-3 py-2.5">
      <span aria-hidden className="contents">
        {stop(<Server />, d.upstreamDiagUsers)}
        {arrow}
        {stop(<DoorOpen />, node.name)}
        {arrow}
        {stop(<Workflow />, proxy ?? d.upstreamDiagProxy)}
        {arrow}
        {stop(<Globe />, d.upstreamDiagSeesProxy)}
      </span>
      <figcaption className="sr-only">{d.upstreamDiagOn}</figcaption>
    </figure>
  )
}

/** 一项数：上面一行灰色的小字是名字，下面是值。 */
function Stat({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[13px] text-muted-foreground">
        {hint !== undefined ? (
          <Tooltip content={hint}>
            <span tabIndex={0} className="cursor-help rounded-sm underline decoration-dotted underline-offset-4">
              {label}
            </span>
          </Tooltip>
        ) : (
          label
        )}
      </dt>
      <dd className="mt-1.5 text-sm font-medium tabular">{children}</dd>
    </div>
  )
}

/**
 * 出口的用量：它自己报的、这次启动以来的累计。标题右边是健康（只算出口自己的失败）；设了配额时最上面是本账期的进度条。
 */
function ExitUsageCard({ network, node }: { network: Network; node: NodeDetail }) {
  const exits = useQuery(q.exits(network.id))
  const view = exits.data?.find((candidate) => candidate.node.id === node.id)
  // 出口的视图里直接有经它出去的代理。
  const proxies = view?.proxies?.length ?? 0
  const health = view === undefined ? null : exitHealthView(view)
  const usage = view?.usage ?? null

  return (
    <BoxCard data-testid="exit-usage">
      <BoxCardHeader
        title={d.exitUsageTitle}
        tip={e.usageTip}
        action={
          health === null ? null : (
            <Tooltip content={`${health.detail}。${e.health.rule}`}>
              <span tabIndex={0} className="rounded-sm">
                <StatusText tone={health.tone} className="gap-1.5 text-[13px]">
                  {health.label}
                </StatusText>
              </span>
            </Tooltip>
          )
        }
      />
      {/* 有几个代理经这里出去：代理在代理页里建，这里只说个数。 */}
      <p className="border-b px-5 py-2.5 text-[13px] text-muted-foreground" data-testid="exit-proxies">
        {d.exitProxies(proxies)}
      </p>
      {exits.isPending ? (
        <div className="px-5 py-4">
          <SkeletonBlock lines={2} />
        </div>
      ) : usage === null ? (
        <p className="px-5 py-6 text-center text-[13px] text-muted-foreground">
          {e.usageNone} · {e.usageNoneHint}
        </p>
      ) : (
        <>
          {usage.quota !== null ? (
            <div className="border-b px-5 py-4">
              <p className="mb-2 text-[13px] text-muted-foreground">{d.exitFormQuota}</p>
              <UsageBar view={quotaView(usage.quota)} label={e.quotaLabel(node.name)}>
                <span className="text-xs text-muted-foreground">{quotaView(usage.quota).resets}</span>
              </UsageBar>
            </div>
          ) : null}
          <dl className="grid grid-cols-3 gap-x-6 gap-y-5 px-5 py-5">
            <Stat label={e.rowActive}>{usage.active}</Stat>
            <Stat label={e.rowRequests}>{usage.total}</Stat>
            <Stat label={e.rowTraffic}>
              <span className="whitespace-nowrap">
                ↑ {formatBytes(usage.bytes_to_target)} ↓ {formatBytes(usage.bytes_from_target)}
              </span>
            </Stat>
            <Stat label={e.rowFailedTarget}>{usage.failed_by_target}</Stat>
            <Stat label={e.rowRefused} hint={e.rowRefusedHint}>
              {usage.refused}
            </Stat>
            <Stat label={e.rowFailedExit}>{usage.failed_by_exit}</Stat>
            <Stat label={e.rowAborted}>{usage.aborted}</Stat>
          </dl>
          <p className="border-t px-5 py-2.5 text-xs text-muted-foreground">
            {e.usageTraffic}
            {view?.reported_secs_ago == null ? null : ` · ${formatAge(view.reported_secs_ago)}${e.rowAge}`}
          </p>
        </>
      )}
    </BoxCard>
  )
}

interface ExitEnabledLayoutProps {
  network: Network
  node: NodeDetail
  exit: ExitSettings
  /** 出口卡片本身（顶上的开关等）由出口页给，这里只给它里面的设置列表。 */
  renderCard: (settings: ReactNode) => ReactNode
}

/**
 * 启用了的出口：宽屏分两栏。左边是出口卡片（开关在标题栏，下面一行一项设置）；右边是用量。
 */
export function ExitEnabledLayout({ network, node, exit, renderCard }: ExitEnabledLayoutProps) {
  const ctl = useExitForm(network, node, exit)
  return (
    <div className="grid items-start gap-5 @6xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      {renderCard(<ExitSettingsList node={node} ctl={ctl} />)}
      <ExitUsageCard network={network} node={node} />
    </div>
  )
}
