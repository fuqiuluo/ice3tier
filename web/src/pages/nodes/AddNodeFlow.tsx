import { useQuery } from '@tanstack/react-query'
import { ChevronDown, CircleCheck, LoaderCircle, RotateCw, TicketPlus, Undo2 } from 'lucide-react'
import { type ReactNode, useEffect, useId, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'

import { errorDetail, errorMessage } from '@/api/client'
import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type CreatedEnrollToken, type GroupRef, type Network, type Node, type NodeId } from '@/api/types'
import { CodeBlock, CopyButton } from '@/components/copy'
import { GroupPicker, GroupsLink } from '@/components/groups'
import { InfoTip } from '@/components/info-tip'
import { NodeSelect } from '@/components/node'
import { OsIcon } from '@/components/os-icon'
import { nodePath } from '@/lib/nodes'
import { Notice } from '@/components/notice'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, FormError } from '@/components/ui/field'
import { Input, NativeSelect } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { t } from '@/i18n'
import { installCommand, joinCommandParts, type JoinDeclarations, NO_DECLARATIONS, startCommand } from '@/lib/commands'
import { WAITING_INTERVAL } from '@/lib/polling'
import { type Capability, DEFAULT_TOKEN_TTL, INSTALL_SYSTEMS, type InstallSystem, RELEASES_PAGE } from '@/lib/product'
import { formatRemaining } from '@/lib/time'
import { useNow } from '@/lib/useNow'
import { cn } from '@/lib/utils'
import { validateVirtualIp } from '@/lib/validate'

/** 名字用函数写：渲染时现读，换了语言跟着变。 */
const TTL_CHOICES = [
  { secs: 60 * 60, label: () => t.addNode.ttl1h },
  { secs: DEFAULT_TOKEN_TTL, label: () => t.addNode.ttl24h },
  { secs: 7 * 24 * 60 * 60, label: () => t.addNode.ttl7d },
] as const

/** 等了多久之后给出"还没连上？"的排查提示。 */
const STUCK_AFTER_SECS = 60

/** 系统的名字各种语言里都一样，不用翻译。 */
const SYSTEM_NAME: Record<InstallSystem, string> = { linux: 'Linux', macos: 'macOS', windows: 'Windows' }

/**
 * 两个"可以承担"的勾选。端口转发的目标不用节点声明（0.1.11 起在节点详情里打开），所以这里没有它。
 */
const DECLARE_ROWS: readonly { capability: Capability; label: () => string }[] = [
  { capability: 'relay', label: () => t.addNode.declareRelay },
  { capability: 'exit', label: () => t.addNode.declareExit },
]

/**
 * 一个编号的步骤。编号之间一根细线连着，读的时候眼睛顺着往下走。
 * 标题那一行的右端放这一步的次要选择（`aside`），正文里只留这一步要做的那一件事。
 */
function Step({
  index,
  title,
  aside,
  children,
}: {
  index: number
  title: string
  aside?: ReactNode
  children: ReactNode
}) {
  return (
    <li className="group/step relative grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-3.5 pb-7 last:pb-0">
      <span
        aria-hidden
        className="absolute top-9 bottom-2 left-3.5 w-px -translate-x-1/2 bg-border group-last/step:hidden"
      />
      <span
        aria-hidden
        className="flex size-7 items-center justify-center rounded-full bg-muted text-[13px] font-semibold text-foreground tabular"
      >
        {index}
      </span>
      <div className="min-w-0">
        <div className="flex min-h-7 flex-wrap items-center justify-between gap-x-4 gap-y-1">
          <h3 className="text-sm font-semibold">{title}</h3>
          {aside}
        </div>
        <div className="mt-2.5 space-y-2.5">{children}</div>
      </div>
    </li>
  )
}

export interface AddNodeState {
  /** 令牌已经生成、节点还没用它加入：这时关掉界面，令牌就再也看不到了。 */
  tokenOutstanding: boolean
}

interface AddNodeFlowProps {
  network: Network
  /** 引导里的提示，显示在选项上方（例如"其中一台有公网 IP 的话，勾上 relay"）。 */
  intro?: ReactNode
  onStateChange?: (state: AddNodeState) => void
  /** 点"查看节点"时调用（对话框借此把自己关掉）。 */
  onNavigate?: () => void
}

/**
 * 添加节点的全部内容：选系统、三个编号的步骤、等待区。对话框和总览页的引导用的是同一个。
 * 每一步的正文只有要做的那一件事（一行命令、一个按钮）；次要的选择在这一步标题的右端：
 * 第 2 步是写在令牌上的选项（默认收着），第 3 步是两个声明。
 *
 * 密钥是流程里的一步，不是另一个页面上的事：令牌在第 2 步就地生成，生成之前第 3 步的命令里是占位符，
 * 让人先看懂命令的结构。节点一加入，等待区自己变成结果，不用去刷新列表。
 *
 * Linux 和 macOS 上第 1 步是安装脚本，节点装成系统服务，第 3 步加入之后服务自己启动；
 * Windows 没有脚本：下载程序，加入之后自己启动。
 *
 * "可以承担"的三个勾选是命令的参数，不属于令牌，所以生成令牌之后仍然可以改；
 * 分组、有效期、预设 IP、继任写在令牌上，生成之后变为只读。分组只能从已有的里面选，要新建就去分组页。
 */
export function AddNodeFlow({ network, intro, onStateChange, onNavigate }: AddNodeFlowProps) {
  const now = useNow()
  const optionsId = useId()

  const [system, setSystem] = useState<InstallSystem>('linux')
  const [declare, setDeclare] = useState<JoinDeclarations>(NO_DECLARATIONS)
  const [groups, setGroups] = useState<GroupRef[]>([])
  const [ttl, setTtl] = useState<number>(DEFAULT_TOKEN_TTL)
  const [virtualIp, setVirtualIp] = useState('')
  const [successorOf, setSuccessorOf] = useState<NodeId | null>(null)
  const [optionsOpen, setOptionsOpen] = useState(false)

  const [created, setCreated] = useState<CreatedEnrollToken | null>(null)
  const [createdAt, setCreatedAt] = useState(0)
  /** 生成令牌那一刻已经在网络里的节点。之后多出来的就是新加入的。 */
  const [knownNodes, setKnownNodes] = useState<ReadonlySet<NodeId>>(new Set())
  const [joined, setJoined] = useState<Node | null>(null)

  const waiting = created !== null && joined === null
  const nodes = useQuery({ ...q.nodes(network.id), refetchInterval: waiting ? WAITING_INTERVAL : false })
  const tokens = useQuery({
    ...q.tokens(network.id),
    refetchInterval: waiting ? WAITING_INTERVAL : false,
    enabled: waiting,
  })
  const known = useQuery({ ...q.groups(network.id), refetchInterval: false })
  const offlineNodes = useMemo(() => (nodes.data ?? []).filter((node) => !node.online), [nodes.data])

  const ipProblem = virtualIp.trim() === '' ? null : validateVirtualIp(virtualIp, network.cidr)

  const generate = useAction(network.id, {
    mutationFn: async (previous: CreatedEnrollToken | null) => {
      // 重新生成：先收回刚才那个，免得外面留着一个没人管的有效令牌。它要是已经不在了也无妨。
      if (previous !== null) await api.deleteToken(network.id, previous.id).catch(() => undefined)
      const current = await api.nodes(network.id)
      const token = await api.createToken(network.id, {
        expires_in_secs: ttl,
        groups: groups.map((group) => group.id),
        virtual_ip: successorOf === null && virtualIp.trim() !== '' ? virtualIp.trim() : undefined,
        successor_of: successorOf ?? undefined,
      })
      return { token, known: new Set(current.map((node) => node.id)) }
    },
    success: (_data, previous) => (previous === null ? null : t.addNode.regenerated),
    toastError: false,
  })

  // 令牌从"没用掉的"列表里消失，同时网络里多出一个节点：就是它加入了。
  const tokenPending = tokens.data?.some((token) => token.id === created?.id) ?? true
  const newcomer = useMemo(
    () => (waiting ? (nodes.data ?? []).find((node) => !knownNodes.has(node.id)) : undefined),
    [waiting, nodes.data, knownNodes],
  )
  // 在渲染时直接记下（而不是放进 effect）：这是从取到的数据推出来的状态，记下之后轮询随即停止。
  if (waiting && newcomer !== undefined && !tokenPending) setJoined(newcomer)

  const expired = waiting && now >= created.expires_at
  const gone = waiting && !expired && tokens.data !== undefined && !tokenPending && newcomer === undefined
  const stuck = waiting && !expired && !gone && now - createdAt >= STUCK_AFTER_SECS

  useEffect(() => {
    onStateChange?.({ tokenOutstanding: waiting && !expired && !gone })
  }, [onStateChange, waiting, expired, gone])

  // 结果写在最下面。对话框比屏幕高时那里在视野之外，不把它带进来，用户会以为什么都没发生。
  const outcomeRef = useRef<HTMLElement>(null)
  const settled = joined !== null || expired || gone
  useEffect(() => {
    if (settled) outcomeRef.current?.scrollIntoView({ block: 'nearest' })
  }, [settled])

  const onGenerate = (previous: CreatedEnrollToken | null) => {
    if (ipProblem !== null) return
    generate.mutate(previous, {
      onSuccess: ({ token, known }) => {
        setCreated(token)
        setKnownNodes(known)
        setCreatedAt(Math.floor(Date.now() / 1000))
        setJoined(null)
      },
    })
  }

  // 吊销：令牌作废，回到生成之前（分组、声明这些选择留着），可以再生成一个。
  const revoke = useAction(network.id, {
    mutationFn: (token: CreatedEnrollToken) => api.deleteToken(network.id, token.id),
    success: t.addNode.revoked,
  })
  const onRevoke = (token: CreatedEnrollToken) =>
    revoke.mutate(token, {
      onSuccess: () => {
        setCreated(null)
        setJoined(null)
        generate.reset()
      },
    })

  const addAnother = () => {
    setCreated(null)
    setJoined(null)
    setVirtualIp('')
    setSuccessorOf(null)
    generate.reset()
  }

  const locked = created !== null
  const install = installCommand(system)
  const join = joinCommandParts(created?.token ?? { placeholder: t.addNode.tokenPlaceholder }, declare, system)
  const joinCommand = `${join.before}${join.token}${join.after}`
  /** 加入之后还要自己启动的系统上才有。 */
  const start = startCommand(system)
  const remaining = created === null ? null : formatRemaining(created.expires_at, now)

  return (
    <div className="space-y-6">
      {intro}

      <Segmented
        aria-label={t.addNode.platformLabel}
        value={system}
        onChange={setSystem}
        options={INSTALL_SYSTEMS.map((candidate) => ({
          value: candidate,
          label: (
            <>
              <OsIcon platform={candidate} />
              {SYSTEM_NAME[candidate]}
            </>
          ),
        }))}
      />

      <ol>
        <Step index={1} title={t.addNode.step1}>
          {start !== null ? <p className="text-[13px] text-muted-foreground">{t.addNode.step1Windows}</p> : null}
          <CodeBlock copy={install} copyLabel={t.addNode.copyInstall} testId="install-command">
            {install}
          </CodeBlock>
          {start !== null ? (
            <a
              href={RELEASES_PAGE}
              target="_blank"
              rel="noreferrer"
              className="inline-block rounded-sm text-[13px] text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              {t.addNode.step1Releases}
            </a>
          ) : null}
        </Step>

        <Step
          index={2}
          title={t.addNode.step2}
          aside={
            <Button
              size="sm"
              variant="ghost"
              aria-expanded={optionsOpen}
              aria-controls={optionsId}
              onClick={() => setOptionsOpen((open) => !open)}
              className="-mr-2.5 text-muted-foreground"
            >
              {t.addNode.optionsTitle}
              <ChevronDown aria-hidden className={cn('transition-transform', optionsOpen && 'rotate-180')} />
            </Button>
          }
        >
          {optionsOpen ? (
            <section id={optionsId} aria-label={t.addNode.optionsTitle} className="animate-rise space-y-4 pb-2">
              <Field
                label={t.addNode.groupsLabel}
                hint={
                  locked ? (
                    t.addNode.groupsHint
                  ) : (
                    <span className="flex flex-wrap items-center justify-between gap-x-3">
                      {t.addNode.groupsHint}
                      <GroupsLink network={network.id} onClick={onNavigate} />
                    </span>
                  )
                }
                optional={t.common.optional}
              >
                {(props) => (
                  <GroupPicker
                    {...props}
                    value={groups}
                    onChange={setGroups}
                    groups={known.data ?? []}
                    disabled={locked}
                  />
                )}
              </Field>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Field label={t.addNode.ttlLabel}>
                  {(props) => (
                    <NativeSelect
                      {...props}
                      value={ttl}
                      disabled={locked}
                      onChange={(event) => setTtl(Number(event.target.value))}
                    >
                      {TTL_CHOICES.map((choice) => (
                        <option key={choice.secs} value={choice.secs}>
                          {choice.label()}
                        </option>
                      ))}
                    </NativeSelect>
                  )}
                </Field>
                <Field
                  label={t.addNode.ipLabel}
                  optional={t.common.optional}
                  hint={successorOf !== null ? t.addNode.successorNoIp : t.addNode.ipHint}
                  error={successorOf === null ? ipProblem : null}
                >
                  {(props) => (
                    <Input
                      {...props}
                      className="font-mono"
                      value={successorOf !== null ? '' : virtualIp}
                      disabled={locked || successorOf !== null}
                      placeholder={network.cidr.replace(/\.0\/\d+$/, '.9')}
                      onChange={(event) => setVirtualIp(event.target.value)}
                    />
                  )}
                </Field>
                <Field
                  label={t.addNode.successorLabel}
                  optional={t.common.optional}
                  hint={t.addNode.successorHint}
                  className="sm:col-span-2"
                >
                  {(props) => (
                    <div className="flex items-center gap-2">
                      <div className="min-w-0 flex-1">
                        <NodeSelect
                          {...props}
                          nodes={offlineNodes}
                          value={successorOf}
                          onChange={setSuccessorOf}
                          disabled={locked || offlineNodes.length === 0}
                          placeholder={
                            offlineNodes.length === 0 ? t.addNode.successorEmpty : t.addNode.successorPlaceholder
                          }
                        />
                      </div>
                      {successorOf !== null && !locked ? (
                        <Button size="sm" variant="ghost" onClick={() => setSuccessorOf(null)}>
                          {t.addNode.successorClear}
                        </Button>
                      ) : null}
                    </div>
                  )}
                </Field>
              </div>
              {locked ? <p className="text-[13px] text-muted-foreground">{t.addNode.lockedNote}</p> : null}
            </section>
          ) : null}

          {created === null ? (
            <Button
              variant="primary"
              pending={generate.isPending}
              disabled={ipProblem !== null}
              onClick={() => onGenerate(null)}
            >
              <TicketPlus aria-hidden />
              {t.addNode.generate}
            </Button>
          ) : (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
              <p className="flex items-center gap-1.5 text-sm">
                <CircleCheck className="size-4 text-ok" aria-hidden />
                {remaining === null ? t.addNode.expired : t.addNode.generated(remaining)}
              </p>
              {joined === null ? (
                <>
                  <Button
                    size="sm"
                    pending={generate.isPending}
                    disabled={revoke.isPending}
                    onClick={() => onGenerate(created)}
                    title={t.addNode.regenerateHint}
                  >
                    <RotateCw aria-hidden />
                    {t.addNode.regenerate}
                  </Button>
                  {/* 过期了、已经被吊销了的没有什么可吊销的。 */}
                  {remaining !== null && !gone ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      pending={revoke.isPending}
                      disabled={generate.isPending}
                      onClick={() => onRevoke(created)}
                      title={t.addNode.revokeHint}
                    >
                      <Undo2 aria-hidden />
                      {t.addNode.revoke}
                    </Button>
                  ) : null}
                </>
              ) : null}
            </div>
          )}
          <FormError
            message={generate.isError ? errorMessage(generate.error) : null}
            detail={generate.isError ? errorDetail(generate.error) : null}
          />
        </Step>

        <Step
          index={3}
          title={t.addNode.step3}
          aside={
            <div role="group" aria-label={t.addNode.declareLabel} className="flex items-center gap-x-4">
              {DECLARE_ROWS.map((row) => (
                <label key={row.capability} className="flex items-center gap-2 text-[13px]">
                  <Checkbox
                    checked={declare[row.capability]}
                    onCheckedChange={(checked) =>
                      setDeclare((current) => ({ ...current, [row.capability]: checked === true }))
                    }
                  />
                  {row.label()}
                </label>
              ))}
              <InfoTip label={t.addNode.declareLabel}>
                <p>{t.addNode.declareNote}</p>
                <p className="mt-1">{t.addNode.declareRelayHint}</p>
              </InfoTip>
            </div>
          }
        >
          {start !== null ? <p className="text-[13px] text-muted-foreground">{t.addNode.step3Join}</p> : null}
          <CodeBlock
            copy={created === null ? null : joinCommand}
            copyLabel={t.addNode.copyCommand}
            disabledReason={t.addNode.copyDisabled}
            label={t.addNode.joinCommandLabel}
            testId="join-command"
            className={cn(created !== null && joined === null && 'bg-accent')}
          >
            {join.before}
            {/* 占位符换一种颜色：这里以后是令牌。真的令牌很长，中间没有可以折行的地方，让它在任意处断开。 */}
            <span className={created === null ? 'text-accent-foreground' : 'break-all'}>{join.token}</span>
            {join.after}
          </CodeBlock>
          {created !== null && joined === null ? (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-[13px] font-medium text-warn">{t.addNode.shownOnce}</p>
              <CopyButton value={created.token} size="sm" variant="ghost">
                {t.addNode.copyToken}
              </CopyButton>
            </div>
          ) : null}
          {start !== null ? (
            <>
              <p className="pt-1 text-[13px] text-muted-foreground">{t.addNode.step3Run}</p>
              <CodeBlock copy={start} testId="start-command">
                {start}
              </CodeBlock>
              <p className="text-[13px] text-muted-foreground">{t.addNode.step3RunHint}</p>
            </>
          ) : null}
        </Step>
      </ol>

      {created !== null ? (
        <section ref={outcomeRef} aria-live="polite" className="scroll-my-5 border-t pt-5">
          {joined !== null ? (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="flex items-center gap-2 text-sm font-semibold" data-testid="node-joined">
                  <CircleCheck className="size-4 text-ok" aria-hidden />
                  {t.addNode.joined(joined.name, joined.virtual_ip)}
                </p>
                {/* 脚本装的服务加入之后自己启动，不用再提醒去启动。 */}
                {joined.hostname !== '' || start !== null ? (
                  <p className="mt-0.5 flex flex-wrap gap-x-1.5 pl-6 text-[13px] text-muted-foreground">
                    {joined.hostname !== '' ? (
                      <span data-testid="node-joined-hostname">{t.addNode.joinedHostname(joined.hostname)}</span>
                    ) : null}
                    {joined.hostname !== '' && start !== null ? <span aria-hidden>·</span> : null}
                    {start !== null ? <span>{t.addNode.joinedHint}</span> : null}
                  </p>
                ) : null}
              </div>
              <div className="flex items-center gap-2">
                <Button onClick={addAnother}>{t.addNode.addAnother}</Button>
                <Button asChild variant="primary">
                  <Link to={nodePath(network.id, joined.id)} onClick={onNavigate}>
                    {t.addNode.viewNode}
                  </Link>
                </Button>
              </div>
            </div>
          ) : expired || gone ? (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm font-medium text-warn">{expired ? t.addNode.expired : t.addNode.gone}</p>
              <Button size="sm" pending={generate.isPending} onClick={() => onGenerate(null)}>
                <RotateCw aria-hidden />
                {t.addNode.regenerate}
              </Button>
            </div>
          ) : (
            <>
              <p className="flex items-center gap-2 text-sm font-medium">
                <LoaderCircle className="size-4 animate-spin text-muted-foreground" aria-hidden />
                {t.addNode.waiting}
              </p>
              {stuck ? (
                <details className="mt-2.5 pl-6 text-[13px]">
                  <summary className="rounded-sm font-medium">{t.addNode.stuck}</summary>
                  <ul className="mt-1.5 list-disc space-y-1 pl-4 text-muted-foreground">
                    <li>{t.addNode.stuckCommand}</li>
                    <li>
                      {t.addNode.stuckController}
                      <ControllerAddress />
                    </li>
                    <li>{t.addNode.stuckToken}</li>
                  </ul>
                </details>
              ) : null}
            </>
          )}
        </section>
      ) : null}

      {nodes.isError ? <Notice tone="warn">{errorMessage(nodes.error)}</Notice> : null}
    </div>
  )
}

/** 令牌里写着的 controller 地址。节点连不上时，多半是这个地址从那台机器上到不了。 */
function ControllerAddress() {
  const status = useQuery(q.status())
  if (status.data === undefined) return null
  return (
    <code className="ml-1 rounded-sm bg-muted px-1 py-px font-mono text-xs text-foreground">
      {status.data.public_addr}
    </code>
  )
}
