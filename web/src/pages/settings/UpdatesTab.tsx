import { useQueries, useQuery } from '@tanstack/react-query'
import { ChevronDown, CircleArrowUp, RefreshCw, X } from 'lucide-react'
import { useId, useMemo, useState } from 'react'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type ForcedUpdates, type Network, type Node, type PackageState, type UpdateOverview } from '@/api/types'
import { useConfirm } from '@/components/confirm'
import { ForceAllDialog, ForceUpdateDialog } from '@/components/force-update'
import { NodeLink } from '@/components/node'
import { Notice } from '@/components/notice'
import { EmptyState, ErrorState, SkeletonBlock } from '@/components/states'
import { RelativeTime } from '@/components/status'
import { Table, Td, Th, Tr } from '@/components/table'
import { ReasonButton, UpdateStateView } from '@/components/update'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardBody, CardHeader } from '@/components/ui/card'
import { Field } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { RadioCards } from '@/components/ui/radio-cards'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { formatBytes, formatList } from '@/lib/format'
import { forceAbility, groupPaused, isUpdating, type PausedGroup } from '@/lib/nodeUpdate'
import { LIVE_INTERVAL, WAITING_INTERVAL } from '@/lib/polling'
import { type SourceKind, sourceKind, validateSource } from '@/lib/releaseSource'
import { formatFullTime, formatRelative } from '@/lib/time'
import { useNow } from '@/lib/useNow'
import { useUpdateView } from '@/lib/useUpdateView'

const u = t.updates

/** 不认识的状态查不到，徽标用默认的灰。 */
const PACKAGE_TONES = {
  cached: 'ok',
  fetching: 'relay',
  failed: 'danger',
  not_needed: 'neutral',
  unknown: 'neutral',
} as const satisfies Record<PackageState, string>

/** 包的状态的名字和说明。比界面新的 controller 可能报出这里不认识的状态，原样写出来。 */
function packageText(state: PackageState): { label: string; hint: string } {
  const labels: Partial<Record<string, string>> = u.release.packageState
  const hints: Partial<Record<string, string>> = u.release.packageStateHint
  return { label: labels[state] ?? state, hint: hints[state] ?? u.release.packageStateHint.unknown }
}

/** 有更新正在进行：取得勤一些，用户这时正看着进度。 */
function busy(overview: UpdateOverview | undefined): boolean {
  return (
    overview !== undefined &&
    (overview.nodes.updating > 0 || (overview.release?.packages.some((pkg) => pkg.state === 'fetching') ?? false))
  )
}

/**
 * 一个被暂停的版本：暂停按网络算，每个网络一条失败；"继续"一次继续全部网络里的这个版本。
 * 原因折着，点开是每个网络里哪个节点、什么时候、报了什么。
 */
function PausedBanner({ group, networks }: { group: PausedGroup; networks: readonly Network[] }) {
  const confirm = useConfirm()
  const [open, setOpen] = useState(false)
  const reasonId = useId()
  const { version, entries } = group
  const networkName = (id: number | null) =>
    id === null ? '—' : (networks.find((network) => network.id === id)?.name ?? u.paused.networkGone(id))
  const names = formatList([...new Set(entries.map((entry) => networkName(entry.network)))])
  const [first] = entries
  const resume = useAction('all', {
    mutationFn: () => api.resumeUpdate({ version }),
    success: u.paused.resumed(version),
  })
  const onResume = async () => {
    const ok = await confirm({
      title: u.paused.resumeTitle(version),
      body:
        entries.length === 1
          ? u.paused.resumeBody(version, first?.node?.name ?? null)
          : u.paused.resumeBodyMany(version, names),
      confirmLabel: u.paused.resumeConfirm,
    })
    if (ok) resume.mutate()
  }
  const title =
    entries.length > 1
      ? u.paused.titleMany(version, entries.length)
      : first?.node == null
        ? u.paused.titleNodeGone(version)
        : u.paused.title(version, first.node.name)
  return (
    <Notice
      tone="danger"
      title={title}
      action={
        <div className="flex items-center gap-2">
          <Button size="sm" aria-expanded={open} aria-controls={reasonId} onClick={() => setOpen(!open)}>
            {open ? u.paused.hideReason : u.paused.reason}
          </Button>
          <Button size="sm" variant="primary" pending={resume.isPending} onClick={() => void onResume()}>
            {u.paused.resume}
          </Button>
        </div>
      }
    >
      <p data-testid={`paused-scope-${version}`}>{u.paused.scope(names)}</p>
      <ul id={reasonId} hidden={!open} data-testid={`paused-reason-${version}`} className="mt-1.5 space-y-2">
        {entries.map((entry) => (
          <li key={`${entry.network ?? 0}:${entry.at}`}>
            <p>
              {entry.node === null
                ? u.paused.entryNodeGone(networkName(entry.network))
                : u.paused.entry(networkName(entry.network), entry.node.name)}
              {' · '}
              <RelativeTime at={entry.at} />
            </p>
            <p className="mt-0.5 font-mono text-xs break-all text-foreground/80">{entry.reason}</p>
          </li>
        ))}
      </ul>
    </Notice>
  )
}

/** 点了"立即检查"之后就地说一句结果。查失败的原因另有一条常驻的提醒，这里不重复。 */
function checkResult(checked: UpdateOverview | null): string | null {
  if (checked?.check_error !== null) return null
  const { nodes, release } = checked
  const behind = nodes.outdated + nodes.failed + nodes.manual + nodes.updating
  if (release === null) return u.release.nothingPublished
  return behind === 0 ? u.release.upToDate : u.release.found(release.version, behind)
}

function ReleaseCard({ overview }: { overview: UpdateOverview }) {
  const now = useNow()
  const [checked, setChecked] = useState<UpdateOverview | null>(null)
  const check = useAction(null, { mutationFn: api.checkUpdate })
  const { release } = overview

  const onCheck = () => check.mutate(undefined, { onSuccess: setChecked })
  const result = checkResult(checked)

  return (
    <Card>
      <CardHeader
        title={u.release.title}
        action={
          <Button size="sm" pending={check.isPending} onClick={onCheck}>
            {check.isPending ? null : <RefreshCw aria-hidden />}
            {check.isPending ? u.release.checking : u.release.check}
          </Button>
        }
      />
      <CardBody className="space-y-3">
        <div>
          <p className="text-base font-semibold tabular" data-testid="release-version">
            {release === null ? u.release.none : u.release.latest(release.version)}
          </p>
          <p className="mt-0.5 text-[13px] text-muted-foreground">
            {release === null ? null : <>{u.release.published(formatRelative(release.published, now))} · </>}
            {overview.checked_at === null ? (
              u.release.neverChecked
            ) : (
              <Tooltip content={formatFullTime(overview.checked_at)}>
                <time
                  tabIndex={0}
                  dateTime={new Date(overview.checked_at * 1000).toISOString()}
                  className="rounded-sm whitespace-nowrap"
                >
                  {u.release.checkedAt(formatRelative(overview.checked_at, now))}
                </time>
              </Tooltip>
            )}
          </p>
        </div>
        <div aria-live="polite">
          {result !== null ? (
            <p className="text-sm font-medium text-ok" data-testid="check-result">
              {result}
            </p>
          ) : null}
        </div>
        {overview.check_error !== null ? (
          <Notice tone="danger" title={u.release.checkFailed}>
            <p className="font-mono text-xs break-words text-foreground/80" data-testid="check-error">
              {overview.check_error}
            </p>
            <p className="mt-0.5">{u.release.checkFailedHint}</p>
          </Notice>
        ) : null}
        {release?.controller_too_old === true ? (
          <Notice tone="danger">
            {u.release.controllerTooOld(release.min_controller, overview.controller_version)}
          </Notice>
        ) : release?.newer_than_controller === true ? (
          <Notice tone="warn">{u.release.controllerNewer(overview.controller_version, release.version)}</Notice>
        ) : null}
      </CardBody>
      {release !== null && release.packages.length > 0 ? (
        <>
          <h3 className="mt-6 mb-1 text-[13px] font-medium text-muted-foreground">{u.release.packages}</h3>
          <Table stack>
            <thead>
              <tr>
                <Th>{u.release.colPlatform}</Th>
                <Th>{u.release.colFile}</Th>
                <Th numeric>{u.release.colSize}</Th>
                <Th>{u.release.colState}</Th>
              </tr>
            </thead>
            <tbody>
              {release.packages.map((pkg) => {
                const state = packageText(pkg.state)
                return (
                  <Tr key={pkg.platform} data-testid={`package-${pkg.platform}`}>
                    <Td cell="main" className="font-mono text-[13px]">
                      {pkg.platform}
                    </Td>
                    <Td cell="full" className="font-mono text-[13px] break-all text-muted-foreground">
                      {pkg.file}
                    </Td>
                    <Td cell="end" numeric className="text-[13px]">
                      {formatBytes(pkg.size)}
                    </Td>
                    <Td cell="full" className="text-[13px]">
                      <Tooltip content={state.hint}>
                        <span tabIndex={0} className="rounded-sm">
                          <Badge tone={PACKAGE_TONES[pkg.state]}>{state.label}</Badge>
                        </span>
                      </Tooltip>
                      {pkg.error !== null ? (
                        <p className="mt-1 font-mono text-xs break-words text-muted-foreground">{pkg.error}</p>
                      ) : null}
                    </Td>
                  </Tr>
                )
              })}
            </tbody>
          </Table>
        </>
      ) : null}
    </Card>
  )
}

function AutoUpdateCard({ overview }: { overview: UpdateOverview }) {
  const id = useId()
  const save = useAction('all', {
    mutationFn: (on: boolean) => api.updateSettings({ auto_update: on }),
    success: (_data, on) => (on ? u.auto.turnedOn : u.auto.turnedOff),
  })
  return (
    <Card>
      <CardBody className="flex items-start justify-between gap-6">
        <div>
          <label htmlFor={id} className="text-base font-semibold">
            {u.auto.title}
          </label>
          <p className="mt-0.5 text-[13px] text-muted-foreground">{overview.auto_update ? u.auto.on : u.auto.off}</p>
        </div>
        <Switch
          id={id}
          aria-label={u.auto.label}
          checked={overview.auto_update}
          disabled={save.isPending}
          onCheckedChange={(on) => save.mutate(on)}
        />
      </CardBody>
    </Card>
  )
}

function SourceCard({ overview }: { overview: UpdateOverview }) {
  const initialKind = sourceKind(overview)
  const initialValue = initialKind === 'default' ? '' : overview.source
  const [kind, setKind] = useState<SourceKind>(initialKind)
  const [values, setValues] = useState<Record<Exclude<SourceKind, 'default'>, string>>({
    url: initialKind === 'url' ? initialValue : '',
    dir: initialKind === 'dir' ? initialValue : '',
  })
  const [touched, setTouched] = useState(false)
  const save = useAction('all', {
    mutationFn: () => api.updateSettings({ source: kind === 'default' ? null : values[kind].trim() }),
    success: u.source.saved,
  })

  const value = kind === 'default' ? '' : values[kind]
  const error = validateSource(kind, value)
  const dirty = kind !== initialKind || (kind !== 'default' && value.trim() !== initialValue)
  const summary =
    initialKind === 'default'
      ? u.source.summaryDefault
      : initialKind === 'url'
        ? u.source.summaryUrl(overview.source)
        : u.source.summaryDir(overview.source)

  return (
    <Card>
      {/* 平时不用动，所以折起来；查发布源失败时自己展开，免得要找。 */}
      <details className="group" open={overview.check_error !== null || undefined}>
        <summary className="flex cursor-pointer list-none items-start justify-between gap-4 rounded-md [&::-webkit-details-marker]:hidden">
          <span className="min-w-0">
            <span className="block text-base font-semibold">{u.source.title}</span>
            <span className="mt-0.5 block truncate text-[13px] text-muted-foreground" data-testid="source-summary">
              {summary}
            </span>
          </span>
          <ChevronDown
            className="mt-1 size-4 shrink-0 text-faint transition-transform group-open:rotate-180"
            aria-hidden
          />
        </summary>
        <form
          noValidate
          className="mt-4 space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            setTouched(true)
            if (error === null && dirty) save.mutate()
          }}
        >
          <RadioCards<SourceKind>
            aria-label={u.source.kindLabel}
            columns={3}
            value={kind}
            onChange={(next) => {
              setKind(next)
              setTouched(false)
            }}
            options={[
              { value: 'default', title: u.source.kindDefault, description: u.source.kindDefaultHint },
              { value: 'url', title: u.source.kindUrl, description: u.source.kindUrlHint },
              { value: 'dir', title: u.source.kindDir, description: u.source.kindDirHint },
            ]}
          />
          {kind !== 'default' ? (
            <Field
              label={kind === 'url' ? u.source.urlLabel : u.source.dirLabel}
              hint={u.source.layout}
              error={touched || value !== '' ? error : null}
            >
              {(props) => (
                <Input
                  {...props}
                  value={value}
                  onChange={(event) => setValues({ ...values, [kind]: event.target.value })}
                  placeholder={kind === 'url' ? u.source.urlPlaceholder : u.source.dirPlaceholder}
                  spellCheck={false}
                  autoComplete="off"
                  className="font-mono"
                />
              )}
            </Field>
          ) : null}
          <div className="flex justify-end">
            <Button type="submit" variant="primary" pending={save.isPending} disabled={!dirty || error !== null}>
              {u.source.save}
            </Button>
          </div>
        </form>
      </details>
    </Card>
  )
}

interface Row {
  node: Node
  network: Network
}

function NodeRow({ row, showNetwork, onForce }: { row: Row; showNetwork: boolean; onForce: (node: Node) => void }) {
  const { node, network } = row
  // 自动更新的开关就在这张表上面，每一行不再重复"自动更新已关闭"。
  const view = useUpdateView(node, { autoSwitchShown: true })
  const ability = forceAbility(node)
  return (
    <Tr data-testid={`update-row-${node.name}`}>
      <Td cell="main">
        <NodeLink network={network.id} node={node} online={node.online} />
        {showNetwork ? <div className="mt-0.5 text-xs text-muted-foreground">{network.name}</div> : null}
      </Td>
      <Td cell="row" label={u.nodes.colVersion} className="whitespace-nowrap">
        <div className="text-[13px] tabular">{node.version === '' ? '—' : node.version}</div>
        <div className="text-xs text-muted-foreground">{node.platform}</div>
      </Td>
      <Td cell="row" label={u.nodes.colState} className="max-w-md">
        <UpdateStateView view={view} />
      </Td>
      <Td cell="end" className="text-right">
        {node.update.available !== null ? (
          <ReasonButton
            size="sm"
            reason={ability.ok ? null : ability.reason}
            onClick={() => onForce(node)}
            aria-label={u.force.buttonFor(node.name)}
          >
            <CircleArrowUp aria-hidden />
            {u.force.button}
          </ReasonButton>
        ) : null}
      </Td>
    </Tr>
  )
}

/** 全部网络里的节点，按网络、名字排。实时更新时行的顺序不变。 */
function useAllNodes(fast: boolean): { rows: Row[]; pending: boolean; error: unknown } {
  const networks = useQuery(q.networks())
  const lists = useQueries({
    queries: (networks.data ?? []).map((network) => ({
      ...q.nodes(network.id),
      refetchInterval: fast ? WAITING_INTERVAL : LIVE_INTERVAL,
    })),
  })
  const rows = (networks.data ?? []).flatMap((network, index) =>
    [...(lists[index]?.data ?? [])]
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }))
      .map((node) => ({ node, network })),
  )
  return {
    rows,
    pending: networks.isPending || lists.some((list) => list.isPending),
    error: networks.error ?? lists.find((list) => list.error !== null)?.error ?? null,
  }
}

type Filter = 'all' | 'behind'

function NodesCard({ overview, onForceAll }: { overview: UpdateOverview; onForceAll: () => void }) {
  const fast = busy(overview)
  const { rows, pending, error } = useAllNodes(fast)
  const [filter, setFilter] = useState<Filter>('all')
  const [forcing, setForcing] = useState<Node | null>(null)
  const networks = new Set(rows.map((row) => row.network.id))
  const behind = useMemo(
    () => rows.filter(({ node }) => node.update.available !== null || isUpdating(node.update)),
    [rows],
  )
  const shown = filter === 'all' ? rows : behind
  const candidates = overview.nodes.outdated + overview.nodes.failed
  const release = overview.release
  const forceAllReason =
    release === null || release.controller_too_old || candidates === 0 ? u.nodes.updateAllDisabled : null

  return (
    <Card>
      <CardHeader
        title={u.nodes.title}
        description={<span data-testid="update-summary">{u.nodes.summary(overview.nodes)}</span>}
        action={
          <ReasonButton reason={forceAllReason} onClick={onForceAll}>
            <CircleArrowUp aria-hidden />
            {u.nodes.updateAll}
          </ReasonButton>
        }
      />
      {error !== null && rows.length === 0 ? (
        <ErrorState title={t.errors.loadFailed} error={error} />
      ) : pending && rows.length === 0 ? (
        <SkeletonBlock lines={4} />
      ) : rows.length === 0 ? (
        <EmptyState title={u.nodes.empty} />
      ) : (
        <>
          <div className="mb-3">
            <Segmented<Filter>
              aria-label={u.nodes.filter}
              size="sm"
              value={filter}
              onChange={setFilter}
              options={[
                { value: 'all', label: u.nodes.filterAll },
                { value: 'behind', label: u.nodes.filterBehind(behind.length) },
              ]}
            />
          </div>
          {shown.length === 0 ? (
            <p className="border-t py-6 text-center text-sm text-muted-foreground">{u.nodes.noneBehind}</p>
          ) : (
            <Table stack>
              <thead>
                <tr>
                  <Th>{u.nodes.colNode}</Th>
                  <Th>{u.nodes.colVersion}</Th>
                  <Th>{u.nodes.colState}</Th>
                  <Th className="w-36">
                    <span className="sr-only">{t.common.moreActions}</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {shown.map((row) => (
                  <NodeRow key={row.node.id} row={row} showNetwork={networks.size > 1} onForce={setForcing} />
                ))}
              </tbody>
            </Table>
          )}
        </>
      )}
      {forcing !== null ? <ForceUpdateDialog node={forcing} onClose={() => setForcing(null)} /> : null}
    </Card>
  )
}

function ForceResult({ result, onDismiss }: { result: ForcedUpdates; onDismiss: () => void }) {
  const a = t.updates.forceAll
  const names = (list: readonly { name: string }[]) => formatList(list.map((node) => node.name))
  return (
    <Notice
      tone="info"
      title={a.resultTitle}
      action={
        <Button variant="ghost" size="icon-sm" onClick={onDismiss} aria-label={a.dismiss}>
          <X aria-hidden />
        </Button>
      }
    >
      <div data-testid="force-all-result">
        {result.version === null ? <p>{a.resultNoVersion}</p> : null}
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1">
          {result.ordered.length > 0 ? (
            <>
              <dt className="font-medium text-foreground">{a.resultOrdered}</dt>
              <dd>{names(result.ordered)}</dd>
            </>
          ) : null}
          {result.queued.length > 0 ? (
            <>
              <dt className="font-medium text-foreground">{a.resultQueued}</dt>
              <dd>{names(result.queued)}</dd>
            </>
          ) : null}
          {result.skipped.length > 0 ? (
            <>
              <dt className="font-medium text-foreground">{a.resultSkipped}</dt>
              <dd>
                <ul className="space-y-0.5">
                  {result.skipped.map((skipped) => (
                    <li key={skipped.node.id}>
                      {skipped.node.name}
                      {/* controller 给的原因是一句中文原话，作为补充。 */}
                      <span className="ml-2 text-xs text-muted-foreground">{skipped.reason}</span>
                    </li>
                  ))}
                </ul>
              </dd>
            </>
          ) : null}
        </dl>
      </div>
    </Notice>
  )
}

/**
 * 设置里的「节点更新」。从上到下：被暂停的版本、版本和"立即检查"、自动更新的开关、
 * 发布源、每个节点的更新状态和"全部更新"。更新是全局的，不分网络。
 */
export function UpdatesTab() {
  const overview = useQuery({
    ...q.update(),
    refetchInterval: (query) => (busy(query.state.data) ? WAITING_INTERVAL : LIVE_INTERVAL),
  })
  const [forcingAll, setForcingAll] = useState(false)
  const [result, setResult] = useState<ForcedUpdates | null>(null)
  // 暂停按网络算，横幅里写网络的名字。
  const networks = useQuery(q.networks())

  if (overview.isError && overview.data === undefined) {
    return <ErrorState title={u.loadFailed} error={overview.error} onRetry={() => void overview.refetch()} />
  }
  if (overview.data === undefined) {
    return <SkeletonBlock lines={6} />
  }
  const data = overview.data

  return (
    <div className="space-y-12" data-testid="updates-tab">
      {groupPaused(data.paused).map((group) => (
        <PausedBanner key={group.version} group={group} networks={networks.data ?? []} />
      ))}
      <ReleaseCard overview={data} />
      <AutoUpdateCard overview={data} />
      {/* 发布源变了（别处改的）时重新填表。 */}
      <SourceCard key={`${data.source_is_default}:${data.source}`} overview={data} />
      {result !== null ? <ForceResult result={result} onDismiss={() => setResult(null)} /> : null}
      <NodesCard overview={data} onForceAll={() => setForcingAll(true)} />
      {forcingAll && data.release !== null ? (
        <ForceAllDialog
          version={data.release.version}
          candidates={data.nodes.outdated + data.nodes.failed}
          onClose={() => setForcingAll(false)}
          onDone={setResult}
        />
      ) : null}
    </div>
  )
}
