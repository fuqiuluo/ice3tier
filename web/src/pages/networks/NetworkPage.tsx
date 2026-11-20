import { useQuery } from '@tanstack/react-query'
import { CalendarDays, ChevronRight, Globe, Network as NetworkIcon, Plus, Server, Tag } from 'lucide-react'
import { useId, useState } from 'react'
import { Link, useNavigate } from 'react-router'

import { fieldError, formError, formErrorDetail, formFailure } from '@/api/formErrors'
import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type Network, type Reach, type RoutingMode, type ServiceClass, type UpdateNetwork } from '@/api/types'
import { useConfirm } from '@/components/confirm'
import { DateTimeValue, DetailList, DetailRow } from '@/components/detail-list'
import { FormDialog } from '@/components/form-dialog'
import { Page, PageHeader } from '@/components/page'
import { SettingRow } from '@/components/setting-row'
import { Button } from '@/components/ui/button'
import { BoxCard, BoxCardHeader } from '@/components/ui/card'
import { Field, FormError } from '@/components/ui/field'
import { Input, NativeSelect } from '@/components/ui/input'
import { ClassSelect } from '@/components/usage'
import { t } from '@/i18n'
import { cidrContains, formatCidr, parseCidr } from '@/lib/cidr'
import { MAX_RELAY_HOPS } from '@/lib/product'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { validateNetworkCidr } from '@/lib/validate'

import { networkPath, useNetwork } from './context'
import { CreateNetworkDialog } from './CreateNetworkDialog'

const n = t.networks

/** 扩大地址段。有节点之后地址段只能扩大：新的必须把原来的完整地包含在内。 */
function ExpandDialog({ network, open, onClose }: { network: Network; open: boolean; onClose: () => void }) {
  const [value, setValue] = useState(network.cidr)
  const [touched, setTouched] = useState(false)
  const expand = useAction(network.id, {
    mutationFn: () => api.updateNetwork(network.id, { cidr: value.trim() }),
    success: (updated) => n.expanded(updated.cidr),
    toastError: false,
  })
  const failure = formFailure(expand.error, { range_overlaps: 'cidr', range_not_superset: 'cidr' } as const)

  const current = parseCidr(network.cidr)
  const next = parseCidr(value)
  const dirty = next !== null && current !== null && formatCidr(next) !== formatCidr(current)
  let problem = validateNetworkCidr(value)
  if (problem === null && next !== null && current !== null && !cidrContains(next, current))
    problem = n.expandNotSuperset(network.cidr)

  return (
    <FormDialog
      open={open}
      onClose={onClose}
      title={n.expandTitle(network.name)}
      description={n.expandLead(network.cidr)}
      size="sm"
      dirty={dirty}
      requireDirty
      submitLabel={n.expandSubmit}
      pending={expand.isPending}
      error={formError(failure)}
      errorDetail={formErrorDetail(failure)}
      onSubmit={() => {
        setTouched(true)
        if (problem === null) expand.mutate(undefined, { onSuccess: onClose })
      }}
    >
      <Field label={n.expandLabel} error={(touched || dirty ? problem : null) ?? fieldError(failure, 'cidr')}>
        {(props) => (
          <Input
            {...props}
            className="font-mono"
            value={value}
            autoFocus
            onChange={(event) => {
              setValue(event.target.value)
              expand.reset()
            }}
          />
        )}
      </Field>
    </FormDialog>
  )
}

const ROUTING_DESC: Record<RoutingMode, () => string> = {
  direct_first: () => n.routingDirectFirstDesc,
  lowest_cost: () => n.routingLowestCostDesc,
}
const REACH_DESC: Record<Reach, () => string> = {
  any: () => n.reachAnyDesc,
  direct_only: () => n.reachDirectOnlyDesc,
  relay_only: () => n.reachRelayOnlyDesc,
}

/**
 * 网络的选路设置：一张卡片，一项一行（名字和说明在左，下拉在右，说明跟着选的那一项变），底边是取消和保存。
 * 几项一起改，所以是整站少数显式保存的表单：点"保存"才生效，没有改动时按钮是灰的。
 */
function RoutingCard({ network }: { network: Network }) {
  const nodes = useQuery(q.nodes(network.id))
  const [routing, setRouting] = useState<RoutingMode>(network.routing)
  const [hops, setHops] = useState(network.max_relay_hops)
  const [reach, setReach] = useState<Reach>(network.reach)
  // `null` 和 `auto` 是一回事；表单里一律写成 `auto`。
  const [serviceClass, setServiceClass] = useState<ServiceClass>(network.class ?? 'auto')
  const routingId = useId()
  const hopsId = useId()
  const reachId = useId()
  const classId = useId()

  const save = useAction(network.id, {
    mutationFn: (body: UpdateNetwork) => api.updateNetwork(network.id, body),
    success: n.settingsSaved,
    toastError: false,
  })

  const dirty =
    routing !== network.routing ||
    hops !== network.max_relay_hops ||
    reach !== network.reach ||
    serviceClass !== (network.class ?? 'auto')
  const overriding = (nodes.data ?? []).filter((node) => node.routing !== null).length
  const reset = () => {
    setRouting(network.routing)
    setHops(network.max_relay_hops)
    setReach(network.reach)
    setServiceClass(network.class ?? 'auto')
    save.reset()
  }

  return (
    <BoxCard>
      <BoxCardHeader title={n.routing} />
      <form
        noValidate
        aria-label={n.routing}
        onSubmit={(event) => {
          event.preventDefault()
          if (dirty) save.mutate({ routing, max_relay_hops: hops, reach, class: serviceClass })
        }}
      >
        <div className="divide-y">
          <SettingRow
            label={n.routingLabel}
            htmlFor={routingId}
            description={
              <>
                {ROUTING_DESC[routing]()}
                {overriding > 0 ? (
                  <Link
                    to={networkPath(network.id, 'nodes')}
                    className="block w-fit rounded-sm text-primary underline-offset-4 hover:underline"
                  >
                    {n.routingOverridden(overriding)}
                  </Link>
                ) : null}
              </>
            }
          >
            <NativeSelect
              id={routingId}
              className="w-48"
              value={routing}
              onChange={(event) => setRouting(event.target.value as RoutingMode)}
            >
              <option value="direct_first">{n.routingDirectFirst}</option>
              <option value="lowest_cost">{n.routingLowestCost}</option>
            </NativeSelect>
          </SettingRow>
          <SettingRow label={n.hopsLabel} htmlFor={hopsId} description={n.hopsDesc}>
            <NativeSelect
              id={hopsId}
              className="w-48"
              value={hops}
              onChange={(event) => setHops(Number(event.target.value))}
            >
              {Array.from(
                { length: MAX_RELAY_HOPS.max - MAX_RELAY_HOPS.min + 1 },
                (_, index) => MAX_RELAY_HOPS.min + index,
              ).map((value) => (
                <option key={value} value={value}>
                  {n.hops(value)}
                </option>
              ))}
            </NativeSelect>
          </SettingRow>
          <SettingRow label={n.reachLabel} htmlFor={reachId} description={REACH_DESC[reach]()}>
            <NativeSelect
              id={reachId}
              className="w-48"
              value={reach}
              onChange={(event) => setReach(event.target.value as Reach)}
            >
              <option value="any">{n.reachAny}</option>
              <option value="direct_only">{n.reachDirectOnly}</option>
              <option value="relay_only">{n.reachRelayOnly}</option>
            </NativeSelect>
          </SettingRow>
          <SettingRow
            label={n.classLabel}
            hint={n.classHint}
            htmlFor={classId}
            description={t.serviceClass[`${serviceClass}Desc`]}
          >
            <ClassSelect
              id={classId}
              compact
              className="w-48"
              value={serviceClass}
              inheritLabel={null}
              onChange={(value) => setServiceClass(value ?? 'auto')}
            />
          </SettingRow>
        </div>
        {save.isError ? (
          <div className="px-5 pb-1">
            <FormError
              message={formError(formFailure(save.error, {}))}
              detail={formErrorDetail(formFailure(save.error, {}))}
            />
          </div>
        ) : null}
        <footer className="flex items-center justify-end gap-2 border-t px-5 py-3">
          <Button size="sm" onClick={reset} disabled={!dirty || save.isPending}>
            {t.common.cancel}
          </Button>
          <Button size="sm" type="submit" variant="primary" disabled={!dirty} pending={save.isPending}>
            {n.saveSettings}
          </Button>
        </footer>
      </form>
    </BoxCard>
  )
}

/** 基本信息：名字、域名后缀、地址段（可以扩大）、节点、创建时间，和节点详情的信息卡一个样子。 */
function BasicsCard({ network, onExpand }: { network: Network; onExpand: () => void }) {
  return (
    <BoxCard>
      <BoxCardHeader title={n.basics} />
      <DetailList>
        <DetailRow icon={<Tag />} label={n.nameLabel} copy={network.name}>
          <span className="text-foreground">{network.name}</span>
        </DetailRow>
        <DetailRow icon={<Globe />} label={n.domainLabel} copy={network.domain}>
          <span className="font-mono text-[13px] text-foreground">{network.domain}</span>
        </DetailRow>
        <DetailRow
          icon={<NetworkIcon />}
          label={n.cidrLabel}
          copy={network.cidr}
          actions={
            <Button size="sm" variant="ghost" className="h-7 px-2 text-primary" onClick={onExpand}>
              {n.expand}
            </Button>
          }
        >
          <span className="font-mono text-[13px] text-foreground">{network.cidr}</span>
        </DetailRow>
        <DetailRow icon={<Server />} label={n.nodesLabel}>
          <Link
            to={networkPath(network.id, 'nodes')}
            className="rounded-sm text-foreground underline-offset-4 hover:text-primary hover:underline"
          >
            {n.nodes(network.nodes)}
          </Link>
        </DetailRow>
        <DetailRow icon={<CalendarDays />} label={n.createdAt}>
          <DateTimeValue at={network.created_at} />
        </DetailRow>
      </DetailList>
    </BoxCard>
  )
}

/** 其他网络：点一行切过去（顶栏的切换器也能切）。只有这一个网络时没有这张卡片。 */
function OthersCard({ networks, current }: { networks: readonly Network[]; current: Network }) {
  const others = networks.filter((other) => other.id !== current.id)
  if (others.length === 0) return null
  return (
    <BoxCard>
      <BoxCardHeader title={n.othersTitle} />
      <ul className="divide-y">
        {others.map((other) => (
          <li key={other.id}>
            <Link
              to={networkPath(other.id, 'network')}
              aria-label={n.switchTo(other.name)}
              className="grid min-h-11 grid-cols-[minmax(0,1fr)_auto_auto_1rem] items-center gap-4 px-5 py-2 text-sm transition-colors last:rounded-b-xl hover:bg-muted/50"
            >
              <span className="truncate font-medium">{other.name}</span>
              <span className="font-mono text-[13px] text-muted-foreground">{other.cidr}</span>
              <span className="w-16 text-right text-[13px] text-muted-foreground tabular">{n.nodes(other.nodes)}</span>
              <ChevronRight className="size-4 text-faint" aria-hidden />
            </Link>
          </li>
        ))}
      </ul>
    </BoxCard>
  )
}

/**
 * 删除网络：整站唯一需要输入名字的确认，因为它一次毁掉一批东西且无法撤回。
 * controller 只删空的网络，所以网络里还有节点时按钮是灰的，旁边写明要先做什么，不等提交了再报错。
 */
function DangerCard({ network }: { network: Network }) {
  const confirm = useConfirm()
  const navigate = useNavigate()
  const overview = useQuery(q.overview(network.id))
  const remove = useAction(null, {
    mutationFn: () => api.deleteNetwork(network.id),
    success: n.deleted(network.name),
  })

  const onDelete = async () => {
    const counts = overview.data
    const confirmed = await confirm({
      tone: 'danger',
      title: n.deleteTitle(network.name),
      body: counts === undefined ? n.dangerBody : n.deleteBody(counts.rules, counts.proxies, counts.pending_tokens),
      confirmLabel: n.deleteConfirm,
      typeToConfirm: network.name,
    })
    if (!confirmed) return
    remove.mutate(undefined, { onSuccess: () => void navigate('/', { replace: true }) })
  }

  return (
    <BoxCard aria-labelledby="network-danger-title">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-3 px-5 py-4">
        <div className="min-w-0">
          <h2 id="network-danger-title" className="text-[15px] leading-6 font-semibold">
            {n.dangerTitle}
          </h2>
          <p className="mt-0.5 text-[13px] text-muted-foreground">
            {network.nodes > 0 ? n.dangerNotEmpty(network.nodes) : n.dangerBody}
            {network.nodes > 0 ? (
              <>
                {' · '}
                <Link
                  to={networkPath(network.id, 'nodes')}
                  className="rounded-sm text-primary underline-offset-4 hover:underline"
                >
                  {n.viewNodes}
                </Link>
              </>
            ) : null}
          </p>
        </div>
        <Button
          size="sm"
          variant="danger-outline"
          disabled={network.nodes > 0}
          pending={remove.isPending}
          onClick={() => void onDelete()}
        >
          {n.deleteButton}
        </Button>
      </div>
    </BoxCard>
  )
}

/**
 * 网络页：和节点详情的概览一个样子，两栏卡片。左边基本信息、其他网络、删除网络；右边选路的设置。
 * 窄的时候一栏，选路排在基本信息后面。
 */
export function NetworkPage() {
  useDocumentTitle(n.title)
  const network = useNetwork()
  const networks = useQuery(q.networks())
  const [creating, setCreating] = useState(false)
  const [expanding, setExpanding] = useState(false)

  return (
    <Page>
      <PageHeader
        title={n.title}
        description={n.subtitle}
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus aria-hidden />
            {n.create}
          </Button>
        }
      />

      <div className="grid grid-cols-1 items-start gap-x-8 gap-y-6 @4xl:grid-cols-2">
        <div className="space-y-6">
          <BasicsCard network={network} onExpand={() => setExpanding(true)} />
          <OthersCard networks={networks.data ?? []} current={network} />
          <DangerCard network={network} />
        </div>
        {/* key：切换网络或者保存之后，表单从最新的设置重新开始。 */}
        <RoutingCard
          key={`${network.id}:${network.routing}:${network.max_relay_hops}:${network.reach}:${network.class ?? 'auto'}`}
          network={network}
        />
      </div>

      <CreateNetworkDialog open={creating} onClose={() => setCreating(false)} />
      {expanding ? <ExpandDialog network={network} open onClose={() => setExpanding(false)} /> : null}
    </Page>
  )
}
