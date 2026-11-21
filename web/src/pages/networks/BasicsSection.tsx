import { useQuery } from '@tanstack/react-query'
import { CalendarDays, ChevronRight, Globe, Network as NetworkIcon, Server, Tag } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'

import { fieldError, formError, formErrorDetail, formFailure } from '@/api/formErrors'
import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type Network } from '@/api/types'
import { DateTimeValue, DetailList, DetailRow } from '@/components/detail-list'
import { FormDialog } from '@/components/form-dialog'
import { Button } from '@/components/ui/button'
import { BoxCard, BoxCardHeader } from '@/components/ui/card'
import { Field } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { t } from '@/i18n'
import { cidrContains, formatCidr, parseCidr } from '@/lib/cidr'
import { validateNetworkCidr } from '@/lib/validate'

import { networkPath } from './context'

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

/** 「基本信息」分区：这个网络是什么（名字、域名后缀、地址段、节点、创建时间），和别的网络。 */
export function BasicsSection({ network }: { network: Network }) {
  const networks = useQuery(q.networks())
  const [expanding, setExpanding] = useState(false)
  return (
    <div className="space-y-6">
      <BasicsCard network={network} onExpand={() => setExpanding(true)} />
      <OthersCard networks={networks.data ?? []} current={network} />
      {expanding ? <ExpandDialog network={network} open onClose={() => setExpanding(false)} /> : null}
    </div>
  )
}
