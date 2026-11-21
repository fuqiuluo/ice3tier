import { useQuery } from '@tanstack/react-query'
import { useId, useState } from 'react'
import { Link } from 'react-router'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type Network, type Reach, type RoutingMode, type ServiceClass, type UpdateNetwork } from '@/api/types'
import { SettingRow } from '@/components/setting-row'
import { BoxCard, BoxCardHeader } from '@/components/ui/card'
import { NativeSelect } from '@/components/ui/input'
import { ClassSelect } from '@/components/usage'
import { t } from '@/i18n'
import { MAX_RELAY_HOPS } from '@/lib/product'

import { networkPath } from './context'
import { SaveBar } from './sectionParts'
import { modifiedFrom } from './settings'

const n = t.networks

const ROUTING_NAME: Record<RoutingMode, () => string> = {
  direct_first: () => n.routingDirectFirst,
  lowest_cost: () => n.routingLowestCost,
}
const ROUTING_DESC: Record<RoutingMode, () => string> = {
  direct_first: () => n.routingDirectFirstDesc,
  lowest_cost: () => n.routingLowestCostDesc,
}
const REACH_NAME: Record<Reach, () => string> = {
  any: () => n.reachAny,
  direct_only: () => n.reachDirectOnly,
  relay_only: () => n.reachRelayOnly,
}
const REACH_DESC: Record<Reach, () => string> = {
  any: () => n.reachAnyDesc,
  direct_only: () => n.reachDirectOnlyDesc,
  relay_only: () => n.reachRelayOnlyDesc,
}

/**
 * 「选路」分区：一项一行（名字和说明在左，下拉在右，说明跟着选的那一项变），底边是取消和保存。
 * 几项一起改，所以是整站少数显式保存的表单：点"保存"才生效，没有改动时按钮是灰的。
 * 和默认值不一样的那一行标着"已修改"；"恢复默认"把默认值填回表单，也要点保存。
 */
export function RoutingSection({ network }: { network: Network }) {
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

  const defaults = network.defaults ?? undefined
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
            modified={modifiedFrom(routing, defaults?.routing, (value) => ROUTING_NAME[value](), setRouting)}
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
          <SettingRow
            label={n.hopsLabel}
            htmlFor={hopsId}
            description={n.hopsDesc}
            modified={modifiedFrom(hops, defaults?.max_relay_hops, n.hops, setHops)}
          >
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
          <SettingRow
            label={n.reachLabel}
            htmlFor={reachId}
            description={REACH_DESC[reach]()}
            modified={modifiedFrom(reach, defaults?.reach, (value) => REACH_NAME[value](), setReach)}
          >
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
            modified={modifiedFrom(
              serviceClass,
              defaults === undefined ? undefined : (defaults.class ?? 'auto'),
              (value) => t.serviceClass[value],
              setServiceClass,
            )}
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
        <SaveBar error={save.error} canSave={dirty} dirty={dirty} pending={save.isPending} onReset={reset} />
      </form>
    </BoxCard>
  )
}
