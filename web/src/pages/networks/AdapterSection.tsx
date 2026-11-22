import { useId, useState } from 'react'

import { api } from '@/api/endpoints'
import { useAction } from '@/api/queries'
import { type Network, type UpdateNetwork } from '@/api/types'
import { SettingRow } from '@/components/setting-row'
import { BoxCard, BoxCardHeader } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { t } from '@/i18n'
import { VNET_MTU } from '@/lib/product'

import { NumberWithUnit, SaveBar } from './sectionParts'
import { modifiedFrom, wholeNumberWithin } from './settings'

const n = t.networks

/**
 * 「虚拟网卡」分区：节点的虚拟网卡照什么建、包怎么走。分段卸载的开关、默认的 MTU、合并小包的开关。
 * 前两项节点收到之后自己把网卡重装一遍，合并小包收到就生效，都不用重启节点。
 * 比某一项旧的 controller 不报它：那时不显示那一行，也不提交它；一项都不报时说明一句。
 */
export function AdapterSection({ network }: { network: Network }) {
  const supportsOffload = network.vnet_offload !== undefined
  const supportsMtu = network.vnet_mtu !== undefined
  const supportsBundling = network.bundle_small_packets !== undefined
  const [offload, setOffload] = useState(network.vnet_offload ?? true)
  const [mtu, setMtu] = useState(String(network.vnet_mtu ?? ''))
  const [bundle, setBundle] = useState(network.bundle_small_packets ?? true)
  const offloadLabelId = useId()
  const offloadDescId = useId()
  const mtuId = useId()
  const bundleLabelId = useId()
  const bundleDescId = useId()

  const save = useAction(network.id, {
    mutationFn: (body: UpdateNetwork) => api.updateNetwork(network.id, body),
    success: n.settingsSaved,
    toastError: false,
  })

  const defaults = network.defaults ?? undefined
  const nextMtu = supportsMtu ? wholeNumberWithin(mtu, VNET_MTU) : null
  const mtuInvalid = supportsMtu && nextMtu === null
  const offloadDirty = supportsOffload && offload !== network.vnet_offload
  const mtuDirty = supportsMtu && nextMtu !== network.vnet_mtu
  const bundleDirty = supportsBundling && bundle !== network.bundle_small_packets
  const dirty = offloadDirty || mtuDirty || bundleDirty
  const changed =
    <T,>(set: (value: T) => void) =>
    (value: T) => {
      set(value)
      save.reset()
    }
  const reset = () => {
    setOffload(network.vnet_offload ?? true)
    setMtu(String(network.vnet_mtu ?? ''))
    setBundle(network.bundle_small_packets ?? true)
    save.reset()
  }
  const onOff = (on: boolean) => (on ? n.switchOn : n.switchOff)

  if (!supportsOffload && !supportsMtu && !supportsBundling)
    return (
      <BoxCard>
        <BoxCardHeader title={n.adapter} />
        <p className="px-5 py-4 text-[13px] text-muted-foreground">{n.adapterUnsupported}</p>
      </BoxCard>
    )

  return (
    <BoxCard>
      <BoxCardHeader title={n.adapter} />
      <form
        noValidate
        aria-label={n.adapter}
        onSubmit={(event) => {
          event.preventDefault()
          // 只提交动过的那几项。
          if (dirty && !mtuInvalid)
            save.mutate({
              ...(offloadDirty ? { vnet_offload: offload } : {}),
              ...(mtuDirty && nextMtu !== null ? { vnet_mtu: nextMtu } : {}),
              ...(bundleDirty ? { bundle_small_packets: bundle } : {}),
            })
        }}
      >
        <div className="divide-y">
          {supportsOffload ? (
            <SettingRow
              label={n.offloadLabel}
              hint={n.offloadHint}
              labelId={offloadLabelId}
              description={n.offloadDesc}
              descriptionId={offloadDescId}
              modified={modifiedFrom(offload, defaults?.vnet_offload, onOff, changed(setOffload))}
            >
              <Switch
                aria-labelledby={offloadLabelId}
                aria-describedby={offloadDescId}
                checked={offload}
                onCheckedChange={changed(setOffload)}
              />
            </SettingRow>
          ) : null}
          {supportsMtu ? (
            <SettingRow
              label={n.mtuLabel}
              hint={n.mtuHint}
              htmlFor={mtuId}
              description={n.mtuDesc}
              modified={modifiedFrom(
                nextMtu,
                defaults?.vnet_mtu,
                (value) => `${value} ${n.mtuUnit}`,
                (value) => changed(setMtu)(String(value)),
              )}
              error={mtuInvalid ? n.wholeNumberBetween(VNET_MTU.min, VNET_MTU.max) : null}
            >
              <NumberWithUnit id={mtuId} value={mtu} unit={n.mtuUnit} invalid={mtuInvalid} onChange={changed(setMtu)} />
            </SettingRow>
          ) : null}
          {supportsBundling ? (
            <SettingRow
              label={n.bundleLabel}
              hint={n.bundleHint}
              labelId={bundleLabelId}
              description={n.bundleDesc}
              descriptionId={bundleDescId}
              modified={modifiedFrom(bundle, defaults?.bundle_small_packets, onOff, changed(setBundle))}
            >
              <Switch
                aria-labelledby={bundleLabelId}
                aria-describedby={bundleDescId}
                checked={bundle}
                onCheckedChange={changed(setBundle)}
              />
            </SettingRow>
          ) : null}
        </div>
        <SaveBar
          error={save.error}
          canSave={dirty && !mtuInvalid}
          dirty={dirty}
          pending={save.isPending}
          onReset={reset}
        />
      </form>
    </BoxCard>
  )
}
