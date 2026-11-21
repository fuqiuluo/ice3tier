import { useId, useState } from 'react'

import { api } from '@/api/endpoints'
import { useAction } from '@/api/queries'
import { type Network, type UpdateNetwork } from '@/api/types'
import { SettingRow } from '@/components/setting-row'
import { BoxCard, BoxCardHeader } from '@/components/ui/card'
import { t } from '@/i18n'
import { ACK_ELICITING_THRESHOLD, MAX_ACK_DELAY_MS } from '@/lib/product'

import { NumberWithUnit, SaveBar } from './sectionParts'
import { modifiedFrom, wholeNumberWithin } from './settings'

const n = t.networks

/**
 * 「连接」分区：节点之间的连接的参数，和选路那个分区一个样子。现在是请对端怎样确认的两项，别的连接参数接着往下加行。
 * 节点只在建连接时用这些值，所以底边写着"只对之后新建的连接生效"。
 */
export function ConnectionSection({ network }: { network: Network }) {
  const [threshold, setThreshold] = useState(String(network.ack_eliciting_threshold))
  const [delay, setDelay] = useState(String(network.max_ack_delay_ms))
  const thresholdId = useId()
  const delayId = useId()

  const save = useAction(network.id, {
    mutationFn: (body: UpdateNetwork) => api.updateNetwork(network.id, body),
    success: n.settingsSaved,
    toastError: false,
  })

  const defaults = network.defaults ?? undefined
  const nextThreshold = wholeNumberWithin(threshold, ACK_ELICITING_THRESHOLD)
  const nextDelay = wholeNumberWithin(delay, MAX_ACK_DELAY_MS)
  const dirty = nextThreshold !== network.ack_eliciting_threshold || nextDelay !== network.max_ack_delay_ms
  const changed = (set: (text: string) => void) => (text: string) => {
    set(text)
    save.reset()
  }
  const reset = () => {
    setThreshold(String(network.ack_eliciting_threshold))
    setDelay(String(network.max_ack_delay_ms))
    save.reset()
  }

  return (
    <BoxCard>
      <BoxCardHeader title={n.connection} />
      <form
        noValidate
        aria-label={n.connection}
        onSubmit={(event) => {
          event.preventDefault()
          if (dirty && nextThreshold !== null && nextDelay !== null)
            save.mutate({ ack_eliciting_threshold: nextThreshold, max_ack_delay_ms: nextDelay })
        }}
      >
        <div className="divide-y">
          <SettingRow
            label={n.ackThresholdLabel}
            hint={n.ackThresholdHint}
            htmlFor={thresholdId}
            description={n.ackThresholdDesc}
            modified={modifiedFrom(
              nextThreshold,
              defaults?.ack_eliciting_threshold,
              (value) => `${value} ${n.ackThresholdUnit}`,
              (value) => changed(setThreshold)(String(value)),
            )}
            error={
              nextThreshold === null
                ? n.wholeNumberBetween(ACK_ELICITING_THRESHOLD.min, ACK_ELICITING_THRESHOLD.max)
                : null
            }
          >
            <NumberWithUnit
              id={thresholdId}
              value={threshold}
              unit={n.ackThresholdUnit}
              invalid={nextThreshold === null}
              onChange={changed(setThreshold)}
            />
          </SettingRow>
          <SettingRow
            label={n.ackDelayLabel}
            hint={n.ackDelayHint}
            htmlFor={delayId}
            description={n.ackDelayDesc}
            modified={modifiedFrom(
              nextDelay,
              defaults?.max_ack_delay_ms,
              (value) => `${value} ${n.ackDelayUnit}`,
              (value) => changed(setDelay)(String(value)),
            )}
            error={nextDelay === null ? n.wholeNumberBetween(MAX_ACK_DELAY_MS.min, MAX_ACK_DELAY_MS.max) : null}
          >
            <NumberWithUnit
              id={delayId}
              value={delay}
              unit={n.ackDelayUnit}
              invalid={nextDelay === null}
              onChange={changed(setDelay)}
            />
          </SettingRow>
        </div>
        <SaveBar
          error={save.error}
          note={n.connectionNote}
          canSave={dirty && nextThreshold !== null && nextDelay !== null}
          dirty={dirty}
          pending={save.isPending}
          onReset={reset}
        />
      </form>
    </BoxCard>
  )
}
