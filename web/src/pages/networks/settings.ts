import { type Network, type NetworkDefaults } from '@/api/types'
import { type ModifiedSetting } from '@/components/setting-row'

/**
 * 网络的设置各在哪个分区。加一项设置就在这里加它的字段名：分区名旁边"改过几项"的数跟着对。
 * 没有可改的设置的分区（基本信息、危险操作）不在这里。
 */
export const SECTION_SETTINGS = {
  routing: ['routing', 'max_relay_hops', 'reach', 'class'],
  connection: ['ack_eliciting_threshold', 'max_ack_delay_ms'],
  adapter: ['vnet_offload', 'vnet_mtu', 'bundle_small_packets'],
} as const satisfies Record<string, readonly (keyof NetworkDefaults)[]>

export type SettingsSection = keyof typeof SECTION_SETTINGS

/** 这个分区里有几项设置和默认值不一样。controller 没给默认值（比这项功能旧）时说不出来，算 0。 */
export function modifiedCount(network: Network, section: SettingsSection): number {
  const defaults = network.defaults ?? null
  if (defaults === null) return 0
  // QoS 的 `null` 和 `auto` 是一回事。别的设置没有 `null`。
  return SECTION_SETTINGS[section].filter((name) => (network[name] ?? 'auto') !== (defaults[name] ?? 'auto')).length
}

/**
 * 一行设置现在的值和默认值不一样时，交给 `SettingRow` 的"已修改"：默认值怎么写，恢复默认时把它填回表单。
 * 一样、或者 controller 没给默认值时是 `null`，那一行什么都不标。
 */
export function modifiedFrom<T>(
  current: T | null,
  fallback: T | undefined,
  label: (value: T) => string,
  restore: (value: T) => void,
): ModifiedSetting | null {
  if (fallback === undefined || current === fallback) return null
  return { defaultLabel: label(fallback), onRestore: () => restore(fallback) }
}

/** 输入框里写的是不是 `range` 里的一个整数；不是的话是 `null`。 */
export function wholeNumberWithin(raw: string, range: { min: number; max: number }): number | null {
  const text = raw.trim()
  if (!/^\d{1,4}$/.test(text)) return null
  const value = Number(text)
  return value >= range.min && value <= range.max ? value : null
}
