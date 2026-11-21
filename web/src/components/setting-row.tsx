import { type ReactNode } from 'react'

import { InfoTip } from '@/components/info-tip'
import { Badge } from '@/components/ui/badge'
import { t } from '@/i18n'
import { cn } from '@/lib/utils'

/** 一项设置现在的值和默认值不一样：默认值怎么写，恢复默认时做什么。 */
export interface ModifiedSetting {
  defaultLabel: string
  onRestore: () => void
}

interface SettingRowProps {
  label: string
  /** 悬停在 ⓘ 上看的说明。 */
  hint?: string
  /** 直接写在名字下面的说明：不看就不懂这一项时用它，不用 `hint`。控件用 `aria-describedby` 指向 `descriptionId`。 */
  description?: ReactNode
  descriptionId?: string
  /** 名字是哪个控件的 `<label>`；不给时名字是一段带 `labelId` 的文字（控件用 `aria-labelledby` 指向它）。 */
  htmlFor?: string
  labelId?: string
  /** 控件放在名字下面（可以选好几个的那种），而不是右边。 */
  stacked?: boolean
  /** 这一项的值不对：写在这一行的最下面。 */
  error?: string | null
  /** 值和默认值不一样时给：名字旁边标"已修改"，说明下面写默认值和"恢复默认"。一样、或者说不出默认值时不给。 */
  modified?: ModifiedSetting | null
  /** 外边距另给（嵌在别的行下面时去掉左右的留白）。 */
  className?: string
  children: ReactNode
}

/** 一项设置：左边是名字和悬停的说明，右边是控件。行和信息卡一样高、一样的字。 */
export function SettingRow({
  label,
  hint,
  description,
  descriptionId,
  htmlFor,
  labelId,
  stacked = false,
  error,
  modified = null,
  className,
  children,
}: SettingRowProps) {
  const problem =
    error !== undefined && error !== null && error !== '' ? (
      <p role="alert" className="mt-1.5 text-[13px] text-danger">
        {error}
      </p>
    ) : null
  const name = (
    <div className="min-w-32 flex-1">
      <div className="flex items-center gap-1.5 text-sm">
        {htmlFor !== undefined ? <label htmlFor={htmlFor}>{label}</label> : <span id={labelId}>{label}</span>}
        {hint !== undefined ? <InfoTip>{hint}</InfoTip> : null}
        {modified !== null ? <Badge tone="accent">{t.common.modified}</Badge> : null}
      </div>
      {description !== undefined ? (
        <p id={descriptionId} className="mt-0.5 text-[13px] text-muted-foreground">
          {description}
        </p>
      ) : null}
      {modified !== null ? (
        <p className="mt-0.5 text-[13px] text-muted-foreground">
          {t.common.defaultIs(modified.defaultLabel)}
          {' · '}
          <button
            type="button"
            aria-label={t.common.restoreDefaultOf(label)}
            onClick={modified.onRestore}
            className="rounded-sm text-primary underline-offset-4 hover:underline"
          >
            {t.common.restoreDefault}
          </button>
        </p>
      ) : null}
    </div>
  )
  if (stacked) {
    return (
      <div className={cn('px-5 py-3', className)}>
        <div className="flex min-h-7 items-center">{name}</div>
        <div className="mt-2">{children}</div>
        {problem}
      </div>
    )
  }
  return (
    <div className={cn('px-5 py-2.5', className)}>
      {/* 控件和名字一行放不下时（窄屏上的输入框、分段切换）换到名字下面。 */}
      <div className="flex min-h-9 flex-wrap items-center justify-between gap-x-4 gap-y-2">
        {name}
        <div className="max-w-full shrink-0">{children}</div>
      </div>
      {problem}
    </div>
  )
}
