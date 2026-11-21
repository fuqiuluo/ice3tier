import { formError, formErrorDetail, formFailure } from '@/api/formErrors'
import { Button } from '@/components/ui/button'
import { FormError } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { t } from '@/i18n'

interface SaveBarProps {
  /** 上一次保存出的错。 */
  error: unknown
  /** 左边的一句话：这个分区的设置什么时候生效之类。 */
  note?: string
  canSave: boolean
  dirty: boolean
  pending: boolean
  onReset: () => void
}

/** 设置分区的底边：保存出的错，左边一句话，右边取消和保存。一个分区的几项一起保存。 */
export function SaveBar({ error, note, canSave, dirty, pending, onReset }: SaveBarProps) {
  const failure = formFailure(error, {})
  return (
    <>
      {failure !== null ? (
        <div className="px-5 pb-1">
          <FormError message={formError(failure)} detail={formErrorDetail(failure)} />
        </div>
      ) : null}
      <footer className="flex flex-wrap items-center justify-end gap-x-4 gap-y-2 border-t px-5 py-3">
        {note !== undefined ? <p className="mr-auto text-[13px] text-muted-foreground">{note}</p> : null}
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={onReset} disabled={!dirty || pending}>
            {t.common.cancel}
          </Button>
          <Button size="sm" type="submit" variant="primary" disabled={!canSave} pending={pending}>
            {t.networks.saveSettings}
          </Button>
        </div>
      </footer>
    </>
  )
}

interface NumberWithUnitProps {
  id: string
  value: string
  unit: string
  invalid: boolean
  onChange: (value: string) => void
}

/** 一个整数和它的单位：一行设置右边的控件。和下拉一样宽，各个分区的控件左右对齐。 */
export function NumberWithUnit({ id, value, unit, invalid, onChange }: NumberWithUnitProps) {
  return (
    <span className="flex w-48 items-center gap-2">
      <Input
        id={id}
        inputMode="numeric"
        className="min-w-0 flex-1 tabular"
        aria-invalid={invalid ? true : undefined}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
      {/* 单位留一样宽，几行的输入框对齐。 */}
      <span className="w-14 shrink-0 text-[13px] text-muted-foreground">{unit}</span>
    </span>
  )
}
