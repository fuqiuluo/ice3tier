import { AlertDialog } from 'radix-ui'
import { createContext, type ReactNode, use, useCallback, useId, useMemo, useRef, useState } from 'react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { t } from '@/i18n'

export interface ConfirmOptions {
  /** 带对象的名字和动作，例如"删除 nas-01？"。 */
  title: string
  /** 具体的后果和数字。算不出来的后果不写。 */
  body?: ReactNode
  /** 动词加对象，例如"删除节点"。不写"确定"。 */
  confirmLabel: string
  cancelLabel?: string
  /**
   * `normal`：会打断正在进行的事，或者让别处的配置失效。
   * `danger`：不能撤回。确认按钮是红色，默认焦点在"取消"上。
   */
  tone?: 'normal' | 'danger'
  /** 要先输入这个名字，确认按钮才可用。只给一次毁掉一大批东西的操作用。 */
  typeToConfirm?: string
}

type Confirm = (options: ConfirmOptions) => Promise<boolean>

const ConfirmContext = createContext<Confirm | null>(null)

interface Pending {
  options: ConfirmOptions
  resolve: (confirmed: boolean) => void
}

/** 全站只有这一个确认框。点对话框外面不关闭，必须明确选一个。 */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null)
  const [typed, setTyped] = useState('')
  const confirmRef = useRef<HTMLButtonElement>(null)
  const typedId = useId()

  const confirm = useCallback<Confirm>(
    (options) =>
      new Promise<boolean>((resolve) => {
        setTyped('')
        setPending({ options, resolve })
      }),
    [],
  )

  const settle = (confirmed: boolean) => {
    pending?.resolve(confirmed)
    setPending(null)
  }

  const options = pending?.options
  const danger = options?.tone === 'danger'
  const mustType = options?.typeToConfirm
  const typedOk = mustType === undefined || typed.trim() === mustType

  const value = useMemo(() => confirm, [confirm])

  return (
    <ConfirmContext value={value}>
      {children}
      <AlertDialog.Root open={pending !== null} onOpenChange={(open) => (open ? undefined : settle(false))}>
        <AlertDialog.Portal>
          <AlertDialog.Overlay className="fixed inset-0 z-[70] animate-fade bg-foreground/30" />
          <AlertDialog.Content
            onOpenAutoFocus={(event) => {
              // 普通确认把焦点放在确认按钮上，回车即可；危险确认留在"取消"上（库的默认行为），回车不会误删。
              if (!danger && mustType === undefined && confirmRef.current !== null) {
                event.preventDefault()
                confirmRef.current.focus()
              }
            }}
            className="fixed top-1/2 left-1/2 z-[71] w-[min(30rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 animate-fade rounded-xl bg-card p-5 md:p-6 shadow-pop outline-none"
          >
            <AlertDialog.Title className="text-base font-semibold">{options?.title}</AlertDialog.Title>
            <AlertDialog.Description asChild>
              <div className="mt-2 space-y-2 text-[13px] leading-relaxed text-muted-foreground">{options?.body}</div>
            </AlertDialog.Description>
            {mustType !== undefined ? (
              <div className="mt-4 flex flex-col gap-1.5">
                <label htmlFor={typedId} className="text-[13px] font-medium">
                  {t.confirm.typeName(mustType)}
                </label>
                <Input id={typedId} value={typed} onChange={(event) => setTyped(event.target.value)} autoFocus />
              </div>
            ) : null}
            <div className="mt-6 flex justify-end gap-2">
              <AlertDialog.Cancel asChild>
                <Button variant="outline">{options?.cancelLabel ?? t.common.cancel}</Button>
              </AlertDialog.Cancel>
              <Button
                ref={confirmRef}
                variant={danger ? 'danger' : 'primary'}
                disabled={!typedOk}
                onClick={() => settle(true)}
              >
                {options?.confirmLabel}
              </Button>
            </div>
          </AlertDialog.Content>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    </ConfirmContext>
  )
}

// eslint-disable-next-line react-refresh/only-export-components -- hook 和它的 Provider 放在一起更好找
export function useConfirm(): Confirm {
  const confirm = use(ConfirmContext)
  if (confirm === null) throw new Error('useConfirm 要在 ConfirmProvider 里面用')
  return confirm
}
