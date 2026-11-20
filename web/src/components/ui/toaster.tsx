import { CircleAlert, CircleCheck, Info, LoaderCircle, X } from 'lucide-react'
import { useEffect, useState } from 'react'

import { t } from '@/i18n'
import { cn } from '@/lib/utils'

import { toast, type ToastItem, useToasts } from './toast'

/** 成功和提示类的通知多久之后自己消失。 */
const AUTO_DISMISS_MS = 4500

const ICONS = { loading: LoaderCircle, success: CircleCheck, error: CircleAlert, info: Info } as const
const TONES = {
  loading: 'text-muted-foreground',
  success: 'text-ok',
  error: 'text-danger',
  info: 'text-relay',
} as const

function ToastView({ item }: { item: ToastItem }) {
  const Icon = ICONS[item.kind]
  const sticky = item.kind === 'error' || item.kind === 'loading'
  // 鼠标停在上面、或者键盘焦点在里面时不消失：用户正在读。
  const [held, setHeld] = useState(false)

  useEffect(() => {
    if (sticky || held) return undefined
    const timer = window.setTimeout(() => toast.dismiss(item.id), AUTO_DISMISS_MS)
    return () => window.clearTimeout(timer)
  }, [item.id, item.kind, item.message, sticky, held])

  return (
    <li
      role={item.kind === 'error' ? 'alert' : 'status'}
      onMouseEnter={() => setHeld(true)}
      onMouseLeave={() => setHeld(false)}
      onFocus={() => setHeld(true)}
      onBlur={() => setHeld(false)}
      className={cn(
        'pointer-events-auto flex w-full animate-rise items-start gap-2.5 rounded-lg bg-card px-3.5 py-3 shadow-pop md:w-88',
      )}
    >
      <Icon
        className={cn('mt-0.5 size-4 shrink-0', TONES[item.kind], item.kind === 'loading' && 'animate-spin')}
        aria-hidden
      />
      <div className="min-w-0 flex-1 text-sm leading-snug break-words">
        <p>{item.message}</p>
        {item.detail !== undefined && item.detail !== null ? (
          <p className="mt-0.5 text-xs text-muted-foreground">{item.detail}</p>
        ) : null}
      </div>
      {item.kind === 'loading' ? null : (
        <button
          type="button"
          onClick={() => toast.dismiss(item.id)}
          aria-label={t.common.dismiss}
          className="-mt-0.5 -mr-1.5 flex size-6 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground"
        >
          <X className="size-3.5" aria-hidden />
        </button>
      )}
    </li>
  )
}

/**
 * 通知的容器，整个应用只放一个。
 *
 * 容器自己标成 `aria-live`：对话框打开时，它外面的东西对读屏软件都是隐藏的，只有标了 `aria-live` 的例外。
 * 不标的话，在对话框里改了东西（例如给节点打标签）弹出的那条"已更新"看得见却读不出来。
 */
export function Toaster() {
  const items = useToasts()
  return (
    <ol
      aria-label={t.common.notifications}
      aria-live="polite"
      className="pointer-events-none fixed inset-x-3 bottom-[calc(0.75rem+env(safe-area-inset-bottom))] z-[80] flex flex-col gap-2 md:inset-x-auto md:right-5 md:bottom-5"
    >
      {items.map((item) => (
        <ToastView key={item.id} item={item} />
      ))}
    </ol>
  )
}
