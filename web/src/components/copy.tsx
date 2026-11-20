import { Check, Copy } from 'lucide-react'
import { Fragment, type ReactNode, useEffect, useState } from 'react'

import { Button, type ButtonProps } from '@/components/ui/button'
import { toast } from '@/components/ui/toast'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { copyText } from '@/lib/clipboard'
import { matchesMedia, NO_HOVER } from '@/lib/useMediaQuery'
import { cn } from '@/lib/utils'

/** 点过之后"已复制"保持多久。 */
const COPIED_MS = 2000

/**
 * `quiet`：复制成功只在原地变一下（图标、悬停的说明）。触屏上没有悬停，原地那一下又常常看不到（手指挡着、图标藏着），
 * 所以再弹一条通知；按钮上本来就写着"已复制"的不用。
 */
function useCopy(value: string, { quiet = false }: { quiet?: boolean } = {}): { copied: boolean; copy: () => void } {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return undefined
    const timer = window.setTimeout(() => setCopied(false), COPIED_MS)
    return () => window.clearTimeout(timer)
  }, [copied])

  const copy = () => {
    void copyText(value).then((ok) => {
      if (!ok) {
        toast.error(t.common.copyFailed)
        return
      }
      setCopied(true)
      if (quiet && matchesMedia(NO_HOVER)) toast.success(t.common.copied)
    })
  }
  return { copied, copy }
}

interface CopyButtonProps extends Omit<ButtonProps, 'value' | 'onClick' | 'children'> {
  /** 复制出去的内容。可以和屏幕上显示的不一样：显示可以截短、折行，复制出去的总是完整的一行。 */
  value: string
  /** 按钮上的文字。不给就只有图标，这时 `label` 作为读屏和悬停的说明。 */
  children?: ReactNode
  label?: string
}

export function CopyButton({
  value,
  children,
  label = t.common.copy,
  variant = 'outline',
  size,
  className,
  ...props
}: CopyButtonProps) {
  const { copied, copy } = useCopy(value, { quiet: children === undefined })
  const Icon = copied ? Check : Copy
  if (children === undefined) {
    return (
      <Tooltip content={copied ? t.common.copied : label}>
        <Button
          variant={variant}
          size={size ?? 'icon-sm'}
          onClick={copy}
          aria-label={copied ? t.common.copied : label}
          className={cn(copied && 'text-ok', className)}
          {...props}
        >
          <Icon aria-hidden />
        </Button>
      </Tooltip>
    )
  }
  return (
    <Button variant={variant} size={size} onClick={copy} className={className} {...props}>
      <Icon aria-hidden className={cn(copied && 'text-ok')} />
      <span aria-live="polite">{copied ? t.common.copied : children}</span>
    </Button>
  )
}

interface CopyTextProps {
  value: string
  /** 显示的内容，默认就是 `value`。截短显示时用。 */
  children?: ReactNode
  mono?: boolean
  /** 太长时折行而不是截短。给公钥这种要看全的值用。 */
  wrap?: boolean
  className?: string
}

/** 一个点一下就复制的值：虚拟 IP、名字、地址端口。 */
export function CopyText({ value, children, mono = true, wrap = false, className }: CopyTextProps) {
  const { copied, copy } = useCopy(value, { quiet: true })
  return (
    <Tooltip content={copied ? t.common.copied : t.common.clickToCopy}>
      <button
        type="button"
        onClick={(event) => {
          event.stopPropagation()
          copy()
        }}
        aria-label={t.common.copyValue(value)}
        className={cn(
          'group/copy inline-flex max-w-full items-center gap-1 rounded-sm text-left hover:text-primary',
          mono && 'font-mono text-[13px]',
          className,
        )}
      >
        <span className={wrap ? 'break-all' : 'truncate'}>{children ?? value}</span>
        {copied ? (
          <Check className="size-3 shrink-0 text-ok" aria-hidden />
        ) : (
          <Copy
            className="size-3 shrink-0 opacity-0 transition-opacity group-hover/copy:opacity-70 group-focus-visible/copy:opacity-70"
            aria-hidden
          />
        )}
      </button>
    </Tooltip>
  )
}

interface CodeBlockProps {
  /** 屏幕上显示的内容。 */
  children: ReactNode
  /** 复制出去的内容；`null` 表示现在还没有可以复制的东西（例如令牌还没生成），按钮置灰。 */
  copy: string | null
  copyLabel?: string
  /** 复制按钮置灰时悬停的说明。 */
  disabledReason?: string
  label?: string
  className?: string
  testId?: string
}

/**
 * 在每个斜杠后面留一个可以折行的地方：浏览器把整个地址当成一个词，不留的话它要么整个掉到下一行，
 * 要么断在词中间。复制出去的内容不受影响。
 */
function breakable(text: string): ReactNode {
  return text.split(/(?<=\/)(?=[^/])/).map((piece, index) => (
    // 片段的顺序不会变，用位置作键没有问题。
    <Fragment key={index}>
      {index > 0 ? <wbr /> : null}
      {piece}
    </Fragment>
  ))
}

/**
 * 一段要照着执行的命令，或者一个要原样保存的密钥。等宽、完整显示、右侧带复制。
 * 一行放不下时先在空格和斜杠处折，实在没有地方折才在词中间断开。
 */
export function CodeBlock({
  children,
  copy,
  copyLabel = t.common.copy,
  disabledReason,
  label,
  className,
  testId,
}: CodeBlockProps) {
  return (
    <div className={cn('flex items-start gap-2 rounded-md bg-muted py-2 pr-2 pl-3.5', className)}>
      <pre
        aria-label={label}
        data-testid={testId}
        tabIndex={0}
        className="min-w-0 flex-1 overflow-x-auto py-1 font-mono text-[13px] leading-relaxed wrap-anywhere whitespace-pre-wrap"
      >
        {typeof children === 'string' ? breakable(children) : children}
      </pre>
      {copy === null ? (
        <Tooltip content={disabledReason}>
          <span tabIndex={0} className="rounded-md">
            <Button size="sm" disabled aria-label={copyLabel}>
              <Copy aria-hidden />
              {copyLabel}
            </Button>
          </span>
        </Tooltip>
      ) : (
        <CopyButton value={copy} size="sm">
          {copyLabel}
        </CopyButton>
      )}
    </div>
  )
}
