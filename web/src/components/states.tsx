import { CircleAlert, type LucideIcon, SearchX } from 'lucide-react'
import { type ReactNode } from 'react'

import { errorDetail, errorMessage } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { t } from '@/i18n'
import { cn } from '@/lib/utils'

interface EmptyStateProps {
  icon?: LucideIcon
  /** 一句话：现在是什么情况。 */
  title: string
  /** 一句解释：这是什么、为什么要它。 */
  description?: ReactNode
  /** 下一步做什么。通常只有一个主按钮。 */
  action?: ReactNode
  children?: ReactNode
  className?: string
}

/**
 * "还没有数据"的样子：它本身就是入口。和"筛选之后没有结果"是两回事，后者用 {@link NoMatches}。
 * 不画框也不画插图：一个淡灰的图标、一句话、一句说明、一个按钮，居中，上下留足空白。
 */
export function EmptyState({ icon: Icon, title, description, action, children, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center px-6 py-16 text-center', className)}>
      {Icon !== undefined ? <Icon className="mb-4 size-7 text-faint" aria-hidden /> : null}
      <h2 className="text-base font-semibold">{title}</h2>
      {description !== undefined ? (
        <p className="mt-1.5 max-w-md text-[13px] leading-relaxed text-muted-foreground">{description}</p>
      ) : null}
      {action !== undefined ? (
        <div className="mt-6 flex flex-wrap items-center justify-center gap-2">{action}</div>
      ) : null}
      {children}
    </div>
  )
}

/** 筛选或搜索之后一行也不剩。 */
export function NoMatches({ message, onClear }: { message: string; onClear: () => void }) {
  return (
    <div className="flex flex-col items-center px-6 py-12 text-center">
      <SearchX className="mb-3 size-6 text-faint" aria-hidden />
      <p className="text-sm text-muted-foreground">{message}</p>
      <Button variant="outline" size="sm" className="mt-4" onClick={onClear}>
        {t.common.clearFilters}
      </Button>
    </div>
  )
}

interface ErrorStateProps {
  /** 哪一步出了错，例如"节点列表没有取到"。 */
  title: string
  error: unknown
  onRetry?: () => void
  className?: string
}

/** 取数失败：一句标题、原因（按错误码写），码太笼统时下面再加 controller 的原话。 */
export function ErrorState({ title, error, onRetry, className }: ErrorStateProps) {
  const detail = errorDetail(error)
  return (
    <div role="alert" className={cn('flex flex-col items-center px-6 py-14 text-center', className)}>
      <CircleAlert className="mb-3 size-6 text-danger" aria-hidden />
      <h2 className="text-base font-semibold">{title}</h2>
      <p className="mt-1.5 max-w-md text-[13px] leading-relaxed text-muted-foreground">{errorMessage(error)}</p>
      {detail !== null ? <p className="mt-1 max-w-md text-xs break-words text-muted-foreground">{detail}</p> : null}
      {onRetry !== undefined ? (
        <Button variant="outline" size="sm" className="mt-4" onClick={onRetry}>
          {t.common.retry}
        </Button>
      ) : null}
    </div>
  )
}

/** 表格第一次加载时的骨架行，形状和将要出现的行一致（窄的地方一行排成一块时只留前两格）。 */
export function SkeletonRows({ rows = 4, columns }: { rows?: number; columns: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, row) => (
        <tr key={row} className="border-b last:border-b-0">
          {Array.from({ length: columns }, (_, column) => (
            <td key={column} data-cell={column === 0 ? 'main' : column === 1 ? 'full' : 'hide'} className="px-3 py-4">
              <Skeleton className={cn('h-3', column === 0 ? 'w-32' : 'w-16')} />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

export function SkeletonBlock({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn('space-y-3.5 py-2', className)} aria-busy="true" aria-label={t.common.loading}>
      {Array.from({ length: lines }, (_, line) => (
        <Skeleton key={line} className={cn('h-3', line % 3 === 0 ? 'w-2/5' : line % 3 === 1 ? 'w-3/5' : 'w-1/3')} />
      ))}
    </div>
  )
}
