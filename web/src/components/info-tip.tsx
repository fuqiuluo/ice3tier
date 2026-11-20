import { Info } from 'lucide-react'
import { type ReactNode } from 'react'

import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { cn } from '@/lib/utils'

/**
 * 放在名字旁边的一个小图标，悬停或键盘聚焦时显示一段较长的说明（触屏上点一下）。页面上常驻的字只留必要的，
 * 值得留下的解释放在这里。
 */
export function InfoTip({ children, label, className }: { children: ReactNode; label?: string; className?: string }) {
  return (
    <Tooltip content={children} tap>
      <button
        type="button"
        aria-label={label ?? t.common.details}
        className={cn(
          'inline-flex size-4 shrink-0 items-center justify-center rounded-full align-[-3px] text-faint hover:text-muted-foreground',
          className,
        )}
      >
        <Info className="size-3.5" aria-hidden />
      </button>
    </Tooltip>
  )
}
