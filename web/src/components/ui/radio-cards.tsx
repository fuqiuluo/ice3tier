import { RadioGroup } from 'radix-ui'
import { type ReactNode } from 'react'

import { cn } from '@/lib/utils'

interface RadioCardOption<V extends string> {
  value: V
  title: ReactNode
  /** 一句话，说选了它会怎样。 */
  description?: ReactNode
  disabled?: boolean
  /** 不能选的原因，写在卡片里。 */
  disabledReason?: ReactNode
}

interface RadioCardsProps<V extends string> {
  value: V
  onChange: (value: V) => void
  options: readonly RadioCardOption<V>[]
  'aria-label'?: string
  'aria-labelledby'?: string
  columns?: 1 | 2 | 3
  className?: string
}

/** 并排的几列只在放得下时并排：按这组选项自己那一块的宽度算，窄了就一列。 */
const COLUMNS = { 1: 'grid-cols-1', 2: 'grid-cols-1 @sm:grid-cols-2', 3: 'grid-cols-1 @lg:grid-cols-3' } as const

/**
 * 单选的一组选项，每个选项带一句说明后果的话。不画框：一个圆圈、标题、灰色的说明；
 * 选中的那个圆圈是实心的强调色，标题加深。悬停时整行有一层很淡的底色，整行都能点。
 */
function RadioCards<V extends string>({
  value,
  onChange,
  options,
  columns = 1,
  className,
  ...aria
}: RadioCardsProps<V>) {
  return (
    <div className="@container">
      <RadioGroup.Root
        value={value}
        onValueChange={(next) => onChange(next as V)}
        className={cn('-mx-2.5 grid gap-x-4 gap-y-0.5', COLUMNS[columns], className)}
        {...aria}
      >
        {options.map((option) => (
          <RadioGroup.Item
            key={option.value}
            value={option.value}
            disabled={option.disabled}
            className="group flex items-start gap-2.5 rounded-md px-2.5 py-2 text-left transition-colors hover:bg-muted data-disabled:opacity-60 data-disabled:hover:bg-transparent"
          >
            <span
              aria-hidden
              className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border border-faint bg-card group-data-[state=checked]:border-primary group-data-[state=checked]:bg-primary"
            >
              <span className="size-1.5 rounded-full bg-white opacity-0 group-data-[state=checked]:opacity-100" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-medium">{option.title}</span>
              {option.description !== undefined ? (
                <span className="mt-0.5 block text-[13px] leading-snug text-muted-foreground">
                  {option.description}
                </span>
              ) : null}
              {option.disabled === true && option.disabledReason !== undefined ? (
                <span className="mt-1 block text-[13px] leading-snug text-warn">{option.disabledReason}</span>
              ) : null}
            </span>
          </RadioGroup.Item>
        ))}
      </RadioGroup.Root>
    </div>
  )
}

export { RadioCards, type RadioCardOption }
