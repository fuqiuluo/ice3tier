import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import { type ComponentProps, type ReactNode } from 'react'

import { t } from '@/i18n'
import { cn } from '@/lib/utils'

/**
 * 全站一种表格：第一列是名字，操作在最后一列的菜单里，数字右对齐。
 * 不放在框里：表头是一行灰色的小字，行与行之间一条很淡的线。表格向两边各伸出 12 像素，
 * 这样单元格里的字和页面标题左对齐，悬停时的底色又不贴着字。
 *
 * 放不下时在自己这一块里横向滚动。`stack` 的表格在窄的地方（不到 672 像素）换一种排法：一行排成一块，
 * 名字和行末的菜单在第一行，其余的格子一格一行、左边写着表头（每一格用 `Td` 的 `cell` 说自己怎么排）。
 * 排法写在 `index.css` 里，内容还是同一份。
 */
export function Table({ className, stack = false, ...props }: ComponentProps<'table'> & { stack?: boolean }) {
  return (
    // relative：读屏用的 sr-only 文字是绝对定位的，不在这里面定位的话会跑到滚动区域外面，把整页撑宽。
    <div className="@container/table relative -mx-3 overflow-x-auto">
      <table
        data-stack={stack ? '' : undefined}
        className={cn('w-full border-collapse text-sm', className)}
        {...props}
      />
    </div>
  )
}

/**
 * `stack` 的表格在窄的地方，这一格怎么排：
 * - `main`：第一行，占满剩下的宽度（名字）
 * - `end`：第一行的右端（开关、菜单）
 * - `row`：自己占一行，左边写着 `label`（它的表头）
 * - `inline`：和旁边的 `inline` 并排在一行里，不写表头
 * - `full`：自己占一行，不写表头
 * - `hide`：不显示
 */
export type StackCell = 'main' | 'end' | 'row' | 'inline' | 'full' | 'hide'

export function Th({ className, numeric = false, ...props }: ComponentProps<'th'> & { numeric?: boolean }) {
  return (
    <th
      scope="col"
      className={cn(
        'h-9 border-b px-3 text-xs font-medium whitespace-nowrap text-muted-foreground',
        numeric ? 'text-right' : 'text-left',
        className,
      )}
      {...props}
    />
  )
}

export type SortDirection = 'asc' | 'desc'

interface SortThProps {
  children: ReactNode
  active: boolean
  direction: SortDirection
  onSort: () => void
  className?: string
}

/** 可以点的表头：点一下按这一列排，再点一下反过来。没排的列，箭头只在悬停或聚焦时出现。 */
export function SortTh({ children, active, direction, onSort, className }: SortThProps) {
  const Icon = !active ? ArrowUpDown : direction === 'asc' ? ArrowUp : ArrowDown
  return (
    <Th aria-sort={active ? (direction === 'asc' ? 'ascending' : 'descending') : 'none'} className={className}>
      <button
        type="button"
        onClick={onSort}
        className={cn(
          'group/sort -mx-1 inline-flex items-center gap-1 rounded-sm px-1 hover:text-foreground',
          active && 'text-foreground',
        )}
        title={t.common.sortBy}
      >
        {children}
        <Icon
          className={cn(
            'size-3',
            !active && 'opacity-0 group-hover/sort:opacity-60 group-focus-visible/sort:opacity-60',
          )}
          aria-hidden
        />
      </button>
    </Th>
  )
}

export function Tr({ className, dimmed = false, ...props }: ComponentProps<'tr'> & { dimmed?: boolean }) {
  return (
    <tr
      className={cn('border-b last:border-b-0', dimmed && '[&>td:not([data-keep])]:opacity-55', className)}
      {...props}
    />
  )
}

interface TdProps extends ComponentProps<'td'> {
  numeric?: boolean
  /** 窄的地方怎么排，见 {@link StackCell}。 */
  cell?: StackCell
  /** `cell="row"` 时写在左边的名字：这一列的表头。 */
  label?: string
}

export function Td({ className, numeric = false, cell, label, ...props }: TdProps) {
  return (
    <td
      data-cell={cell}
      data-label={label}
      className={cn('px-3 py-3 align-middle', numeric && 'text-right tabular', className)}
      {...props}
    />
  )
}

/** 表格下面的一行：共几项、翻页。表格最后一行不画底线，那条线由它来画。 */
export function TableFooter({ className, ...props }: ComponentProps<'footer'>) {
  return (
    <footer
      className={cn(
        '-mx-3 flex items-center justify-between border-t px-3 pt-3 text-[13px] text-muted-foreground',
        className,
      )}
      {...props}
    />
  )
}

/** 表格上面的一行：搜索、筛选、切换。不放在框里，和表格之间留 16 像素。 */
export function Toolbar({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cn('mb-4 flex flex-wrap items-center gap-2', className)} {...props} />
}

/** 表格下面常驻的一句说明（数据从哪来、多久更新一次）。和表格之间一条细线，灰色小字。 */
export function TableNote({ className, ...props }: ComponentProps<'p'>) {
  return <p className={cn('-mx-3 border-t px-3 pt-3 text-[13px] text-muted-foreground', className)} {...props} />
}

/**
 * 表格里能点的一格（节点的分组、分组的成员）：看着是格子里的内容，悬停时浅灰底，点开改它。
 */
export function CellButton({ className, ...props }: ComponentProps<'button'>) {
  return (
    <button
      type="button"
      className={cn('-mx-1.5 rounded-md px-1.5 py-1 text-left hover:bg-muted', className)}
      {...props}
    />
  )
}

/** 表格下面的"共 N 项"；筛过时写成"共 N 项 / 全部"。 */
export function RowsTotal({ shown, total }: { shown: number; total?: number }) {
  return (
    <span className="tabular">
      {t.common.rowsTotal(shown)}
      {total !== undefined && total !== shown ? ` / ${total}` : ''}
    </span>
  )
}
