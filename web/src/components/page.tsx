import { type ReactNode } from 'react'

import { cn } from '@/lib/utils'

interface PageHeaderProps {
  title: ReactNode
  /** 标题下面的一句话（副标题）：这个页面是做什么的。 */
  description?: ReactNode
  /** 右端：这个页面的主按钮。 */
  actions?: ReactNode
  className?: string
}

/**
 * 页面的标题区，在正文面板的最上面：左边是 22 像素的粗体标题，下面一行 14 像素的灰色副标题；
 * 右端是这个页面的按钮——最多一个主按钮加一两个次要按钮，和标题那一块上下居中。总览没有标题区。
 */
export function PageHeader({ title, description, actions, className }: PageHeaderProps) {
  return (
    <header
      data-page-header
      className={cn(
        'flex shrink-0 flex-wrap items-center justify-between gap-x-6 gap-y-3 pt-5 pb-4 md:pt-7 md:pb-6',
        className,
      )}
    >
      <div className="min-w-0">
        <h1 className="flex items-center gap-2.5 text-xl leading-7 font-bold tracking-tight text-balance md:text-[22px] md:leading-[30px]">
          {title}
        </h1>
        {description !== undefined ? (
          <p className="mt-1 max-w-3xl text-sm text-pretty text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions !== undefined ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </header>
  )
}

/**
 * 页面的内容区：铺满面板，左右留 32 像素（窄屏上 16），不限制宽度；至少和面板一样高。
 * 它是一个容器（`@container`）：里面的版面按它的宽度变（`@2xl:` 这类），而不是按窗口的宽度，侧栏收起、展开都对。
 *
 * `fill` 的页面是一个竖着排的弹性盒子：里面要占满剩下高度的那一块（画图的画布）写 `flex-1`，
 * 而不是给它一个写死的高度。
 */
export function Page({
  children,
  fill = false,
  className,
}: {
  children: ReactNode
  fill?: boolean
  className?: string
}) {
  return (
    // 没有标题区的页面（节点详情）自己从面板顶上留出一段。
    <div
      className={cn(
        '@container min-h-full w-full px-4 pb-6 md:px-8 md:pb-8 [&>:not([data-page-header]):first-child]:mt-5 md:[&>:not([data-page-header]):first-child]:mt-7',
        fill && 'flex flex-col',
        className,
      )}
    >
      {children}
    </div>
  )
}

/**
 * 画布：占满它所在的弹性盒子里剩下的地方，里面的东西铺满它。给关系图这类"自己没有高度、要别人给"的内容用。
 * 只有一个下限，窗口再矮也画得下；没有写死的高度。
 */
export function Canvas({ children, className, ...rest }: React.ComponentProps<'div'>) {
  return (
    <div className={cn('relative min-h-96 flex-1 rounded-lg bg-sidebar', className)} {...rest}>
      <div className="absolute inset-0">{children}</div>
    </div>
  )
}

/** 只读信息里的一行：左边是名字（灰），右边是值。几行放在一个 `<dl>` 里，行与行之间不画线。 */
export function InfoRow({ label, children, className }: { label: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cn('grid grid-cols-[8.5rem_minmax(0,1fr)] items-baseline gap-4 py-1.5', className)}>
      <dt className="text-[13px] text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  )
}
