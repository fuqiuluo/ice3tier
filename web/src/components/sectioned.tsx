import { type ReactNode, useEffect, useRef } from 'react'
import { NavLink, useLocation } from 'react-router'

import { cn } from '@/lib/utils'

export interface SectionLink {
  /** 这个分区的地址。 */
  to: string
  label: string
  /** 名字右边的记号：一个提醒的点、改过几项之类。 */
  mark?: ReactNode
}

interface SectionedProps {
  /** 这一列分区名是什么的导航（读屏用）。 */
  label: string
  sections: readonly SectionLink[]
  /** 选中的那个分区的内容。 */
  children: ReactNode
}

/**
 * 一页的内容分成几个分区时的排法：左侧竖排的分区名，右边是选中的那个分区；每个分区有自己的地址。
 * 窄的时候分区名排成上面的一行（放不下就横向滑动，选中的那个自己滑进看得见的那一段），内容占满宽度。
 * 分区再多也只是左边多一行，所以设置会越加越多的页面用它（全局的设置、网络的设置）。
 */
export function Sectioned({ label, sections, children }: SectionedProps) {
  const list = useRef<HTMLUListElement>(null)
  const { pathname } = useLocation()
  useEffect(() => {
    // 只在它不在看得见的那一段里时才动；竖排的时候本来就都看得见。
    list.current?.querySelector('[aria-current="page"]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
  }, [pathname])
  return (
    <div className="grid grid-cols-1 items-start gap-5 @2xl:grid-cols-[10rem_minmax(0,1fr)] @2xl:gap-12">
      <nav aria-label={label} className="min-w-0">
        <ul
          ref={list}
          className="-mx-4 flex [scrollbar-width:none] gap-1 overflow-x-auto px-4 @2xl:mx-0 @2xl:block @2xl:space-y-0.5 @2xl:px-0 [&::-webkit-scrollbar]:hidden"
        >
          {sections.map((section) => (
            <li key={section.to} className="shrink-0">
              <NavLink
                to={section.to}
                className={({ isActive }) =>
                  cn(
                    'flex h-8 items-center justify-between gap-2 rounded-md px-2.5 text-sm whitespace-nowrap transition-colors',
                    isActive
                      ? 'bg-foreground/[0.06] font-medium text-foreground'
                      : 'text-foreground/80 hover:bg-foreground/[0.04] hover:text-foreground',
                  )
                }
              >
                {section.label}
                {section.mark}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="min-w-0">{children}</div>
    </div>
  )
}
