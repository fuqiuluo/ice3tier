import { Tooltip as TooltipPrimitive } from 'radix-ui'
import { type MouseEvent, type ReactNode, useRef, useState } from 'react'

import { NO_HOVER, useMediaQuery } from '@/lib/useMediaQuery'

const TooltipProvider = TooltipPrimitive.Provider

interface TooltipProps {
  content: ReactNode
  children: ReactNode
  side?: 'top' | 'right' | 'bottom' | 'left'
  /**
   * 触屏上点一下就弹出，哪怕 `children` 是个按钮：给"这个按钮只是用来看说明"的地方用（ⓘ）。
   * 不是按钮、链接的（一段带说明的字、一个徽标）不用写，触屏上本来就是点一下弹出。
   */
  tap?: boolean
}

const CONTENT =
  'z-50 max-w-80 animate-fade rounded-md bg-tooltip px-2.5 py-1.5 text-xs leading-snug text-tooltip-foreground'

/** 点了是做它自己的事的东西：按钮、链接、表单控件，或者在它们里面。 */
const ACTIONABLE = 'a, button, input, select, textarea, label, [role="button"], [role="switch"], [role="menuitem"]'

/**
 * 悬停或者键盘聚焦时出现的一小段说明。`children` 必须是能获得焦点的元素。
 *
 * 触屏没有悬停：只是说明的那些（ⓘ、带说明的字和徽标）点一下弹出，再点或者点别处收起；
 * 本来就能点的（按钮、链接）点了照常做它自己的事，不弹说明——它们的说明只是名字。
 */
function Tooltip({ content, children, side = 'top', tap = false }: TooltipProps) {
  const touch = useMediaQuery(NO_HOVER)
  const [open, setOpen] = useState(false)
  // 按下去的那一刻开着没有：库在按下时会先把它关上，点完要按那一刻的样子决定是开是关。
  const wasOpen = useRef(false)
  if (content === null || content === undefined || content === '') return <>{children}</>

  const body = (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content side={side} sideOffset={6} collisionPadding={8} className={CONTENT}>
        {content}
      </TooltipPrimitive.Content>
    </TooltipPrimitive.Portal>
  )
  if (!touch) {
    return (
      <TooltipPrimitive.Root>
        <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
        {body}
      </TooltipPrimitive.Root>
    )
  }

  const toggle = (event: MouseEvent<HTMLElement>) => {
    if (!tap && event.currentTarget.closest(ACTIONABLE) !== null) return
    // 不让库把它当成一次普通的点击关掉，也不让外面那一行跟着被点开。
    event.preventDefault()
    event.stopPropagation()
    setOpen(!wasOpen.current)
  }
  return (
    <TooltipPrimitive.Root open={open} onOpenChange={setOpen}>
      <TooltipPrimitive.Trigger
        asChild
        onPointerDown={() => {
          wasOpen.current = open
        }}
        onClick={toggle}
      >
        {children}
      </TooltipPrimitive.Trigger>
      {body}
    </TooltipPrimitive.Root>
  )
}

export { Tooltip, TooltipProvider }
