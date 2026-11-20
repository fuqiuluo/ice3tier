import { Check, ChevronRight } from 'lucide-react'
import { DropdownMenu as MenuPrimitive } from 'radix-ui'
import { type ComponentProps } from 'react'

import { cn } from '@/lib/utils'

/**
 * 弹出和收起的动画（`index.css` 的 pop-in、pop-out）：从触发它的那个按钮的方向长出来、缩回去。
 * 原点用 Radix 算好的那个点；朝外挪的方向跟着实际弹出的那一侧。
 */
const POP =
  'origin-(--radix-dropdown-menu-content-transform-origin) data-[state=open]:animate-pop-in data-[state=closed]:animate-pop-out data-[side=bottom]:[--pop-y:-6px] data-[side=left]:[--pop-x:6px] data-[side=right]:[--pop-x:-6px] data-[side=top]:[--pop-y:6px]'

const DropdownMenu = MenuPrimitive.Root
const DropdownMenuTrigger = MenuPrimitive.Trigger

function DropdownMenuContent({
  className,
  align = 'end',
  sideOffset = 4,
  ...props
}: ComponentProps<typeof MenuPrimitive.Content>) {
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        collisionPadding={8}
        className={cn(
          'z-50 max-w-[calc(100vw-1rem)] min-w-40 rounded-xl bg-popover p-1 text-popover-foreground shadow-pop',
          POP,
          className,
        )}
        {...props}
      />
    </MenuPrimitive.Portal>
  )
}

interface ItemProps extends ComponentProps<typeof MenuPrimitive.Item> {
  /** 破坏性的操作：红色，放在菜单最后、分隔线之后。 */
  danger?: boolean
}

function DropdownMenuItem({ className, danger = false, ...props }: ItemProps) {
  return (
    <MenuPrimitive.Item
      className={cn(
        'flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm leading-5 outline-none select-none data-disabled:cursor-not-allowed data-disabled:opacity-50 data-highlighted:bg-muted [&_svg]:size-4 [&_svg]:shrink-0',
        danger ? 'text-danger data-highlighted:bg-danger-soft' : '[&_svg]:text-faint',
        className,
      )}
      {...props}
    />
  )
}

function DropdownMenuSeparator({ className, ...props }: ComponentProps<typeof MenuPrimitive.Separator>) {
  return <MenuPrimitive.Separator className={cn('-mx-1 my-1 h-px bg-border', className)} {...props} />
}

function DropdownMenuLabel({ className, ...props }: ComponentProps<typeof MenuPrimitive.Label>) {
  return <MenuPrimitive.Label className={cn('px-2 pt-1.5 pb-1 text-xs font-medium text-faint', className)} {...props} />
}

const DropdownMenuRadioGroup = MenuPrimitive.RadioGroup

/** 几个里选一个（例如语言）：选中的那一项右端一个勾。 */
function DropdownMenuRadioItem({ className, children, ...props }: ComponentProps<typeof MenuPrimitive.RadioItem>) {
  return (
    <MenuPrimitive.RadioItem
      className={cn(
        'flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm leading-5 outline-none select-none data-highlighted:bg-muted',
        className,
      )}
      {...props}
    >
      <span className="min-w-0 flex-1">{children}</span>
      <MenuPrimitive.ItemIndicator>
        <Check className="size-4 text-foreground" aria-hidden />
      </MenuPrimitive.ItemIndicator>
    </MenuPrimitive.RadioItem>
  )
}

const DropdownMenuSub = MenuPrimitive.Sub

/** 打开下一级菜单的一项：右端一个向右的箭头。 */
function DropdownMenuSubTrigger({ className, children, ...props }: ComponentProps<typeof MenuPrimitive.SubTrigger>) {
  return (
    <MenuPrimitive.SubTrigger
      className={cn(
        'flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm leading-5 outline-none select-none data-highlighted:bg-muted data-[state=open]:bg-muted [&_svg]:size-4 [&_svg]:shrink-0 [&_svg]:text-faint',
        className,
      )}
      {...props}
    >
      {children}
      <ChevronRight className="ml-auto" aria-hidden />
    </MenuPrimitive.SubTrigger>
  )
}

function DropdownMenuSubContent({ className, ...props }: ComponentProps<typeof MenuPrimitive.SubContent>) {
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.SubContent
        sideOffset={6}
        collisionPadding={8}
        className={cn('z-50 min-w-36 rounded-xl bg-popover p-1 text-popover-foreground shadow-pop', POP, className)}
        {...props}
      />
    </MenuPrimitive.Portal>
  )
}

export {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
}
