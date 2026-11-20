import { Popover as PopoverPrimitive } from 'radix-ui'
import { type ComponentProps } from 'react'

import { cn } from '@/lib/utils'

/** 弹出和收起的动画，和菜单一样（见 `dropdown-menu.tsx`）。 */
const POP =
  'origin-(--radix-popover-content-transform-origin) data-[state=open]:animate-pop-in data-[state=closed]:animate-pop-out data-[side=bottom]:[--pop-y:-6px] data-[side=left]:[--pop-x:6px] data-[side=right]:[--pop-x:-6px] data-[side=top]:[--pop-y:6px]'

const Popover = PopoverPrimitive.Root
const PopoverTrigger = PopoverPrimitive.Trigger
const PopoverAnchor = PopoverPrimitive.Anchor
const PopoverClose = PopoverPrimitive.Close

function PopoverContent({
  className,
  align = 'start',
  sideOffset = 6,
  ...props
}: ComponentProps<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        collisionPadding={8}
        className={cn(
          'z-50 max-w-[calc(100vw-1rem)] rounded-lg bg-popover text-popover-foreground shadow-pop outline-none',
          POP,
          className,
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  )
}

export { Popover, PopoverAnchor, PopoverClose, PopoverContent, PopoverTrigger }
