import { Tabs as TabsPrimitive } from 'radix-ui'
import { type ComponentProps } from 'react'

import { cn } from '@/lib/utils'

const Tabs = TabsPrimitive.Root

function TabsList({ className, ...props }: ComponentProps<typeof TabsPrimitive.List>) {
  // 放不下时在自己这一行里横向滑动，不出现滚动条。底下那条线是画在里面的阴影：行会裁掉伸到外面的东西，
  // 选中那一项的粗线就压在它上面。
  return (
    <TabsPrimitive.List
      className={cn(
        'flex [scrollbar-width:none] items-center gap-6 overflow-x-auto overflow-y-hidden shadow-[inset_0_-1px_0_var(--border)] [&::-webkit-scrollbar]:hidden',
        className,
      )}
      {...props}
    />
  )
}

function TabsTrigger({ className, ...props }: ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 border-b-2 border-transparent pt-1 pb-3 text-sm font-medium whitespace-nowrap text-muted-foreground transition-colors hover:text-foreground data-[state=active]:border-foreground data-[state=active]:text-foreground',
        className,
      )}
      {...props}
    />
  )
}

function TabsContent({ className, ...props }: ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cn('pt-5 outline-none md:pt-8', className)} {...props} />
}

export { Tabs, TabsContent, TabsList, TabsTrigger }
