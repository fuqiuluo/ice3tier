import { X } from 'lucide-react'
import { Dialog as DialogPrimitive } from 'radix-ui'
import { type ComponentProps, type ReactNode } from 'react'

import { t } from '@/i18n'
import { cn } from '@/lib/utils'

const Dialog = DialogPrimitive.Root
const DialogTrigger = DialogPrimitive.Trigger
const DialogClose = DialogPrimitive.Close

interface DialogContentProps extends Omit<ComponentProps<typeof DialogPrimitive.Content>, 'title'> {
  title: ReactNode
  description?: ReactNode
  /** 宽度（宽屏上；窄屏上对话框都是贴着底边、和屏幕一样宽的一块）。表单用默认的；左右两栏的对话框用 `lg`。 */
  size?: 'sm' | 'md' | 'lg'
  /**
   * 能不能用 Esc 和右上角的叉关掉。显示一次性密钥的对话框是 false：只能点里面的按钮。
   * 点对话框外面在任何情况下都不关闭，免得误触丢掉填了一半的表单。
   */
  dismissible?: boolean
}

const SIZES = { sm: 'md:max-w-md', md: 'md:max-w-xl', lg: 'md:max-w-4xl' } as const

function DialogContent({
  title,
  description,
  size = 'md',
  dismissible = true,
  className,
  children,
  ...props
}: DialogContentProps) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-foreground/30 data-[state=closed]:animate-fade-out data-[state=open]:animate-fade" />
      <DialogPrimitive.Content
        onPointerDownOutside={(event) => event.preventDefault()}
        onInteractOutside={(event) => event.preventDefault()}
        onEscapeKeyDown={dismissible ? undefined : (event) => event.preventDefault()}
        aria-describedby={description === undefined ? undefined : props['aria-describedby']}
        className={cn(
          'fixed z-50 flex flex-col bg-card shadow-pop outline-none',
          // 窄屏：贴着底边、和屏幕一样宽的一块，从下面升起来，顶上留一截看得见后面的页面。
          'inset-x-0 bottom-0 max-h-[calc(100dvh-2.5rem)] rounded-t-2xl pb-[env(safe-area-inset-bottom)] data-[state=closed]:animate-sheet-out data-[state=open]:animate-sheet-in',
          // 宽屏：居中的一块。
          'md:inset-x-auto md:top-1/2 md:bottom-auto md:left-1/2 md:max-h-[calc(100vh-3rem)] md:w-[calc(100vw-3rem)] md:-translate-x-1/2 md:-translate-y-1/2 md:rounded-xl md:pb-0 md:data-[state=closed]:animate-fade-out md:data-[state=open]:animate-fade',
          SIZES[size],
          className,
        )}
        {...props}
      >
        <header className="flex items-start justify-between gap-4 px-4 pt-4 pb-2 md:px-6 md:pt-5">
          <div className="min-w-0">
            <DialogPrimitive.Title className="text-base font-semibold">{title}</DialogPrimitive.Title>
            {description !== undefined ? (
              <DialogPrimitive.Description className="mt-1 text-[13px] text-muted-foreground">
                {description}
              </DialogPrimitive.Description>
            ) : null}
          </div>
          {dismissible ? (
            <DialogPrimitive.Close
              aria-label={t.common.close}
              className="-mt-1 -mr-2 flex size-9 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground md:size-8"
            >
              <X className="size-4" aria-hidden />
            </DialogPrimitive.Close>
          ) : null}
        </header>
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

function DialogBody({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div className={cn('flex-1 overflow-y-auto overscroll-contain px-4 pt-3 pb-5 md:px-6', className)} {...props} />
  )
}

function DialogFooter({ className, ...props }: ComponentProps<'footer'>) {
  // 页脚上面一条很淡的细线：正文长到要滚动时，按钮仍然看得出不属于正文。页脚不另加底色。
  return (
    <footer
      className={cn('flex flex-wrap items-center justify-end gap-2 border-t px-4 py-3 md:px-6 md:py-4', className)}
      {...props}
    />
  )
}

export { Dialog, DialogBody, DialogClose, DialogContent, DialogFooter, DialogTrigger }
