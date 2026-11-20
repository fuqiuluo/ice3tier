import { Search } from 'lucide-react'
import { useEffect, useRef } from 'react'

import { fieldBase } from '@/components/ui/input'
import { t } from '@/i18n'
import { cn } from '@/lib/utils'

interface SearchBoxProps {
  value: string
  onChange: (value: string) => void
  placeholder: string
  className?: string
}

/** 列表上方的搜索框：左边放大镜，右边 Ctrl K 的提示，在页面任何地方按 Ctrl K（Mac 上 ⌘K）都跳到这里。 */
export function SearchBox({ value, onChange, placeholder, className }: SearchBoxProps) {
  const ref = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        ref.current?.focus()
        ref.current?.select()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className={cn('relative w-full sm:w-72', className)}>
      <Search
        className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-faint"
        aria-hidden
      />
      <input
        ref={ref}
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        aria-keyshortcuts="Control+K"
        autoComplete="off"
        spellCheck={false}
        className={cn(fieldBase, 'h-9 pr-3 pl-8.5 pointer-fine:pr-14 [&::-webkit-search-cancel-button]:hidden')}
      />
      <kbd
        aria-hidden
        className="pointer-events-none absolute top-1/2 right-2 hidden -translate-y-1/2 rounded-sm bg-muted px-1 font-sans text-[11px] text-muted-foreground pointer-fine:block"
      >
        {t.common.searchShortcut}
      </kbd>
    </div>
  )
}
