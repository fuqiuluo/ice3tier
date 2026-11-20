import { useQuery } from '@tanstack/react-query'
import { Languages, Menu, Monitor, Moon, Sun } from 'lucide-react'

import { q } from '@/api/queries'
import { type Network } from '@/api/types'
import { LanguageItems } from '@/components/language'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { LOCALES, t, useLocale } from '@/i18n'
import { setTheme, type Theme, THEMES, useResolvedTheme, useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'

import { NetworkSwitcher } from './NetworkSwitcher'
import { VersionBadge } from './VersionFooter'

/** 顶栏上只有图标的按钮：32 像素见方（窄屏上 36，手指点得准），平时灰，悬停和打开时有一块淡淡的底。 */
const ICON_BUTTON =
  'flex size-9 shrink-0 items-center justify-center md:size-8 rounded-lg text-muted-foreground transition-colors outline-none hover:bg-foreground/[0.05] hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring data-[state=open]:bg-foreground/[0.06] data-[state=open]:text-foreground [&_svg]:size-[17px]'

const THEME_ICONS = { system: Monitor, light: Sun, dark: Moon } satisfies Record<Theme, unknown>

const isTheme = (value: string): value is Theme => THEMES.some((theme) => theme === value)

function ThemeMenu() {
  const theme = useTheme()
  const resolved = useResolvedTheme()
  const Icon = resolved === 'dark' ? Moon : Sun
  return (
    <DropdownMenu>
      <DropdownMenuTrigger aria-label={`${t.common.appearance}: ${t.common.themes[theme]}`} className={ICON_BUTTON}>
        <Icon strokeWidth={1.75} aria-hidden />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" sideOffset={6} className="w-40">
        <DropdownMenuRadioGroup
          value={theme}
          onValueChange={(value) => {
            if (isTheme(value)) setTheme(value)
          }}
        >
          {THEMES.map((value) => {
            const ItemIcon = THEME_ICONS[value]
            return (
              <DropdownMenuRadioItem key={value} value={value}>
                <span className="flex items-center gap-2.5">
                  <ItemIcon className="size-4 text-faint" aria-hidden />
                  {t.common.themes[value]}
                </span>
              </DropdownMenuRadioItem>
            )
          })}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function LanguageIconMenu() {
  const locale = useLocale()
  const name = LOCALES.find((entry) => entry.code === locale)?.name ?? locale
  return (
    <DropdownMenu>
      <DropdownMenuTrigger aria-label={`${t.common.language}: ${name}`} className={ICON_BUTTON}>
        <Languages strokeWidth={1.75} aria-hidden />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" sideOffset={6} className="w-40">
        <LanguageItems />
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

interface TopBarProps {
  networks: readonly Network[]
  current: Network
  onSignOut: () => void
  /** 窄屏上最左边的菜单按钮：打开导航的抽屉。 */
  onOpenNav: () => void
}

/**
 * 顶栏：侧栏右边、正文面板上面，60 像素高，左右留 24 像素；和侧栏一样坐在浅灰的底上，没有自己的底色和边线。
 * 左边总是写着「控制台」（18 像素）和界面的版本号，页面自己的标题在正文里；右上角是外观、语言和当前网络（菜单里也有设置和退出登录）。
 * 窄屏上矮一些（52 像素），最左边多一个打开导航的按钮，外观和语言挪到抽屉里，右边只留当前网络。
 */
export function TopBar({ networks, current, onSignOut, onOpenNav }: TopBarProps) {
  const status = useQuery(q.status())

  return (
    <header className="flex h-[52px] shrink-0 items-center gap-1.5 px-2 md:h-[60px] md:gap-6 md:px-6">
      <button type="button" onClick={onOpenNav} aria-label={t.nav.openMenu} className={cn(ICON_BUTTON, 'md:hidden')}>
        <Menu strokeWidth={1.75} aria-hidden />
      </button>
      <div className="flex min-w-0 flex-1 items-center gap-2">
        <span className="truncate text-[17px] leading-[26px] font-semibold tracking-tight md:text-lg">
          {t.nav.console}
        </span>
        <VersionBadge status={status.data} />
      </div>

      <div className="flex min-w-0 shrink-0 items-center gap-2">
        <div className="hidden items-center gap-2 md:flex">
          <ThemeMenu />
          <LanguageIconMenu />
          <span aria-hidden className="h-4 w-px bg-border-strong" />
        </div>
        <NetworkSwitcher networks={networks} current={current} onSignOut={onSignOut} />
      </div>
    </header>
  )
}
