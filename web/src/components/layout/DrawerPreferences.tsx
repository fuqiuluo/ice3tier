import { Monitor, Moon, Sun } from 'lucide-react'

import { Segmented } from '@/components/ui/segmented'
import { LOCALES, setLocale, t, useLocale } from '@/i18n'
import { setTheme, type Theme, THEMES, useTheme } from '@/lib/theme'

const THEME_ICONS = { system: Monitor, light: Sun, dark: Moon } satisfies Record<Theme, unknown>

/**
 * 抽屉底下的两行：外观和语言。窄屏的顶栏只放得下菜单按钮和当前网络，这两样就放在这里；
 * 都是分段切换，点一下就换，不用再开一层菜单。
 */
export function DrawerPreferences() {
  const theme = useTheme()
  const locale = useLocale()
  return (
    <div className="space-y-2 border-t border-border-strong/60 px-2.5 pt-3">
      <div className="flex min-h-9 items-center justify-between gap-3">
        <span className="text-[13px] text-muted-foreground">{t.common.appearance}</span>
        <Segmented
          aria-label={t.common.appearance}
          value={theme}
          onChange={setTheme}
          className="bg-foreground/[0.06]"
          options={THEMES.map((value) => {
            const Icon = THEME_ICONS[value]
            return {
              value,
              label: (
                <>
                  <Icon className="size-4" aria-hidden />
                  <span className="sr-only">{t.common.themes[value]}</span>
                </>
              ),
            }
          })}
        />
      </div>
      <div className="flex min-h-9 items-center justify-between gap-3">
        <span className="text-[13px] text-muted-foreground">{t.common.language}</span>
        <Segmented
          aria-label={t.common.language}
          value={locale}
          onChange={setLocale}
          className="bg-foreground/[0.06]"
          options={LOCALES.map((entry) => ({
            value: entry.code,
            label: <span lang={entry.code}>{entry.name}</span>,
          }))}
        />
      </div>
    </div>
  )
}
