import { ChevronsUpDown, LogOut, Network as NetworkIcon, Settings, Settings2 } from 'lucide-react'
import { useLocation, useNavigate } from 'react-router'

import { type Network } from '@/api/types'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { t } from '@/i18n'
import { cn } from '@/lib/utils'
import { networkPath } from '@/pages/networks/context'

import { currentPage } from './nav'

/** 网络的头像：名字的第一个字，圆角方块。当前网络是黑底白字，别的网络浅灰底。 */
function NetworkAvatar({ name, muted = false }: { name: string; muted?: boolean }) {
  return (
    <span
      aria-hidden
      className={cn(
        'flex size-[18px] shrink-0 items-center justify-center rounded-[5px] text-[10px] font-semibold uppercase',
        muted ? 'bg-muted text-muted-foreground' : 'bg-foreground text-background',
      )}
    >
      {name.slice(0, 1)}
    </span>
  )
}

const SEPARATOR = 'mx-1 my-1'

interface NetworkSwitcherProps {
  networks: readonly Network[]
  current: Network
  onSignOut: () => void
}

/**
 * 顶栏右上角的网络：和旁边的图标按钮一样没有底和边，一个网络的图标、当前网络的名字和上下箭头。点开的菜单顶上写着当前网络（地址段、节点数），
 * 有别的网络时列出来，点了切过去——停留在同一类页面上：在节点页切换，到的是另一个网络的节点页；然后是网络设置。
 * 最后隔一条线是设置和退出登录：管理界面只有一个管理员，没有名字和头像，不另放一个账号按钮。新建网络只在网络页上。
 */
export function NetworkSwitcher({ networks, current, onSignOut }: NetworkSwitcherProps) {
  const navigate = useNavigate()
  const location = useLocation()
  const page = currentPage(location.pathname) ?? 'overview'
  const others = networks.filter((network) => network.id !== current.id)

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label={`${t.switcher.label}（${t.switcher.current}：${current.name}）`}
        className="flex h-9 max-w-40 items-center gap-1.5 rounded-lg px-2 text-sm md:h-8 md:max-w-48 font-medium text-foreground/85 transition-colors outline-none hover:bg-foreground/[0.05] hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring data-[state=open]:bg-foreground/[0.06] data-[state=open]:text-foreground"
      >
        <NetworkIcon className="size-4 shrink-0 text-muted-foreground" strokeWidth={1.75} aria-hidden />
        <span className="min-w-0 truncate">{current.name}</span>
        <ChevronsUpDown className="size-3.5 shrink-0 text-faint" aria-hidden />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" sideOffset={6} className="w-60">
        <div className="px-2 pt-1.5 pb-2">
          <p className="truncate text-sm leading-5 font-semibold">{current.name}</p>
          <p className="truncate text-xs leading-4 text-muted-foreground tabular">
            {current.cidr} · {t.switcher.nodes(current.nodes)}
          </p>
        </div>

        {others.length > 0 ? (
          <>
            <DropdownMenuSeparator className={SEPARATOR} />
            <DropdownMenuLabel>{t.switcher.label}</DropdownMenuLabel>
            {others.map((network) => (
              <DropdownMenuItem key={network.id} onSelect={() => void navigate(networkPath(network.id, page))}>
                <NetworkAvatar name={network.name} muted />
                <span className="min-w-0 flex-1 truncate">{network.name}</span>
                <span className="text-xs text-muted-foreground tabular">{network.cidr}</span>
              </DropdownMenuItem>
            ))}
          </>
        ) : null}

        <DropdownMenuSeparator className={SEPARATOR} />
        <DropdownMenuItem
          className="[&_svg]:text-foreground/70"
          onSelect={() => void navigate(networkPath(current.id, 'network'))}
        >
          <Settings2 aria-hidden />
          {t.switcher.manage}
        </DropdownMenuItem>

        <DropdownMenuSeparator className={SEPARATOR} />
        <DropdownMenuItem className="[&_svg]:text-foreground/70" onSelect={() => void navigate('/settings')}>
          <Settings aria-hidden />
          {t.nav.settings}
        </DropdownMenuItem>
        <DropdownMenuItem className="[&_svg]:text-foreground/70" onSelect={onSignOut}>
          <LogOut aria-hidden />
          {t.nav.signOut}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
