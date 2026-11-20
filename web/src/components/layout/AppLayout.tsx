import { useQuery } from '@tanstack/react-query'
import { WifiOff } from 'lucide-react'
import { useState } from 'react'
import { Navigate, Outlet, useNavigate, useParams } from 'react-router'

import { useReachable } from '@/api/connection'
import { q } from '@/api/queries'
import { session } from '@/auth/session'
import { ErrorState, SkeletonBlock } from '@/components/states'
import { t } from '@/i18n'
import { isBoolean, readStored, writeStored } from '@/lib/storage'
import { NARROW_SCREEN, useMediaQuery } from '@/lib/useMediaQuery'
import { pickCurrentNetwork } from '@/pages/networks/current'

import { DrawerPreferences } from './DrawerPreferences'
import { MobileNav, Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

const SIDEBAR_COLLAPSED_KEY = 'sidebarCollapsed'

/**
 * 登录之后的外壳：一层浅灰的底。左边一列是侧栏（标志、收起按钮、导航），整个窗口那么高；
 * 右边上面是顶栏（「控制台」、版本号、外观、语言、网络），下面是一块白色的大圆角面板，正文在面板里滚动，页面的标题和副标题在正文的最上面。
 *
 * 侧栏里的链接都属于"当前网络"：地址里有网络编号就是它；在全局的页面上（设置）用上次看的那个。
 *
 * 窄屏（手机）上没有侧栏：导航在一个从左边滑出来的抽屉里，顶栏最左边的按钮打开它；面板铺满整个宽度，只留上面两个圆角。
 */
export function AppLayout() {
  const params = useParams()
  const navigate = useNavigate()
  const networks = useQuery(q.networks())
  const reachable = useReachable()
  const [collapsed, setCollapsed] = useState(() => readStored(SIDEBAR_COLLAPSED_KEY, false, isBoolean))
  const narrow = useMediaQuery(NARROW_SCREEN)
  const [navOpen, setNavOpen] = useState(false)

  if (networks.isPending) {
    return (
      <div className="mx-auto max-w-3xl pt-24">
        <SkeletonBlock lines={6} />
      </div>
    )
  }
  if (networks.isError) {
    return (
      <div className="mx-auto max-w-3xl pt-24">
        <ErrorState title={t.errors.loadFailed} error={networks.error} onRetry={() => void networks.refetch()} />
      </div>
    )
  }
  const current = pickCurrentNetwork(networks.data, params.network === undefined ? undefined : Number(params.network))
  // 一个网络都没有：先去建第一个。
  if (current === undefined) return <Navigate to="/welcome" replace />

  const toggleSidebar = () => {
    setCollapsed((value) => {
      writeStored(SIDEBAR_COLLAPSED_KEY, !value)
      return !value
    })
  }

  const signOut = () => {
    session.signOut('manual')
    void navigate('/login', { replace: true })
  }

  return (
    // 整个外壳只有这一处用视口的高度：框住一屏，里面全部靠弹性盒子分。
    <div className="flex h-dvh bg-canvas">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[80] focus:rounded-md focus:bg-card focus:px-3 focus:py-2 focus:shadow-pop"
      >
        {t.nav.skipToContent}
      </a>
      <Sidebar current={current} collapsed={collapsed} onToggle={toggleSidebar} />
      {/* 窗口变宽之后抽屉自己关上：它只属于窄屏。 */}
      <MobileNav current={current} open={navOpen && narrow} onOpenChange={setNavOpen} footer={<DrawerPreferences />} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar networks={networks.data} current={current} onSignOut={signOut} onOpenNav={() => setNavOpen(true)} />
        <div className="flex min-h-0 flex-1 flex-col md:pr-2 md:pb-2">
          {/* 面板自己不滚动，圆角一直看得见；滚动的是里面的 main。 */}
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-t-[18px] bg-card shadow-panel md:rounded-[20px]">
            {reachable ? null : (
              <div
                role="alert"
                className="flex shrink-0 items-center gap-2 bg-warn-soft px-4 py-2 text-[13px] font-medium text-warn md:px-8"
              >
                <WifiOff className="size-4 shrink-0" aria-hidden />
                {t.errors.connectionLost}
              </div>
            )}
            <main id="main" tabIndex={-1} className="min-h-0 min-w-0 flex-1 overflow-y-auto outline-none">
              <Outlet />
            </main>
          </div>
        </div>
      </div>
    </div>
  )
}
