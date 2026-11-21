import { useQuery } from '@tanstack/react-query'
import { type ComponentType, lazy, Suspense } from 'react'
import { Navigate, Route, Routes, useSearchParams } from 'react-router'

import { q } from '@/api/queries'

import { RequireAuth } from '@/auth/RequireAuth'
import { SignInPage } from '@/auth/SignInPage'
import { AppLayout } from '@/components/layout/AppLayout'
import { Page } from '@/components/page'
import { SkeletonBlock } from '@/components/states'
import { Card } from '@/components/ui/card'
import { ForwardsPage } from '@/pages/forwards/ForwardsPage'
import { GroupsPage } from '@/pages/groups/GroupsPage'
import { networkPath } from '@/pages/networks/context'
import { pickCurrentNetwork } from '@/pages/networks/current'
import { NetworkLayout } from '@/pages/networks/NetworkLayout'
import { NetworkPage } from '@/pages/networks/NetworkPage'
import { WelcomePage } from '@/pages/networks/WelcomePage'
import { NodeDetailPage } from '@/pages/nodes/NodeDetailPage'
import { NodesPage } from '@/pages/nodes/NodesPage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { OverviewPage } from '@/pages/overview/OverviewPage'
import { PairsPage } from '@/pages/pairs/PairsPage'
import { ProxiesPage } from '@/pages/proxies/ProxiesPage'

// 访问控制页和拓扑页带着画图的库，单独成块：别的页面用不到它。
const AccessPage = lazy(() => import('@/pages/access/AccessPage').then((module) => ({ default: module.AccessPage })))
const TopologyPage = lazy(() =>
  import('@/pages/topology/TopologyPage').then((module) => ({ default: module.TopologyPage })),
)
// 不常去的页面也单独成块，第一次打开界面时少下载一些。
const PathPage = lazy(() => import('@/pages/path/PathPage').then((module) => ({ default: module.PathPage })))
const SettingsPage = lazy(() =>
  import('@/pages/settings/SettingsPage').then((module) => ({ default: module.SettingsPage })),
)

/** 单独成块的页面在取回来之前先显示骨架。 */
function Lazy({ page: Component }: { page: ComponentType }) {
  return (
    <Suspense fallback={<PageFallback />}>
      <Component />
    </Suspense>
  )
}

function PageFallback() {
  return (
    <Page>
      <Card>
        <SkeletonBlock lines={6} />
      </Card>
    </Page>
  )
}

/**
 * 全部路由。地址的形状：网络在路径里（`/n/<网络编号>/…`），对象的编号在路径里，
 * 筛选、搜索、选中的一对节点在查询参数里；浏览器的前进后退能还原这些状态。
 *
 */
export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<SignInPage />} />
      <Route element={<RequireAuth />}>
        <Route path="/welcome" element={<WelcomePage />} />
        <Route element={<AppLayout />}>
          {/* 外壳会算出"当前网络"；首页只是把人送到它的总览。 */}
          <Route index element={<HomeRedirect />} />
          <Route path="n/:network" element={<NetworkLayout />}>
            <Route index element={<Navigate to="overview" replace />} />
            <Route path="overview" element={<OverviewPage />} />
            <Route path="nodes" element={<NodesPage />} />
            <Route path="nodes/:node" element={<NodeDetailPage />} />
            <Route path="access" element={<Lazy page={AccessPage} />} />
            <Route path="groups" element={<GroupsPage />} />
            {/* 出口页去掉了：出口是节点的一种身份，在节点详情里看和改；旧链接去节点列表、只看出口。 */}
            <Route path="exits" element={<Navigate to="../nodes?role=exit" replace />} />
            {/* 监听器页去掉了：代理在出口节点详情的「代理出口」里。 */}
            <Route path="listeners" element={<Navigate to="../nodes?role=exit" replace />} />
            <Route path="proxies" element={<ProxiesPage />} />
            {/* 凭据页去掉了：认证是每个代理自己的用户名和密码。 */}
            <Route path="credentials" element={<Navigate to="../proxies" replace />} />
            <Route path="forwards" element={<ForwardsPage />} />
            <Route path="topology" element={<Lazy page={TopologyPage} />} />
            <Route path="diagnosis" element={<Lazy page={PathPage} />} />
            {/* 连通性测试页并进了路径诊断。旧链接带着选的节点和测试过去。 */}
            <Route path="tests" element={<TestsRedirect />} />
            {/* 注册令牌页去掉了：令牌在「添加节点」里生成、吊销。 */}
            <Route path="tokens" element={<Navigate to="../nodes" replace />} />
            <Route path="pairs" element={<PairsPage />} />
            <Route path="network" element={<NetworkPage />} />
            <Route path="network/:section" element={<NetworkPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
          <Route path="settings" element={<Lazy page={SettingsPage} />} />
          <Route path="settings/:tab" element={<Lazy page={SettingsPage} />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  )
}

function HomeRedirect() {
  // 外壳已经取到了网络列表才会渲染到这里，所以缓存里一定有。
  const networks = useQuery(q.networks())
  const current = pickCurrentNetwork(networks.data ?? [])
  return current === undefined ? <Navigate to="/welcome" replace /> : <Navigate to={networkPath(current.id)} replace />
}

function TestsRedirect() {
  const [params] = useSearchParams()
  const kept = new URLSearchParams()
  for (const key of ['a', 'b', 'test']) {
    const value = params.get(key)
    if (value !== null) kept.set(key, value)
  }
  const query = kept.toString()
  return <Navigate to={`../diagnosis${query === '' ? '' : `?${query}`}`} replace />
}
