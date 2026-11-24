import { useQuery } from '@tanstack/react-query'
import { Navigate, useParams } from 'react-router'

import { q } from '@/api/queries'
import { Page, PageHeader } from '@/components/page'
import { Sectioned } from '@/components/sectioned'
import { StatusDot } from '@/components/status'
import { t } from '@/i18n'
import { useDocumentTitle } from '@/lib/useDocumentTitle'

import { AboutTab } from './AboutTab'
import { LogTab } from './LogTab'
import { McpTab } from './McpTab'
import { SessionTab } from './SessionTab'
import { UpdatesTab } from './UpdatesTab'

const s = t.settings

const TAB_IDS = ['session', 'mcp', 'updates', 'log', 'about'] as const
type TabId = (typeof TAB_IDS)[number]

/** 分区的名字在渲染时现取，换了语言就是新的。 */
function tabLabel(id: TabId): string {
  switch (id) {
    case 'session':
      return s.tabSession
    case 'mcp':
      return s.tabMcp
    case 'updates':
      return t.updates.tab
    case 'log':
      return s.tabLog
    case 'about':
      return s.tabAbout
  }
}

/** 全局设置。分区的排法见 `Sectioned`：左侧竖排的分区，每个分区有自己的地址。 */
export function SettingsPage() {
  const params = useParams()
  const tab = TAB_IDS.find((candidate) => candidate === params.tab)
  useDocumentTitle(tab === undefined ? s.title : `${tabLabel(tab)} · ${s.title}`)
  // 有被暂停的版本时，「节点更新」旁边一个红点：从设置的任何一页都看得到。
  const update = useQuery(q.update())
  const paused = (update.data?.paused.length ?? 0) > 0
  if (tab === undefined) return <Navigate to="/settings/session" replace />
  const active: TabId = tab

  return (
    <Page>
      <PageHeader title={s.title} description={s.subtitle} />
      <Sectioned
        label={s.tabsLabel}
        sections={TAB_IDS.map((candidate) => ({
          to: `/settings/${candidate}`,
          label: tabLabel(candidate),
          mark: candidate === 'updates' && paused ? <StatusDot tone="danger" label={t.updates.pausedDot} /> : undefined,
        }))}
      >
        {active === 'session' ? <SessionTab /> : null}
        {active === 'mcp' ? <McpTab /> : null}
        {active === 'updates' ? <UpdatesTab /> : null}
        {active === 'log' ? <LogTab /> : null}
        {active === 'about' ? <AboutTab /> : null}
      </Sectioned>
    </Page>
  )
}
