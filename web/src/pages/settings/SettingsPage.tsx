import { useQuery } from '@tanstack/react-query'
import { LogOut } from 'lucide-react'
import { Navigate, NavLink, useNavigate, useParams } from 'react-router'

import { q } from '@/api/queries'
import { session } from '@/auth/session'
import { CodeBlock } from '@/components/copy'
import { Page, PageHeader } from '@/components/page'
import { StatusDot } from '@/components/status'
import { Button } from '@/components/ui/button'
import { Card, CardBody, CardHeader } from '@/components/ui/card'
import { t } from '@/i18n'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { cn } from '@/lib/utils'

import { AboutTab } from './AboutTab'
import { LogTab } from './LogTab'
import { UpdatesTab } from './UpdatesTab'

const s = t.settings

const TAB_IDS = ['session', 'updates', 'log', 'about'] as const
type TabId = (typeof TAB_IDS)[number]

/** 分区的名字在渲染时现取，换了语言就是新的。 */
function tabLabel(id: TabId): string {
  switch (id) {
    case 'session':
      return s.tabSession
    case 'updates':
      return t.updates.tab
    case 'log':
      return s.tabLog
    case 'about':
      return s.tabAbout
  }
}

function SessionTab() {
  const navigate = useNavigate()
  return (
    <div className="space-y-12">
      <Card>
        <CardHeader
          title={s.session.title}
          action={
            <Button
              size="sm"
              onClick={() => {
                session.signOut('manual')
                void navigate('/login', { replace: true })
              }}
            >
              <LogOut aria-hidden />
              {s.session.signOut}
            </Button>
          }
        />
        <CardBody>
          <p className="text-[13px] text-muted-foreground">{s.session.stored}</p>
        </CardBody>
      </Card>
      <Card>
        <CardHeader title={s.session.resetTitle} />
        <CardBody className="space-y-3">
          <p className="text-[13px] text-muted-foreground">{t.signIn.lostBody}</p>
          <CodeBlock copy={t.signIn.lostCommand}>{t.signIn.lostCommand}</CodeBlock>
        </CardBody>
      </Card>
    </div>
  )
}

/** 全局设置。左侧竖排的分区（窄的时候是上面的一行），每个分区有自己的地址。 */
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
      {/* 窄的时候分区排成上面的一行（放不下就横向滑动），内容占满宽度。 */}
      <div className="grid grid-cols-1 items-start gap-5 @2xl:grid-cols-[10rem_minmax(0,1fr)] @2xl:gap-12">
        <nav aria-label={s.tabsLabel} className="min-w-0">
          <ul className="-mx-4 flex [scrollbar-width:none] gap-1 overflow-x-auto px-4 @2xl:mx-0 @2xl:block @2xl:space-y-0.5 @2xl:px-0 [&::-webkit-scrollbar]:hidden">
            {TAB_IDS.map((candidate) => (
              <li key={candidate} className="shrink-0">
                <NavLink
                  to={`/settings/${candidate}`}
                  className={({ isActive }) =>
                    cn(
                      'flex h-8 items-center justify-between gap-2 rounded-md px-2.5 text-sm whitespace-nowrap transition-colors',
                      isActive
                        ? 'bg-foreground/[0.06] font-medium text-foreground'
                        : 'text-foreground/80 hover:bg-foreground/[0.04] hover:text-foreground',
                    )
                  }
                >
                  {tabLabel(candidate)}
                  {candidate === 'updates' && paused ? <StatusDot tone="danger" label={t.updates.pausedDot} /> : null}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="min-w-0">
          {active === 'session' ? <SessionTab /> : null}
          {active === 'updates' ? <UpdatesTab /> : null}
          {active === 'log' ? <LogTab /> : null}
          {active === 'about' ? <AboutTab /> : null}
        </div>
      </div>
    </Page>
  )
}
