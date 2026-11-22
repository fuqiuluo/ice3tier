import { Plus } from 'lucide-react'
import { useState } from 'react'
import { Navigate, useParams } from 'react-router'

import { type Network } from '@/api/types'
import { Page, PageHeader } from '@/components/page'
import { Sectioned } from '@/components/sectioned'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { t } from '@/i18n'
import { useDocumentTitle } from '@/lib/useDocumentTitle'

import { BasicsSection } from './BasicsSection'
import { ConnectionSection } from './ConnectionSection'
import { networkPath, useNetwork } from './context'
import { CreateNetworkDialog } from './CreateNetworkDialog'
import { DangerSection } from './DangerSection'
import { RoutingSection } from './RoutingSection'
import { modifiedCount, SECTION_SETTINGS, type SettingsSection } from './settings'

const n = t.networks

/** 分区，按左边那一列的顺序。加一类设置就是在这里加一个分区、写它的那个文件。 */
const SECTION_IDS = ['basics', 'routing', 'connection', 'danger'] as const
type SectionId = (typeof SECTION_IDS)[number]

/** 分区的名字在渲染时现取，换了语言就是新的。 */
function sectionLabel(id: SectionId): string {
  switch (id) {
    case 'basics':
      return n.basics
    case 'routing':
      return n.routing
    case 'connection':
      return n.connection
    case 'danger':
      return n.danger
  }
}

function isSettingsSection(id: SectionId): id is SettingsSection {
  return id in SECTION_SETTINGS
}

/** 分区名右边：这个分区里有几项设置和默认值不一样。都是默认值时什么都没有。 */
function modifiedMark(network: Network, id: SectionId) {
  const count = isSettingsSection(id) ? modifiedCount(network, id) : 0
  return count === 0 ? undefined : (
    <Badge tone="accent" aria-label={n.modifiedCount(count)}>
      {count}
    </Badge>
  )
}

/**
 * 网络页：这个网络的信息和全部设置，排法和全局的「设置」一样（`Sectioned`）：左边一列分区，右边是选中的那个，
 * 每个分区有自己的地址（`/n/1/network/connection`）。设置会越加越多，所以按分区排，不往下叠卡片。
 * 右边的内容不跟着面板拉宽：一行设置的名字和它的控件不能隔得太远。
 */
export function NetworkPage() {
  const network = useNetwork()
  const params = useParams()
  const section = SECTION_IDS.find((candidate) => candidate === params.section)
  useDocumentTitle(section === undefined ? n.title : `${sectionLabel(section)} · ${n.title}`)
  const [creating, setCreating] = useState(false)
  if (section === undefined) return <Navigate to={networkPath(network.id, 'network/basics')} replace />
  const active: SectionId = section

  return (
    <Page>
      <PageHeader
        title={n.title}
        description={n.subtitle}
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus aria-hidden />
            {n.create}
          </Button>
        }
      />

      <Sectioned
        label={n.sectionsLabel}
        sections={SECTION_IDS.map((id) => ({
          to: networkPath(network.id, `network/${id}`),
          label: sectionLabel(id),
          mark: modifiedMark(network, id),
        }))}
      >
        <div className="max-w-4xl">
          {active === 'basics' ? <BasicsSection network={network} /> : null}
          {/* key：切换网络或者保存之后，表单从最新的设置重新开始。 */}
          {active === 'routing' ? (
            <RoutingSection
              key={`${network.id}:${network.routing}:${network.max_relay_hops}:${network.reach}:${network.class ?? 'auto'}`}
              network={network}
            />
          ) : null}
          {active === 'connection' ? (
            <ConnectionSection
              key={`${network.id}:${network.ack_eliciting_threshold}:${network.max_ack_delay_ms}:${network.bundle_small_packets ?? ''}`}
              network={network}
            />
          ) : null}
          {active === 'danger' ? <DangerSection network={network} /> : null}
        </div>
      </Sectioned>

      <CreateNetworkDialog open={creating} onClose={() => setCreating(false)} />
    </Page>
  )
}
