import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { type Network } from '@/api/types'
import { t } from '@/i18n'
import { makeNode } from '@/test/fixtures'
import { fakeApi, NETWORK, renderWithApp } from '@/test/harness'

import { NetworkContext } from './context'
import { NetworkPage } from './NetworkPage'

const n = t.networks

const LAB: Network = { ...NETWORK, id: 2, name: 'lab', domain: 'lab.i3t', cidr: '10.67.0.0/16', nodes: 3 }

function setup(networks: Network[] = [NETWORK, LAB]) {
  return fakeApi({
    'GET /networks': networks,
    'GET /networks/1/nodes': [makeNode(1, 'nas', { routing: 'lowest_cost' })],
    'GET /networks/1/overview': { rules: 1, proxies: 0, pending_tokens: 0 },
    'PATCH /networks/1': (call) => ({ ...NETWORK, ...(call.body as object) }),
  })
}

/** 打开网络页的一个分区（不写就是不带分区的地址）。 */
function open(section: string | null, network: Network = NETWORK) {
  const page = (
    <Routes>
      <Route path="/n/:network/network" element={<NetworkPage />} />
      <Route path="/n/:network/network/:section" element={<NetworkPage />} />
    </Routes>
  )
  return renderWithApp(page, { network, route: section === null ? '/n/1/network' : `/n/1/network/${section}` })
}

describe('网络', () => {
  it('左边一列分区，各有自己的地址；不带分区的地址去基本信息', () => {
    setup()
    open(null)
    const sections = within(screen.getByRole('navigation', { name: n.sectionsLabel }))
    expect(sections.getAllByRole('link').map((link) => link.getAttribute('href'))).toEqual([
      '/n/1/network/basics',
      '/n/1/network/routing',
      '/n/1/network/connection',
      '/n/1/network/adapter',
      '/n/1/network/danger',
    ])
    expect(sections.getByRole('link', { name: n.basics })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('heading', { name: n.basics })).toBeVisible()
    // 一次只看一个分区。
    expect(screen.queryByRole('form', { name: n.routing })).not.toBeInTheDocument()
  })

  it('窄屏上分区名是横着滑的一行：打开排在后面的分区，它的名字滑进看得见的地方', () => {
    setup()
    const scrolled = vi.spyOn(Element.prototype, 'scrollIntoView')
    open('danger')
    const sections = within(screen.getByRole('navigation', { name: n.sectionsLabel }))
    expect(scrolled.mock.contexts).toContain(sections.getByRole('link', { name: n.danger }))
    scrolled.mockRestore()
  })

  it('分区名旁边写着这个分区改过几项；都是默认值时不写', () => {
    setup()
    open('basics', {
      ...NETWORK,
      reach: 'relay_only',
      class: 'bulk',
      max_ack_delay_ms: 5,
      vnet_mtu: 1400,
      vnet_offload: false,
    })
    const sections = within(screen.getByRole('navigation', { name: n.sectionsLabel }))
    expect(
      within(sections.getByRole('link', { name: new RegExp(n.routing) })).getByLabelText(n.modifiedCount(2)),
    ).toBeVisible()
    expect(
      within(sections.getByRole('link', { name: new RegExp(n.connection) })).getByLabelText(n.modifiedCount(1)),
    ).toBeVisible()
    expect(
      within(sections.getByRole('link', { name: new RegExp(n.adapter) })).getByLabelText(n.modifiedCount(2)),
    ).toBeVisible()
    expect(sections.getByRole('link', { name: n.basics })).toHaveTextContent(n.basics)
  })

  it('controller 没给默认值（旧版本）：不标谁改过', () => {
    setup()
    open('connection', { ...NETWORK, ack_eliciting_threshold: 4, defaults: undefined })
    expect(screen.queryByText(t.common.modified)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(n.modifiedCount(1))).not.toBeInTheDocument()
  })

  it('基本信息：一张卡片；其他网络一行一个，点了切过去', async () => {
    setup()
    open('basics')
    const basics = screen.getByRole('heading', { name: n.basics }).closest('section')
    if (basics === null) throw new Error('没有基本信息卡片')
    expect(basics).toHaveTextContent('home.i3t')
    expect(basics).toHaveTextContent('10.66.0.0/16')
    expect(within(basics).getByRole('button', { name: n.expand })).toBeVisible()
    expect(await screen.findByRole('link', { name: n.switchTo('lab') })).toHaveAttribute('href', '/n/2/network')
  })

  it('基本信息：只有这一个网络时没有其他网络那张卡片', async () => {
    setup([NETWORK])
    open('basics')
    await screen.findByRole('heading', { name: n.basics })
    await waitFor(() => expect(screen.queryByRole('heading', { name: n.othersTitle })).not.toBeInTheDocument())
  })

  it('选路：说明跟着选的那一项变；改了才能保存，一次提交这个分区的全部', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('routing')
    const save = screen.getByRole('button', { name: n.saveSettings })
    expect(save).toBeDisabled()
    expect(screen.getByText(n.routingDirectFirstDesc)).toBeVisible()
    // 单独设了选路模式的节点有几个，点过去看。
    expect(await screen.findByRole('link', { name: n.routingOverridden(1) })).toHaveAttribute('href', '/n/1/nodes')

    await user.selectOptions(screen.getByLabelText(n.routingLabel), 'lowest_cost')
    await user.selectOptions(screen.getByLabelText(n.reachLabel), 'direct_only')
    expect(screen.getByText(n.routingLowestCostDesc)).toBeVisible()
    expect(screen.getByText(n.reachDirectOnlyDesc)).toBeVisible()
    await user.click(save)
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toEqual({
      routing: 'lowest_cost',
      max_relay_hops: 2,
      reach: 'direct_only',
      class: 'auto',
    })
  })

  it('选路：取消回到原来的设置', async () => {
    const user = userEvent.setup()
    setup()
    open('routing')
    const hops = screen.getByLabelText(n.hopsLabel)
    await user.selectOptions(hops, '3')
    await user.click(screen.getByRole('button', { name: t.common.cancel }))
    expect(hops).toHaveValue('2')
    expect(screen.getByRole('button', { name: n.saveSettings })).toBeDisabled()
  })

  it('选路：和默认值不一样的那一行标着已修改、写着默认值；恢复默认填回表单，保存才生效', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('routing', { ...NETWORK, max_relay_hops: 3, class: 'bulk' })
    expect(screen.getAllByText(t.common.modified)).toHaveLength(2)
    expect(screen.getByText(t.common.defaultIs(n.hops(2)), { exact: false })).toBeVisible()
    expect(screen.getByText(t.common.defaultIs(t.serviceClass.auto), { exact: false })).toBeVisible()

    await user.click(screen.getByRole('button', { name: t.common.restoreDefaultOf(n.hopsLabel) }))
    expect(screen.getByLabelText(n.hopsLabel)).toHaveValue('2')
    expect(screen.getAllByText(t.common.modified)).toHaveLength(1)
    expect(api.callsTo('PATCH /networks/1')).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: n.saveSettings }))
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toMatchObject({ max_relay_hops: 2, class: 'bulk' })
  })

  it('连接：两项确认设置一起保存，只提交这两项', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('connection')
    const threshold = screen.getByLabelText(n.ackThresholdLabel)
    const delay = screen.getByLabelText(n.ackDelayLabel)
    const save = screen.getByRole('button', { name: n.saveSettings })
    expect(threshold).toHaveValue('3')
    expect(delay).toHaveValue('2')
    expect(save).toBeDisabled()
    expect(screen.queryByText(t.common.modified)).not.toBeInTheDocument()

    await user.clear(threshold)
    await user.type(threshold, '4')
    // 表单里的值一和默认值不一样，这一行就标出来，写着默认值。
    expect(screen.getByText(t.common.modified)).toBeVisible()
    expect(screen.getByText(t.common.defaultIs(`3 ${n.ackThresholdUnit}`), { exact: false })).toBeVisible()
    await user.click(save)
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toEqual({ ack_eliciting_threshold: 4, max_ack_delay_ms: 2 })
  })

  it('连接：超出范围的值写明范围，保存是灰的；取消回到原来的值', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('connection')
    const delay = screen.getByLabelText(n.ackDelayLabel)
    await user.clear(delay)
    await user.type(delay, '26')
    expect(screen.getByRole('alert')).toHaveTextContent(n.wholeNumberBetween(1, 25))
    expect(screen.getByRole('button', { name: n.saveSettings })).toBeDisabled()
    await user.type(delay, '{Enter}')
    expect(api.callsTo('PATCH /networks/1')).toHaveLength(0)

    await user.click(screen.getByRole('button', { name: t.common.cancel }))
    expect(delay).toHaveValue('2')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('连接：恢复默认把默认值填回去', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('connection', { ...NETWORK, ack_eliciting_threshold: 4, max_ack_delay_ms: 5 })
    await user.click(screen.getByRole('button', { name: t.common.restoreDefaultOf(n.ackDelayLabel) }))
    expect(screen.getByLabelText(n.ackDelayLabel)).toHaveValue('2')
    await user.click(screen.getByRole('button', { name: n.saveSettings }))
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toEqual({ ack_eliciting_threshold: 4, max_ack_delay_ms: 2 })
  })

  it('虚拟网卡：三项设置按顺序排着；合并小包从连接那里搬到了这里', () => {
    setup()
    const { unmount } = open('adapter')
    const form = within(screen.getByRole('form', { name: n.adapter }))
    expect(form.getByRole('switch', { name: n.offloadLabel })).toBeChecked()
    expect(form.getByLabelText(n.mtuLabel)).toHaveValue('1280')
    expect(form.getByRole('switch', { name: n.bundleLabel })).toBeChecked()
    expect(screen.getByText(n.offloadDesc)).toBeVisible()
    expect(screen.getByText(n.mtuDesc)).toBeVisible()
    expect(screen.getByRole('button', { name: n.saveSettings })).toBeDisabled()
    unmount()

    open('connection')
    expect(screen.queryByRole('switch', { name: n.bundleLabel })).not.toBeInTheDocument()
  })

  it('虚拟网卡：关掉分段卸载只提交这一项；恢复默认把它打开', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('adapter')
    const offload = screen.getByRole('switch', { name: n.offloadLabel })
    await user.click(offload)
    expect(offload).not.toBeChecked()
    expect(screen.getByText(t.common.defaultIs(n.switchOn), { exact: false })).toBeVisible()
    await user.click(screen.getByRole('button', { name: n.saveSettings }))
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toEqual({ vnet_offload: false })

    await user.click(screen.getByRole('button', { name: t.common.restoreDefaultOf(n.offloadLabel) }))
    expect(offload).toBeChecked()
  })

  it('虚拟网卡：默认 MTU 写得不对时有提示、不能保存；写对了只提交这一项', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('adapter')
    const mtu = screen.getByLabelText(n.mtuLabel)
    for (const wrong of ['575', '1501', '12.5', '']) {
      await user.clear(mtu)
      if (wrong !== '') await user.type(mtu, wrong)
      expect(screen.getByRole('alert')).toHaveTextContent(n.wholeNumberBetween(576, 1500))
      expect(screen.getByRole('button', { name: n.saveSettings })).toBeDisabled()
    }
    await user.clear(mtu)
    await user.type(mtu, '1400')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByText(t.common.defaultIs(`1280 ${n.mtuUnit}`), { exact: false })).toBeVisible()
    await user.click(screen.getByRole('button', { name: n.saveSettings }))
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toEqual({ vnet_mtu: 1400 })

    await user.click(screen.getByRole('button', { name: t.common.restoreDefaultOf(n.mtuLabel) }))
    expect(mtu).toHaveValue('1280')
  })

  it('虚拟网卡：合并小包是一个开关，关掉之后只提交这一项；恢复默认把它打开', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('adapter')
    const bundling = screen.getByRole('switch', { name: n.bundleLabel })
    expect(bundling).toBeChecked()
    expect(screen.getByText(n.bundleDesc)).toBeVisible()

    await user.click(bundling)
    expect(bundling).not.toBeChecked()
    await user.click(screen.getByRole('button', { name: n.saveSettings }))
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toEqual({ bundle_small_packets: false })

    await user.click(screen.getByRole('button', { name: t.common.restoreDefaultOf(n.bundleLabel) }))
    expect(bundling).toBeChecked()
  })

  it('虚拟网卡：改过的标着已修改；几项一起改一起提交，取消回到原来的', async () => {
    const user = userEvent.setup()
    const api = setup()
    open('adapter', { ...NETWORK, bundle_small_packets: false, vnet_mtu: 1400 })
    expect(screen.getByRole('switch', { name: n.bundleLabel })).not.toBeChecked()
    expect(screen.getAllByText(t.common.modified)).toHaveLength(2)

    await user.click(screen.getByRole('switch', { name: n.offloadLabel }))
    await user.click(screen.getByRole('switch', { name: n.bundleLabel }))
    await user.click(screen.getByRole('button', { name: t.common.cancel }))
    expect(screen.getByRole('switch', { name: n.offloadLabel })).toBeChecked()
    expect(screen.getByRole('switch', { name: n.bundleLabel })).not.toBeChecked()

    await user.click(screen.getByRole('switch', { name: n.offloadLabel }))
    await user.click(screen.getByRole('switch', { name: n.bundleLabel }))
    await user.click(screen.getByRole('button', { name: n.saveSettings }))
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toEqual({ vnet_offload: false, bundle_small_packets: true })
  })

  it('虚拟网卡：controller 不报的那几项没有那一行，也不提交；一项都不报时写着说明', async () => {
    const user = userEvent.setup()
    const api = setup()
    // 有合并小包、还没有网卡那两项的 controller。
    const older: Network = { ...NETWORK }
    delete older.vnet_offload
    delete older.vnet_mtu
    const { unmount } = open('adapter', older)
    expect(screen.queryByRole('switch', { name: n.offloadLabel })).not.toBeInTheDocument()
    expect(screen.queryByLabelText(n.mtuLabel)).not.toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: n.bundleLabel }))
    await user.click(screen.getByRole('button', { name: n.saveSettings }))
    await waitFor(() => expect(api.callsTo('PATCH /networks/1')).toHaveLength(1))
    expect(api.callsTo('PATCH /networks/1')[0]?.body).toEqual({ bundle_small_packets: false })
    unmount()

    const oldest: Network = { ...older }
    delete oldest.bundle_small_packets
    open('adapter', oldest)
    expect(screen.getByText(n.adapterUnsupported)).toBeVisible()
    expect(screen.queryByRole('button', { name: n.saveSettings })).not.toBeInTheDocument()
  })

  it('虚拟网卡：别处改了设置，这里跟着变，不算有没保存的改动', async () => {
    const user = userEvent.setup()
    setup()
    // 网络的设置是从外面给进来的：别的标签页或者 i3tctl 改了之后，重新取到的就是新的。按钮代替"重新取到了"。
    function Page() {
      const [network, setNetwork] = useState(NETWORK)
      return (
        <NetworkContext value={network}>
          <button
            type="button"
            onClick={() => setNetwork({ ...NETWORK, bundle_small_packets: false, vnet_offload: false, vnet_mtu: 1400 })}
          >
            changed elsewhere
          </button>
          <Routes>
            <Route path="/n/:network/network/:section" element={<NetworkPage />} />
          </Routes>
        </NetworkContext>
      )
    }
    renderWithApp(<Page />, { route: '/n/1/network/adapter' })
    expect(screen.getByRole('switch', { name: n.bundleLabel })).toBeChecked()

    await user.click(screen.getByRole('button', { name: 'changed elsewhere' }))
    expect(screen.getByRole('switch', { name: n.bundleLabel })).not.toBeChecked()
    expect(screen.getByRole('switch', { name: n.offloadLabel })).not.toBeChecked()
    expect(screen.getByLabelText(n.mtuLabel)).toHaveValue('1400')
    expect(screen.getByRole('button', { name: n.saveSettings })).toBeDisabled()
  })

  it('危险操作：网络里还有节点时删除是灰的，写着要先删节点', () => {
    setup()
    open('danger', { ...NETWORK, nodes: 2 })
    expect(screen.getByRole('button', { name: n.deleteButton })).toBeDisabled()
    expect(screen.getByText(n.dangerNotEmpty(2), { exact: false })).toBeVisible()
  })
})
