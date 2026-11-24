import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { type LogEntry } from '@/api/types'
import { en } from '@/i18n/en'
import { setLocale, t } from '@/i18n'
import { makeNode } from '@/test/fixtures'
import { apiFailure, type ApiCall, fakeApi, NETWORK, renderWithApp } from '@/test/harness'

import { LogTab } from './LogTab'

const s = t.settings.log

/** 150 条记录，编号从 150 往下：一页 25 条，一共六页。 */
const ENTRIES: LogEntry[] = Array.from({ length: 150 }, (_, index) => {
  const id = 150 - index
  if (id === 150)
    return {
      id,
      at: 1_794_000_000,
      network: 1,
      action: 'credential.revoke',
      detail: '凭据 #5 phone 已吊销',
      refs: [
        { kind: 'credential', id: 5 },
        { kind: 'node', id: 2 },
        { kind: 'gadget', id: 1 },
      ],
    }
  return { id, at: 1_794_000_000 - index, network: 1, action: 'node.update', detail: `第 ${id} 条`, refs: [] }
})

/** 按 controller 的规则筛：before、network、action（前缀）、ref；一次最多给一千条。 */
function serveFrom(entries: readonly LogEntry[]) {
  return (call: ApiCall): LogEntry[] => {
    const before = Number(call.query.get('before') ?? Infinity)
    const action = call.query.get('action')
    const ref = call.query.get('ref')
    const limit = Math.min(Number(call.query.get('limit') ?? 100), 1000)
    return entries
      .filter((entry) => entry.id < before)
      .filter((entry) => action === null || entry.action === action || entry.action.startsWith(`${action}.`))
      .filter((entry) => ref === null || entry.refs.some((item) => `${item.kind}:${item.id}` === ref))
      .slice(0, limit)
  }
}

/** 1200 条：controller 一次给不完，要取两次。 */
const MANY: LogEntry[] = Array.from({ length: 1200 }, (_, index) => ({
  id: 1200 - index,
  at: 1_794_000_000 - index,
  network: 1,
  action: 'node.update',
  detail: '',
  refs: [],
}))

function setup() {
  return fakeApi({
    'GET /log': serveFrom(ENTRIES),
    'GET /networks': [NETWORK],
    'GET /networks/1/nodes': [makeNode(2, 'laptop')],
  })
}

describe('操作记录', () => {
  it('分页显示：一页 25 条，翻页换一批，不再向 controller 取', async () => {
    const user = userEvent.setup()
    const api = setup()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    expect(await screen.findByTestId('log-row-150')).toBeVisible()
    expect(screen.getByTestId('log-row-126')).toBeVisible()
    expect(screen.queryByTestId('log-row-125')).not.toBeInTheDocument()
    expect(screen.getByTestId('log-count')).toHaveTextContent(t.common.rowsTotal(150))
    expect(screen.getByText(t.common.pageOf(1, 6))).toBeVisible()
    expect(screen.getByRole('button', { name: t.common.prevPage })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: t.common.nextPage }))
    expect(screen.getByTestId('log-row-125')).toBeVisible()
    expect(screen.queryByTestId('log-row-150')).not.toBeInTheDocument()
    expect(screen.getByText(t.common.pageOf(2, 6))).toBeVisible()

    await user.click(screen.getByRole('button', { name: t.common.prevPage }))
    expect(screen.getByTestId('log-row-150')).toBeVisible()
    const calls = api.callsTo('GET /log')
    expect(calls).toHaveLength(1)
    expect(calls[0]?.query.get('limit')).toBe('1000')
  })

  it('一次取不完的接着往前取：下一批从上一批最后一条的编号往前，取完才写一共几项', async () => {
    const api = fakeApi({ 'GET /log': serveFrom(MANY), 'GET /networks': [NETWORK], 'GET /networks/1/nodes': [] })
    renderWithApp(<LogTab />, { route: '/settings/log' })
    expect(await screen.findByText(t.common.pageOf(1, 48))).toBeVisible()
    expect(screen.getByTestId('log-count')).toHaveTextContent(t.common.rowsTotal(1200))
    const calls = api.callsTo('GET /log')
    expect(calls).toHaveLength(2)
    expect(calls[1]?.query.get('before')).toBe('201')
  })

  it('后面的没取回来：写已加载几条，可以重试', async () => {
    const user = userEvent.setup()
    const serve = serveFrom(MANY)
    const api = fakeApi({
      'GET /log': (call) => (call.query.has('before') ? apiFailure(500, 'internal', '数据库忙') : serve(call)),
      'GET /networks': [NETWORK],
      'GET /networks/1/nodes': [],
    })
    renderWithApp(<LogTab />, { route: '/settings/log' })
    const retry = await screen.findByRole('button', { name: t.common.retry })
    expect(screen.getByTestId('log-count')).toHaveTextContent(s.loaded(1000))
    // 已经取回来的照样能翻。
    expect(screen.getByText(t.common.pageOf(1, 40))).toBeVisible()
    expect(api.callsTo('GET /log')).toHaveLength(2)

    api.use({ 'GET /log': serve })
    await user.click(retry)
    expect(await screen.findByText(t.common.pageOf(1, 48))).toBeVisible()
    expect(screen.getByTestId('log-count')).toHaveTextContent(t.common.rowsTotal(1200))
  })

  it('地址里的页码直接生效；改了条件回到第一页', async () => {
    const user = userEvent.setup()
    setup()
    renderWithApp(<LogTab />, { route: '/settings/log?page=3' })
    expect(await screen.findByTestId('log-row-100')).toBeVisible()
    expect(screen.queryByTestId('log-row-150')).not.toBeInTheDocument()
    expect(screen.getByText(t.common.pageOf(3, 6))).toBeVisible()

    await user.selectOptions(screen.getByRole('combobox', { name: s.filterAction }), 'node')
    expect(await screen.findByText(t.common.pageOf(1, 6))).toBeVisible()
    expect(screen.getByTestId('log-row-149')).toBeVisible()
  })

  it('记录说的东西做成链接；节点写名字；不认识的种类不显示', async () => {
    setup()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    const row = await screen.findByTestId('log-row-150')
    expect(within(row).getByRole('link', { name: s.refLabels.credential(5) })).toHaveAttribute('href', '/n/1/proxies')
    expect(await within(row).findByRole('link', { name: s.refLabels.node(2, 'laptop') })).toHaveAttribute(
      'href',
      '/n/1/nodes/2',
    )
    expect(within(row).queryByText(/gadget/)).not.toBeInTheDocument()
  })

  it('按操作筛：交给 controller，一类操作写前缀', async () => {
    const user = userEvent.setup()
    const api = setup()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    await screen.findByTestId('log-row-150')
    await user.selectOptions(screen.getByRole('combobox', { name: s.filterAction }), 'credential')
    await waitFor(() => expect(api.callsTo('GET /log').at(-1)?.query.get('action')).toBe('credential'))
    expect(await screen.findByTestId('log-count')).toHaveTextContent(t.common.rowsTotal(1))
    expect(screen.queryByTestId('log-row-149')).not.toBeInTheDocument()
  })

  it('只看和某样东西有关的：限定在它的网络里；条件可以单独去掉', async () => {
    const user = userEvent.setup()
    const api = setup()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    const row = await screen.findByTestId('log-row-150')
    await user.click(within(row).getByRole('button', { name: s.filterByRef(s.refLabels.credential(5)) }))
    await waitFor(() => expect(api.callsTo('GET /log').at(-1)?.query.get('ref')).toBe('credential:5'))
    expect(api.callsTo('GET /log').at(-1)?.query.get('network')).toBe('1')
    expect(screen.getByTestId('log-ref-filter')).toHaveTextContent(s.refChip(s.refLabels.credential(5)))
    expect(await screen.findByTestId('log-count')).toHaveTextContent(t.common.rowsTotal(1))

    await user.click(screen.getByRole('button', { name: s.refRemove(s.refLabels.credential(5)) }))
    await waitFor(() => expect(api.callsTo('GET /log').at(-1)?.query.get('ref')).toBeNull())
    expect(await screen.findByTestId('log-row-149')).toBeVisible()
  })

  it('地址里带来的条件直接生效；什么都筛不出来时可以一键清除', async () => {
    const user = userEvent.setup()
    const api = setup()
    renderWithApp(<LogTab />, { route: '/settings/log?action=group&q=x' })
    expect(await screen.findByText(s.noMatches)).toBeVisible()
    expect(api.callsTo('GET /log')[0]?.query.get('action')).toBe('group')
    expect(screen.getByRole('searchbox', { name: s.searchPlaceholder })).toHaveValue('x')
    const [clear] = screen.getAllByRole('button', { name: t.common.clearFilters })
    if (clear === undefined) throw new Error('没有"清除筛选"')
    await user.click(clear)
    expect(await screen.findByTestId('log-row-150')).toBeVisible()
  })

  it('搜索在全部记录里找，不只是这一页：controller 的原话和界面写的字都算', async () => {
    const user = userEvent.setup()
    setup()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    await screen.findByTestId('log-row-150')
    const search = screen.getByRole('searchbox', { name: s.searchPlaceholder })
    await user.type(search, 'phone')
    expect(screen.getByTestId('log-count')).toHaveTextContent(`${t.common.rowsTotal(1)} / 150`)
    await user.clear(search)
    await user.type(search, s.actions['credential.revoke'])
    expect(screen.getByTestId('log-count')).toHaveTextContent(`${t.common.rowsTotal(1)} / 150`)
    // 第 30 条在第五页上，照样找得到；只剩一页，不显示翻页。
    await user.clear(search)
    await user.type(search, '第 30 条')
    expect(screen.getByTestId('log-row-30')).toBeVisible()
    expect(screen.queryByRole('button', { name: t.common.nextPage })).not.toBeInTheDocument()
  })

  it('每一行先写界面按操作写的话，controller 的原话在下面一行', async () => {
    setup()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    const row = await screen.findByTestId('log-row-150')
    expect(within(row).getByTestId('log-action')).toHaveTextContent(s.actions['credential.revoke'])
    expect(within(row).getByTestId('log-detail')).toHaveTextContent('凭据 #5 phone 已吊销')
  })

  it('英文界面：操作和对象用英文写，原话照旧作补充', async () => {
    setLocale('en', { remember: false })
    setup()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    const row = await screen.findByTestId('log-row-150')
    expect(within(row).getByTestId('log-action')).toHaveTextContent(en.settings.log.actions['credential.revoke'])
    expect(within(row).getByRole('link', { name: en.settings.log.refLabels.credential(5) })).toBeVisible()
    expect(within(row).getByTestId('log-detail')).toHaveTextContent('凭据 #5 phone 已吊销')
  })

  it('不认识的操作原样写代码', async () => {
    fakeApi({
      'GET /log': [{ id: 1, at: 1_794_000_000, network: null, action: 'gadget.spin', detail: '', refs: [] }],
      'GET /networks': [NETWORK],
    })
    renderWithApp(<LogTab />, { route: '/settings/log' })
    const row = await screen.findByTestId('log-row-1')
    expect(within(row).getByTestId('log-action')).toHaveTextContent('gadget.spin')
    expect(within(row).queryByTestId('log-detail')).not.toBeInTheDocument()
  })

  const GROUP_ENTRY: LogEntry = {
    id: 7,
    at: 1_794_000_000,
    network: 1,
    action: 'group.members',
    detail: '分组 #3 servers：加入 laptop',
    refs: [
      { kind: 'group', id: 3 },
      { kind: 'node', id: 2 },
    ],
  }

  for (const locale of ['zh-CN', 'en'] as const) {
    it(`分组的操作按代码写（${locale}）；分组做成链接，去分组页上的那一行`, async () => {
      setLocale(locale, { remember: false })
      fakeApi({
        'GET /log': [GROUP_ENTRY],
        'GET /networks': [NETWORK],
        'GET /networks/1/nodes': [makeNode(2, 'laptop')],
      })
      renderWithApp(<LogTab />, { route: '/settings/log' })
      const row = await screen.findByTestId('log-row-7')
      expect(within(row).getByTestId('log-action')).toHaveTextContent(t.settings.log.actions['group.members'])
      expect(within(row).getByRole('link', { name: t.settings.log.refLabels.group(3) })).toHaveAttribute(
        'href',
        '/n/1/groups?focus=3',
      )
    })
  }

  /** 经 MCP 改了一个节点；签发、撤销 MCP 令牌；换了签名密钥。最后一条是参数出现之前的 controller 记的。 */
  const MCP_ENTRIES: LogEntry[] = [
    {
      id: 15,
      at: 1_794_000_500,
      network: 1,
      action: 'node.update',
      detail: '节点 #2 laptop 改名',
      refs: [{ kind: 'node', id: 2 }],
      params: { node: 2, name: 'laptop' },
      actor: { kind: 'mcp', name: 'claude-code', jti: 'jti-claude' },
    },
    {
      id: 14,
      at: 1_794_000_400,
      network: 1,
      action: 'mcp.token.create',
      detail: '签发 MCP 令牌 #3（claude-code）',
      refs: [],
      params: {
        token: 3,
        name: 'claude-code',
        jti: 'jti-claude',
        scopes: ['read', 'nodes:enroll'],
        network: 1,
        network_name: 'home',
        expires_at: 1_796_592_000,
      },
      actor: null,
    },
    {
      id: 13,
      at: 1_794_000_300,
      network: null,
      action: 'mcp.token.create',
      detail: '签发 MCP 令牌 #4（cursor）',
      refs: [],
      params: {
        token: 4,
        name: 'cursor',
        jti: 'jti-cursor',
        scopes: ['read'],
        network: null,
        network_name: null,
        expires_at: 1_796_592_000,
      },
      actor: null,
    },
    {
      id: 12,
      at: 1_794_000_200,
      network: null,
      action: 'mcp.token.revoke',
      detail: '撤销 MCP 令牌 #4（cursor）',
      refs: [],
      params: { token: 4, name: 'cursor', jti: 'jti-cursor' },
      actor: null,
    },
    {
      id: 11,
      at: 1_794_000_100,
      network: null,
      action: 'mcp.key.rotate',
      detail: '签 MCP 令牌的密钥换了，原来签的 2 个令牌全部作废',
      refs: [],
      params: { revoked: 2 },
      actor: null,
    },
    {
      id: 10,
      at: 1_794_000_000,
      network: null,
      action: 'mcp.token.revoke',
      detail: '撤销 MCP 令牌 #1（old）',
      refs: [],
    },
  ]

  function setupMcp() {
    return fakeApi({
      'GET /log': serveFrom(MCP_ENTRIES),
      'GET /networks': [NETWORK],
      'GET /networks/1/nodes': [makeNode(2, 'laptop')],
    })
  }

  for (const locale of ['zh-CN', 'en'] as const) {
    it(`经 MCP 做的操作注明是哪个令牌做的，悬停或聚焦看 jti；别的操作不注（${locale}）`, async () => {
      setLocale(locale, { remember: false })
      setupMcp()
      renderWithApp(<LogTab />, { route: '/settings/log' })
      const row = await screen.findByTestId('log-row-15')
      const actor = within(row).getByTestId('log-actor')
      expect(actor).toHaveTextContent(t.settings.log.actor.mcp('claude-code'))
      // 操作和对象照旧写。
      expect(within(row).getByTestId('log-action')).toHaveTextContent(t.settings.log.actions['node.update'])
      expect(within(row).getByTestId('log-detail')).toHaveTextContent('节点 #2 laptop 改名')
      // 键盘聚焦和悬停一样弹出说明，不用等悬停的那一下延迟。
      act(() => actor.focus())
      expect(await screen.findByRole('tooltip')).toHaveTextContent(t.settings.log.actor.jti('jti-claude'))
      // 管理员自己签发、撤销令牌的那几条不注。
      for (const id of [14, 13, 12, 11, 10]) {
        expect(within(screen.getByTestId(`log-row-${id}`)).queryByTestId('log-actor')).not.toBeInTheDocument()
      }
    })

    it(`MCP 令牌的几种操作按参数写成整句话，不再重复 controller 的原话（${locale}）`, async () => {
      setLocale(locale, { remember: false })
      setupMcp()
      renderWithApp(<LogTab />, { route: '/settings/log' })
      const say = t.settings.log.sentences
      const scopes = ['read', 'nodes:enroll'].join(t.common.listSeparator)
      const action = (id: number) => within(screen.getByTestId(`log-row-${id}`)).getByTestId('log-action')
      await screen.findByTestId('log-row-14')
      expect(action(14)).toHaveTextContent(say.mcpTokenCreate(3, 'claude-code', scopes, 'home'))
      expect(action(13)).toHaveTextContent(say.mcpTokenCreate(4, 'cursor', 'read', null))
      expect(action(12)).toHaveTextContent(say.mcpTokenRevoke(4, 'cursor'))
      expect(action(11)).toHaveTextContent(say.mcpKeyRotate(2))
      for (const id of [14, 13, 12, 11]) {
        expect(within(screen.getByTestId(`log-row-${id}`)).queryByTestId('log-detail')).not.toBeInTheDocument()
      }
      // 没有参数的旧记录：写操作的名字，原话照旧作补充。
      expect(action(10)).toHaveTextContent(t.settings.log.actions['mcp.token.revoke'])
      expect(within(screen.getByTestId('log-row-10')).getByTestId('log-detail')).toHaveTextContent(
        '撤销 MCP 令牌 #1（old）',
      )
    })
  }

  it('写出来的句子：只限一个网络的写网络的名字，不限的写不限', () => {
    const say = t.settings.log.sentences
    expect(say.mcpTokenCreate(3, 'claude-code', 'read', 'home')).toBe(
      '签发 MCP 令牌 #3（claude-code），权限 read，只限网络 home',
    )
    expect(say.mcpTokenCreate(3, 'claude-code', 'read', null)).toBe(
      '签发 MCP 令牌 #3（claude-code），权限 read，不限网络',
    )
    setLocale('en', { remember: false })
    expect(say.mcpTokenCreate(3, 'claude-code', 'read, nodes:enroll', 'home')).toBe(
      'MCP token #3 issued (claude-code), scopes read, nodes:enroll, network home only',
    )
    expect(say.mcpTokenCreate(3, 'claude-code', 'read', null)).toBe(
      'MCP token #3 issued (claude-code), scopes read, any network',
    )
    expect(say.mcpTokenRevoke(3, 'claude-code')).toBe('MCP token #3 revoked (claude-code)')
    expect(say.mcpKeyRotate(1)).toBe('MCP signing key changed; 1 token issued before is void')
    expect(say.mcpKeyRotate(2)).toBe('MCP signing key changed; 2 tokens issued before are void')
  })

  it('搜索找得到做这件事的令牌：按名字，按 jti（签发它的那一条也算）', async () => {
    const user = userEvent.setup()
    setupMcp()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    await screen.findByTestId('log-row-15')
    const search = screen.getByRole('searchbox', { name: s.searchPlaceholder })
    await user.type(search, 'jti-claude')
    expect(screen.getByTestId('log-count')).toHaveTextContent(`${t.common.rowsTotal(2)} / 6`)
    expect(screen.getByTestId('log-row-15')).toBeVisible()
    expect(screen.getByTestId('log-row-14')).toBeVisible()
    await user.clear(search)
    await user.type(search, s.actor.mcp('claude-code'))
    expect(screen.getByTestId('log-count')).toHaveTextContent(`${t.common.rowsTotal(1)} / 6`)
    await user.clear(search)
    await user.type(search, 'nodes:enroll')
    expect(screen.getByTestId('log-count')).toHaveTextContent(`${t.common.rowsTotal(1)} / 6`)
    expect(screen.getByTestId('log-row-14')).toBeVisible()
  })

  it('按操作筛的下拉里有 MCP 令牌这一类', async () => {
    const user = userEvent.setup()
    const api = setupMcp()
    renderWithApp(<LogTab />, { route: '/settings/log' })
    await screen.findByTestId('log-row-15')
    const select = screen.getByRole('combobox', { name: s.filterAction })
    expect(within(select).getByRole('option', { name: s.actions['mcp.token.create'] })).toHaveValue('mcp.token.create')
    expect(within(select).getByRole('option', { name: s.actions['mcp.key.rotate'] })).toHaveValue('mcp.key.rotate')
    await user.selectOptions(select, s.kindAll(s.kinds.mcp))
    await waitFor(() => expect(api.callsTo('GET /log').at(-1)?.query.get('action')).toBe('mcp'))
    expect(await screen.findByTestId('log-count')).toHaveTextContent(t.common.rowsTotal(5))
    expect(screen.queryByTestId('log-row-15')).not.toBeInTheDocument()
  })

  it('比界面新的 controller 报来的别的种类的操作者：原样写种类和名字', async () => {
    fakeApi({
      'GET /log': [
        {
          id: 1,
          at: 1_794_000_000,
          network: null,
          action: 'network.create',
          detail: '',
          refs: [],
          actor: { kind: 'oidc', name: 'alice', jti: 'x' },
        },
      ],
      'GET /networks': [NETWORK],
    })
    renderWithApp(<LogTab />, { route: '/settings/log' })
    expect(within(await screen.findByTestId('log-row-1')).getByTestId('log-actor')).toHaveTextContent('oidc alice')
  })
})
