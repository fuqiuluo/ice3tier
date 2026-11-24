import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router'
import { describe, expect, it } from 'vitest'

import { type CreatedMcpToken, type McpScope, type McpTokenInfo, type Network } from '@/api/types'
import { setLocale, t } from '@/i18n'
import { networkPath } from '@/pages/networks/context'
import { makeMcpToken, makeOverview } from '@/test/fixtures'
import { fakeApi, type FakeApi, NETWORK, renderWithApp, type Routes as ApiRoutes } from '@/test/harness'

import { McpTab } from './McpTab'
import { SettingsPage } from './SettingsPage'

const m = t.settings.mcp
const d = m.dialog

const DAY = 24 * 60 * 60
const NOW = Math.floor(Date.now() / 1000)

const OFFICE: Network = { ...NETWORK, id: 2, name: 'office', domain: 'office.i3t', cidr: '10.67.0.0/16' }

/** 一个还能用的、一个过期的（只限 office，带着一项这个界面不认识的权限）、一个撤销了的（只限 home）。 */
const TOKENS: McpTokenInfo[] = [
  makeMcpToken(1, 'claude-code', { jti: 'jti-claude', scopes: ['read', 'nodes:enroll'], expires_at: NOW + 30 * DAY }),
  makeMcpToken(2, 'cursor', {
    jti: 'jti-cursor',
    scopes: ['read', 'config:write', 'future:scope'],
    network: 2,
    expires_at: NOW - DAY,
    state: 'expired',
  }),
  makeMcpToken(3, 'codex', {
    jti: 'jti-codex',
    network: 1,
    expires_at: NOW + 7 * DAY,
    revoked_at: NOW - 3600,
    state: 'revoked',
  }),
]

/** 一个真的 JWT 的样子：三段 base64url，中间是点。 */
const JWT = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGF1ZGUtY29kZSIsImp0aSI6Imp0aS1uZXcifQ.c2lnbmF0dXJl_x-9'

/** MCP 端点：界面和管理 API 同源。 */
const endpoint = () => `${window.location.origin}/api/v1/mcp`

/** controller 拒绝时的应答，带着 `what` 和 `field`。 */
function refusal(status: number, code: string, what: string, field: string): Response {
  return new Response(JSON.stringify({ error: { code, message: '原话', what, field } }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** 签发之后列表里多出这一个；应答里带着 JWT。 */
function setup(extra: ApiRoutes = {}): FakeApi {
  const api = fakeApi({
    'GET /mcp/tokens': TOKENS,
    'GET /networks': [NETWORK, OFFICE],
    'POST /mcp/tokens': (call) => {
      const body = call.body as { name: string; scopes: string[]; network?: number; expires_in_secs: number }
      const info = makeMcpToken(4, body.name, {
        jti: 'jti-new',
        scopes: body.scopes,
        network: body.network ?? null,
        created_at: NOW,
        expires_at: NOW + body.expires_in_secs,
      })
      api.use({ 'GET /mcp/tokens': [...TOKENS, info] })
      return { ...info, token: JWT } satisfies CreatedMcpToken
    },
    ...extra,
  })
  return api
}

function render() {
  return renderWithApp(<McpTab />, { route: '/settings/mcp' })
}

type User = ReturnType<typeof userEvent.setup>

async function openDialog(user: User): Promise<HTMLElement> {
  await user.click(await screen.findByRole('button', { name: m.issue }))
  return screen.findByRole('dialog', { name: d.title })
}

const scopeBox = (dialog: HTMLElement, scope: McpScope) =>
  within(dialog).getByRole('checkbox', { name: m.scopeNames[scope] })

/** 浏览器的一个存储里现在放着的全部值。 */
const stored = (storage: Storage) =>
  Array.from({ length: storage.length }, (_, index) => storage.getItem(storage.key(index) ?? ''))

describe('设置里的 MCP 令牌', () => {
  for (const locale of ['zh-CN', 'en'] as const) {
    it(`一行一个令牌：状态、权限、网络的名字、jti；只有还能用的可以撤销（${locale}）`, async () => {
      setLocale(locale, { remember: false })
      setup()
      render()

      const active = await screen.findByTestId('mcp-token-row-1')
      expect(active).toHaveTextContent('claude-code')
      expect(active).toHaveTextContent(m.state.active)
      expect(active).toHaveTextContent('read')
      expect(active).toHaveTextContent('nodes:enroll')
      expect(active).toHaveTextContent(m.anyNetwork)
      expect(active).toHaveTextContent('jti-claude')
      expect(active).toHaveTextContent(m.remaining(t.time.days(30)))
      expect(within(active).getByRole('button', { name: m.revokeFor('claude-code') })).toBeVisible()

      // 网络写名字，点了去那个网络；这个界面不认识的权限原样写出来。
      const expired = screen.getByTestId('mcp-token-row-2')
      expect(expired).toHaveTextContent(m.state.expired)
      expect(expired).toHaveTextContent('future:scope')
      expect(within(expired).getByRole('link', { name: 'office' })).toHaveAttribute('href', networkPath(2))
      expect(within(expired).queryByRole('button', { name: m.revokeFor('cursor') })).not.toBeInTheDocument()

      const revoked = screen.getByTestId('mcp-token-row-3')
      expect(revoked).toHaveTextContent(m.state.revoked)
      expect(within(revoked).getByRole('link', { name: 'home' })).toHaveAttribute('href', networkPath(1))
      expect(within(revoked).queryByRole('button', { name: m.revokeFor('codex') })).not.toBeInTheDocument()
    })
  }

  it('写出 Agent 要连的端点：管理 API 的地址加 /api/v1/mcp', async () => {
    setup()
    render()
    expect(await screen.findByTestId('mcp-endpoint')).toHaveTextContent(endpoint())
    expect(endpoint()).toMatch(/^https?:\/\/[^/]+\/api\/v1\/mcp$/)
    expect(screen.getByText(m.endpointBody)).toBeVisible()
    expect(screen.getByText(m.body)).toBeVisible()
  })

  it('一个令牌也没有：说一句，下面就是签发的按钮', async () => {
    setup({ 'GET /mcp/tokens': [] })
    render()
    expect(await screen.findByRole('heading', { name: m.emptyTitle })).toBeVisible()
    expect(screen.getAllByRole('button', { name: m.issue })).toHaveLength(1)
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('比界面新的 controller 报来的状态原样写出来，不能撤销', async () => {
    setup({ 'GET /mcp/tokens': [{ ...makeMcpToken(9, 'later'), state: 'suspended' }] })
    render()
    const row = await screen.findByTestId('mcp-token-row-9')
    expect(row).toHaveTextContent('suspended')
    // 这一行里只剩复制 jti 的那一个按钮。
    expect(within(row).getAllByRole('button')).toEqual([
      within(row).getByRole('button', { name: t.common.copyValue('jti-9') }),
    ])
  })

  it('签发：交出名字、权限和有效期；JWT 和加进 Claude Code 的命令只显示这一次', async () => {
    const user = userEvent.setup()
    const api = setup()
    const { client } = render()
    const dialog = await openDialog(user)

    // 新开的表单只勾着只读，有效期 30 天。
    expect(scopeBox(dialog, 'read')).toBeChecked()
    expect(scopeBox(dialog, 'nodes:enroll')).not.toBeChecked()
    expect(scopeBox(dialog, 'nodes:enroll')).toHaveAccessibleDescription(m.scopeHints['nodes:enroll'])
    await user.type(within(dialog).getByRole('textbox', { name: d.name }), ' claude-code ')
    await user.click(scopeBox(dialog, 'nodes:enroll'))
    await user.selectOptions(within(dialog).getByRole('combobox', { name: d.lifetime }), t.time.days(7))
    await user.click(within(dialog).getByRole('button', { name: d.submit }))

    const issued = await screen.findByRole('dialog', { name: m.issued.title })
    // 不限网络的请求里不写 network。
    expect(api.callsTo('POST /mcp/tokens').map((call) => call.body)).toEqual([
      { name: 'claude-code', scopes: ['read', 'nodes:enroll'], expires_in_secs: 7 * DAY },
    ])
    expect(within(issued).getByTestId('mcp-token').textContent).toBe(JWT)
    expect(within(issued).getByTestId('mcp-claude-command').textContent).toBe(
      `claude mcp add --transport http ice3tier ${endpoint()} --header "Authorization: Bearer ${JWT}"`,
    )
    expect(within(issued).getByText(m.issued.shownOnce)).toBeVisible()
    expect(within(issued).getByText(m.issued.otherClients(endpoint()))).toBeVisible()
    expect(within(issued).getByRole('button', { name: m.issued.copyToken })).toBeVisible()
    expect(within(issued).getByRole('button', { name: m.issued.copyCommand })).toBeVisible()
    // 没有右上角的叉：只能点"完成"。
    expect(within(issued).queryByRole('button', { name: t.common.close })).not.toBeInTheDocument()

    // JWT 只在这个对话框里：不在查询库的缓存里，不在浏览器的存储里。
    const cached = JSON.stringify([
      client
        .getQueryCache()
        .getAll()
        .map((query) => query.state.data),
      client
        .getMutationCache()
        .getAll()
        .map((mutation) => [mutation.state.data, mutation.state.variables]),
    ])
    expect(cached).not.toContain(JWT)
    expect(cached).toContain('jti-new')
    expect(JSON.stringify([stored(window.localStorage), stored(window.sessionStorage)])).not.toContain(JWT)

    await user.click(within(issued).getByRole('button', { name: t.common.done }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.body).not.toHaveTextContent(JWT)
    // 列表里多出刚签发的这一个。
    expect(await screen.findByTestId('mcp-token-row-4')).toHaveTextContent('jti-new')

    // 再打开是一份新的表单，上一次的令牌不会留着。
    const again = await openDialog(user)
    expect(within(again).getByRole('textbox', { name: d.name })).toHaveValue('')
    expect(document.body).not.toHaveTextContent(JWT)
  })

  it('选了网络：管整个 controller 的两项权限不能勾，勾着的去掉，那两行写原因', async () => {
    const user = userEvent.setup()
    const api = setup()
    render()
    const dialog = await openDialog(user)

    await user.click(scopeBox(dialog, 'updates:write'))
    await user.click(scopeBox(dialog, 'config:write'))
    expect(scopeBox(dialog, 'updates:write')).toBeChecked()
    expect(within(dialog).queryByText(d.globalOnly)).not.toBeInTheDocument()

    await user.selectOptions(within(dialog).getByRole('combobox', { name: d.network }), 'home')
    for (const scope of ['updates:write', 'networks:write'] as const) {
      expect(scopeBox(dialog, scope)).toBeDisabled()
      expect(scopeBox(dialog, scope)).not.toBeChecked()
      expect(scopeBox(dialog, scope)).toHaveAccessibleDescription(d.globalOnly)
    }
    // 别的不受影响。
    expect(scopeBox(dialog, 'config:write')).toBeEnabled()
    expect(scopeBox(dialog, 'config:write')).toBeChecked()

    await user.type(within(dialog).getByRole('textbox', { name: d.name }), 'cursor')
    await user.click(within(dialog).getByRole('button', { name: d.submit }))
    const issued = await screen.findByRole('dialog', { name: m.issued.title })
    expect(api.callsTo('POST /mcp/tokens')[0]?.body).toEqual({
      name: 'cursor',
      scopes: ['read', 'config:write'],
      network: 1,
      expires_in_secs: 30 * DAY,
    })
    expect(issued).toHaveTextContent('home')
  })

  it('改回不限网络：那两项又可以勾', async () => {
    const user = userEvent.setup()
    setup()
    render()
    const dialog = await openDialog(user)
    const network = within(dialog).getByRole('combobox', { name: d.network })
    await user.selectOptions(network, 'office')
    expect(scopeBox(dialog, 'networks:write')).toBeDisabled()
    await user.selectOptions(network, m.anyNetwork)
    expect(scopeBox(dialog, 'networks:write')).toBeEnabled()
    expect(scopeBox(dialog, 'networks:write')).toHaveAccessibleDescription(m.scopeHints['networks:write'])
  })

  it('提交之前：名字不能空，至少一项权限；不合格的不发请求', async () => {
    const user = userEvent.setup()
    const api = setup()
    render()
    const dialog = await openDialog(user)
    await user.click(scopeBox(dialog, 'read'))
    await user.click(within(dialog).getByRole('button', { name: d.submit }))

    expect(within(dialog).getByRole('textbox', { name: d.name })).toHaveAccessibleDescription(
      new RegExp(t.validate.titleRequired),
    )
    expect(within(dialog).getByRole('group', { name: d.scopes })).toHaveAccessibleDescription(m.errors.scopesEmpty)
    expect(api.callsTo('POST /mcp/tokens')).toHaveLength(0)

    await user.type(within(dialog).getByRole('textbox', { name: d.name }), 'x'.repeat(65))
    expect(within(dialog).getByRole('textbox', { name: d.name })).toHaveAccessibleDescription(
      new RegExp(t.validate.titleTooLong(64)),
    )
  })

  it('controller 拒绝时写在它说的那一项下面：网络没有了，写在网络下面', async () => {
    const user = userEvent.setup()
    setup({ 'POST /mcp/tokens': () => refusal(404, 'not_found', 'network', 'network') })
    render()
    const dialog = await openDialog(user)
    await user.type(within(dialog).getByRole('textbox', { name: d.name }), 'cursor')
    await user.selectOptions(within(dialog).getByRole('combobox', { name: d.network }), 'office')
    await user.click(within(dialog).getByRole('button', { name: d.submit }))

    const network = within(dialog).getByRole('combobox', { name: d.network })
    await waitFor(() => expect(network).toHaveAccessibleDescription(new RegExp(m.errors.networkGone)))
    expect(network).toBeInvalid()
    // 只写在那一项下面，表单底部不再重复；也没有弹通知。
    expect(within(dialog).getAllByRole('alert')).toHaveLength(1)
    expect(screen.queryByRole('dialog', { name: m.issued.title })).not.toBeInTheDocument()

    // 改了那一项，错误就撤掉。
    await user.selectOptions(network, m.anyNetwork)
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument()
  })

  it.each([
    ['scopes', 'not_allowed', () => m.errors.scopesGlobal],
    ['scopes', 'malformed', () => m.errors.scopesUnknown],
    ['scopes', 'empty', () => m.errors.scopesEmpty],
  ] as const)('controller 说权限不对（%s / %s）：写在权限下面', async (field, what, message) => {
    const user = userEvent.setup()
    setup({ 'POST /mcp/tokens': () => refusal(400, 'invalid_request', what, field) })
    render()
    const dialog = await openDialog(user)
    await user.type(within(dialog).getByRole('textbox', { name: d.name }), 'cursor')
    await user.click(within(dialog).getByRole('button', { name: d.submit }))
    const group = within(dialog).getByRole('group', { name: d.scopes })
    await waitFor(() => expect(group).toHaveAccessibleDescription(message()))
  })

  it('controller 说名字、有效期不对：各写在自己那一项下面；说不清是哪一项的写在表单底部', async () => {
    const user = userEvent.setup()
    const api = setup({ 'POST /mcp/tokens': () => refusal(400, 'invalid_request', 'malformed', 'name') })
    render()
    const dialog = await openDialog(user)
    const name = within(dialog).getByRole('textbox', { name: d.name })
    const submit = within(dialog).getByRole('button', { name: d.submit })
    await user.type(name, 'cursor')
    await user.click(submit)
    await waitFor(() => expect(name).toHaveAccessibleDescription(new RegExp(m.errors.nameMalformed(64))))

    api.use({ 'POST /mcp/tokens': () => refusal(400, 'invalid_request', 'out_of_range', 'expires_in_secs') })
    await user.click(submit)
    const lifetime = within(dialog).getByRole('combobox', { name: d.lifetime })
    await waitFor(() => expect(lifetime).toHaveAccessibleDescription(new RegExp(m.errors.lifetime(90))))
    expect(name).not.toBeInvalid()

    api.use({
      'POST /mcp/tokens': () =>
        new Response(JSON.stringify({ error: { code: 'internal', message: '数据库忙' } }), { status: 500 }),
    })
    await user.click(submit)
    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent(t.errors.codes.internal)
    expect(alert).toHaveTextContent('数据库忙')
    expect(lifetime).not.toBeInvalid()
  })

  it('撤销：先问一句，说清后果；确认了才调接口，列表跟着变', async () => {
    const user = userEvent.setup()
    const api = setup({
      'POST /mcp/tokens/1/revoke': () => {
        const revoked = { ...TOKENS[0], revoked_at: NOW, state: 'revoked' }
        api.use({ 'GET /mcp/tokens': [revoked, ...TOKENS.slice(1)] })
        return revoked
      },
    })
    render()
    const row = await screen.findByTestId('mcp-token-row-1')

    await user.click(within(row).getByRole('button', { name: m.revokeFor('claude-code') }))
    const confirm = await screen.findByRole('alertdialog', { name: m.revokeTitle('claude-code') })
    expect(confirm).toHaveTextContent(m.revokeBody)
    await user.click(within(confirm).getByRole('button', { name: t.common.cancel }))
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
    expect(api.callsTo('POST /mcp/tokens/1/revoke')).toHaveLength(0)

    await user.click(within(row).getByRole('button', { name: m.revokeFor('claude-code') }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: m.revokeConfirm }))
    expect(await screen.findByText(m.revoked('claude-code'))).toBeVisible()
    expect(api.callsTo('POST /mcp/tokens/1/revoke')).toHaveLength(1)
    await waitFor(() => expect(screen.getByTestId('mcp-token-row-1')).toHaveTextContent(m.state.revoked))
    expect(screen.queryByRole('button', { name: m.revokeFor('claude-code') })).not.toBeInTheDocument()
  })

  it('列表取不到：说一句，可以重试', async () => {
    const user = userEvent.setup()
    const api = setup({
      'GET /mcp/tokens': () =>
        new Response(JSON.stringify({ error: { code: 'internal', message: '数据库忙' } }), { status: 500 }),
    })
    render()
    expect(await screen.findByRole('heading', { name: m.loadFailed })).toBeVisible()
    api.use({ 'GET /mcp/tokens': TOKENS })
    await user.click(screen.getByRole('button', { name: t.common.retry }))
    expect(await screen.findByTestId('mcp-token-row-1')).toBeVisible()
  })

  it('是设置里的一个分区，排在「登录」后面，有自己的地址', async () => {
    setup({ 'GET /update': makeOverview() })
    renderWithApp(
      <Routes>
        <Route path="settings/:tab" element={<SettingsPage />} />
      </Routes>,
      { route: '/settings/mcp' },
    )
    expect(await screen.findByTestId('mcp-tab')).toBeVisible()
    const links = within(screen.getByRole('navigation', { name: t.settings.tabsLabel })).getAllByRole('link')
    expect(links.map((link) => link.textContent).slice(0, 2)).toEqual([t.settings.tabSession, t.settings.tabMcp])
    expect(links[1]).toHaveAttribute('href', '/settings/mcp')
    expect(links[1]).toHaveAttribute('aria-current', 'page')
  })
})
