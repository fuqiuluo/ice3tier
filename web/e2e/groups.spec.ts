import { execFile } from 'node:child_process'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { createServer as createTcpServer } from 'node:net'

import { expect, type Page, test } from '@playwright/test'

import { Controller, type NodeHandle } from './controller'
import { clearToasts, expectToast, goTo, signIn, t } from './helpers'

/**
 * 分组：两个真的跑着的节点，都在本机回环上。gw 上有一个 HTTP 服务，laptop 上一条端口转发通到它，
 * 访问通不通看的是真的经这条转发取到的东西。
 *
 * - 分组页上新建分组；名字的写法不对、和已有的重名（不分大小写），都在名字下面说清。
 * - 在节点页上把节点放进分组：只能从已有的分组里选，输入只是筛选。
 * - 停用默认规则之后转发不通；在两个分组之间写一条规则，转发通了。
 * - 分组改名：规则记的是编号，转发照样通。
 * - 删除分组：确认框里写着它从几个节点上移除、几条规则一起删掉；删掉之后转发又不通了。
 * - 注册令牌带着分组：用它加入的节点就在那个分组里。
 */

const NET = '/networks/1'
const HELLO = 'hello from gw\n'

interface ApiRef {
  id: number
  name: string
}

interface ApiGroup extends ApiRef {
  builtin: boolean
  nodes: ApiRef[]
  rules: ApiRef[]
}

interface ApiNode extends ApiRef {
  groups: ApiRef[]
}

interface ApiRule extends ApiRef {
  enabled: boolean
  src: ApiRef
  dst: ApiRef
}

let controller: Controller
let page: Page
let http: HttpServer
let httpPort = 0
/** laptop 上转发的本机端口。 */
let forwardPort = 0
const nodes = {} as Record<'gw' | 'laptop', { handle: NodeHandle; id: number; name: string }>

function listen(server: HttpServer, host: string): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, host, () => {
      const address = server.address()
      if (address !== null && typeof address === 'object') resolve(address.port)
      else reject(new Error('拿不到端口'))
    })
  })
}

/** 一个现在空闲的端口：占一下就放开。 */
async function freePort(): Promise<number> {
  const server = createTcpServer()
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  await new Promise((resolve) => server.close(resolve))
  return address !== null && typeof address === 'object' ? address.port : 0
}

/** 经 laptop 上的转发取 gw 上的服务，取到什么就返回什么；不通时是空的。异步地等：服务就在这个进程里。 */
function throughForward(): Promise<string> {
  return new Promise((resolve) => {
    execFile(
      'curl',
      ['-s', '-m', '5', '--noproxy', '*', `http://127.0.0.1:${forwardPort}/`],
      { encoding: 'utf8' },
      (_error, stdout) => resolve(stdout),
    )
  })
}

/** 节点收到新的配置要一点时间：等到经转发取到（或者取不到）。 */
async function expectReachable(reachable: boolean): Promise<void> {
  const poll = expect.poll(throughForward, { timeout: 45_000, intervals: [500, 1000, 2000] })
  if (reachable) await poll.toBe(HELLO)
  else await poll.not.toBe(HELLO)
}

async function groupsByName(): Promise<Record<string, ApiGroup>> {
  const list = await controller.api<ApiGroup[]>('GET', `${NET}/groups`)
  return Object.fromEntries(list.map((group) => [group.name, group]))
}

async function apiNode(id: number): Promise<ApiNode | undefined> {
  return (await controller.api<ApiNode[]>('GET', `${NET}/nodes`)).find((node) => node.id === id)
}

test.describe.configure({ mode: 'serial' })

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120_000)
  http = createHttpServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/plain' })
    response.end(HELLO)
  })
  httpPort = await listen(http, '127.0.0.1')
  controller = await Controller.start()
  page = await browser.newPage({ locale: 'zh-CN' })
})

test.afterAll(async () => {
  await page.close()
  await controller.stop()
  http.close()
})

test('准备：gw 和 laptop 跑起来，laptop 上一条转发通到 gw 上的服务', async () => {
  test.setTimeout(120_000)
  await controller.api('POST', '/networks', { name: 'home' })
  const gw = await controller.enroll()
  const laptop = await controller.enroll()
  await controller.api('PATCH', `${NET}/nodes/1`, { name: 'gw' })
  // 端口转发的目标是管理员的开关（0.1.11 起），不是节点的声明。
  await controller.api('PATCH', `${NET}/nodes/1`, { forward_target: true })
  await controller.api('PATCH', `${NET}/nodes/2`, { name: 'laptop' })
  nodes.gw = { handle: gw, id: 1, name: 'gw' }
  nodes.laptop = { handle: laptop, id: 2, name: 'laptop' }
  await controller.run(gw)
  await controller.run(laptop)
  await controller.waitOnline(2)

  forwardPort = await freePort()
  await controller.api('POST', `${NET}/forwards`, {
    name: 'web',
    protocol: 'tcp',
    listen_node: nodes.laptop.id,
    bind: `127.0.0.1:${forwardPort}`,
    target_node: nodes.gw.id,
    target_addr: `127.0.0.1:${httpPort}`,
  })
  // 默认规则 All ⇄ All 开着：通。
  await expectReachable(true)
  await signIn(page, controller)
})

test('分组页：All 在最前面；新建分组，名字的写法不对、重名都在名字下面说清', async () => {
  const g = t.groups
  await goTo(page, t.nav.groups)
  const all = page.getByTestId('group-row-All')
  await expect(all).toContainText(g.builtin)
  // All 不能改名、删除：没有菜单。
  await expect(page.getByRole('button', { name: t.common.actionsFor('All') })).toHaveCount(0)

  await page.getByRole('button', { name: g.create }).click()
  const dialog = page.getByRole('dialog', { name: g.createTitle })
  const name = dialog.getByRole('textbox', { name: g.nameLabel })
  // 写法不对的在这里就拦下，不发请求。
  await name.fill('web servers')
  await dialog.getByRole('button', { name: g.createSubmit }).click()
  await expect(dialog.getByText(t.validate.groupCharset)).toBeVisible()
  expect(Object.keys(await groupsByName())).toEqual(['All'])
  // 和 All 重名（不分大小写）：controller 不答应，按错误码写在名字下面。
  await name.fill('all')
  await dialog.getByRole('button', { name: g.createSubmit }).click()
  await expect(dialog.getByText(t.errors.group.nameTaken)).toBeVisible()

  for (const group of ['servers', 'laptops']) {
    await name.fill(group)
    await dialog.getByRole('button', { name: g.createSubmit }).click()
    await expectToast(page, g.created(group))
    await expect(dialog).toBeHidden()
    // 新建之后接着打开它的成员，就能添加。
    await expect(page.getByTestId(`group-members-${group}`)).toContainText(g.noMembers)
    await page.getByRole('button', { name: t.common.done }).click()
    if (group === 'servers') await page.getByRole('button', { name: g.create }).click()
  }
  expect(Object.keys(await groupsByName())).toEqual(['All', 'laptops', 'servers'])
  await clearToasts(page)
})

test('在节点页上把节点放进分组：只能选已有的', async () => {
  const d = t.nodes.detail
  for (const [node, group] of [
    [nodes.gw, 'servers'],
    [nodes.laptop, 'laptops'],
  ] as const) {
    await page.goto(`${controller.baseUrl}/n/1/nodes/${node.id}`)
    await page.getByRole('combobox', { name: d.groups }).click()
    const search = page.getByRole('textbox', { name: t.groups.picker.search })
    // 搜索只是筛选：没有这个分组时什么也不会新建。
    await search.fill('nope')
    await expect(page.getByText(t.groups.picker.noneFound)).toBeVisible()
    await page.keyboard.press('Enter')
    await search.fill(group.slice(0, 3))
    await page.keyboard.press('Enter')
    await expectToast(page, t.nodes.groupsSaved)
    expect((await apiNode(node.id))?.groups.map((entry) => entry.name)).toEqual([group])
    await clearToasts(page)
  }
  // 输入过的那些字没有变成分组；去分组页的链接就在旁边。
  expect(Object.keys(await groupsByName())).toEqual(['All', 'laptops', 'servers'])
  await expect(page.getByRole('link', { name: t.groups.picker.manage })).toHaveAttribute('href', '/n/1/groups')
})

test('规则写在两个分组之间，访问跟着变', async () => {
  test.setTimeout(120_000)
  // 停用默认规则：没有规则连通它们，转发不通。
  const [defaultRule] = await controller.api<ApiRule[]>('GET', `${NET}/rules`)
  expect(defaultRule).toMatchObject({ src: { name: 'All' }, dst: { name: 'All' } })
  await controller.api('PATCH', `${NET}/rules/${defaultRule?.id ?? 0}`, { enabled: false })
  await expectReachable(false)

  const d = t.access.dialog
  await goTo(page, t.nav.access)
  // 界面上的规则是停用之后的样子，影响才算得对。
  await expect(page.getByRole('switch', { name: t.access.ruleSwitch('default') })).not.toBeChecked()
  await page.getByRole('button', { name: t.access.newRule }).click()
  const dialog = page.getByRole('dialog', { name: d.createTitle })
  await dialog.getByRole('combobox', { name: d.srcLabel }).click()
  await page.getByRole('option', { name: /laptops/ }).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await dialog.getByRole('combobox', { name: d.dstLabel }).click()
  await page.getByRole('option', { name: /servers/ }).click()
  await dialog.getByRole('radio', { name: d.oneWay }).click()
  await expect(page.getByTestId('rule-sentence')).toContainText(
    d.sentenceOneWay(d.nodesOf('laptops', 1), d.nodesOf('servers', 1)),
  )
  await expect(page.getByTestId('rule-impact')).toContainText(d.impactGain(1))
  await dialog.getByLabel(new RegExp(`^${d.nameLabel}`)).fill('web')
  await dialog.getByRole('button', { name: d.submitCreate }).click()
  await expectToast(page, d.created('web'))
  await expectReachable(true)
  await clearToasts(page)
})

test('分组改名：规则记的是编号，照样通', async () => {
  test.setTimeout(90_000)
  const g = t.groups
  await goTo(page, t.nav.groups)
  await page.getByRole('button', { name: t.common.actionsFor('laptops') }).click()
  await page.getByRole('menuitem', { name: g.menuRename }).click()
  const dialog = page.getByRole('dialog', { name: g.renameTitle('laptops') })
  await dialog.getByRole('textbox', { name: g.nameLabel }).fill('Notebooks')
  await dialog.getByRole('button', { name: g.renameSubmit, exact: true }).click()
  await expectToast(page, g.renamed('laptops', 'Notebooks'))
  await expect(page.getByTestId('group-row-Notebooks')).toBeVisible()

  // 规则、节点上写的是新名字；访问没有变。
  const web = (await controller.api<ApiRule[]>('GET', `${NET}/rules`)).find((rule) => rule.name === 'web')
  expect(web?.src.name).toBe('Notebooks')
  expect((await apiNode(nodes.laptop.id))?.groups.map((group) => group.name)).toEqual(['Notebooks'])
  await goTo(page, t.nav.access)
  await expect(page.getByTestId(`rule-row-${web?.id ?? 0}`)).toContainText('Notebooks')
  await expectReachable(true)
  await clearToasts(page)
})

test('删除分组：确认框里写着它从几个节点上移除、几条规则一起删掉；访问随之撤销', async () => {
  test.setTimeout(90_000)
  const g = t.groups
  await goTo(page, t.nav.groups)
  await page.getByRole('button', { name: t.common.actionsFor('Notebooks') }).click()
  await page.getByRole('menuitem', { name: g.menuDelete }).click()
  const question = page.getByRole('alertdialog', { name: g.deleteTitle('Notebooks') })
  await expect(question).toContainText(g.deleteImpact(1, 1) ?? '')
  // 不能撤回：默认焦点在"取消"上。
  await expect(question.getByRole('button', { name: t.common.cancel })).toBeFocused()
  await question.getByRole('button', { name: g.deleteConfirm }).click()
  await expectToast(page, g.deleted('Notebooks'))
  await expect(page.getByTestId('group-row-Notebooks')).toHaveCount(0)

  expect(Object.keys(await groupsByName())).toEqual(['All', 'servers'])
  expect((await controller.api<ApiRule[]>('GET', `${NET}/rules`)).map((rule) => rule.name)).toEqual(['default'])
  expect((await apiNode(nodes.laptop.id))?.groups).toEqual([])
  await expectReachable(false)
  await clearToasts(page)
})

test('注册令牌带着分组：用它加入的节点就在那个分组里', async () => {
  await goTo(page, t.nav.nodes)
  await page.getByRole('button', { name: t.nodes.add }).click()
  const dialog = page.getByRole('dialog', { name: t.addNode.title })
  await dialog.getByRole('button', { name: t.addNode.optionsTitle }).click()
  await dialog.getByRole('combobox', { name: t.addNode.groupsLabel }).click()
  await page.getByRole('textbox', { name: t.groups.picker.search }).fill('serv')
  await page.keyboard.press('Enter')
  await page.keyboard.press('Escape')
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await dialog.getByRole('button', { name: t.addNode.generate }).click()
  const command = page.getByTestId('join-command')
  await expect(command).toHaveText(/^echo i3t-[A-Za-z0-9_-]+ \| sudo i3t join$/)
  const tokens = await controller.api<{ groups: ApiRef[] }[]>('GET', `${NET}/tokens`)
  expect(tokens.map((token) => token.groups.map((group) => group.name))).toEqual([['servers']])

  controller.join((await command.textContent()) ?? '')
  await expect(page.getByTestId('node-joined')).toBeVisible()
  const joined = (await controller.api<ApiNode[]>('GET', `${NET}/nodes`)).find((node) => node.id > nodes.laptop.id)
  expect(joined?.groups.map((group) => group.name)).toEqual(['servers'])
  await dialog.getByRole('button', { name: t.addNode.done }).click()
  await expect(page.getByTestId(`node-row-${joined?.name ?? ''}`)).toContainText('servers')
})
