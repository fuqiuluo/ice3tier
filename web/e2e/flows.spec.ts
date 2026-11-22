import { expect, type Locator, type Page, test } from '@playwright/test'

import { Controller, type NodeHandle } from './controller'
import { en } from '../src/i18n/en'
import { clearToasts, expectToast, goTo, goToAdmin, literal, t } from './helpers'

/**
 * 从一个空的 controller 开始，把主要的流程照着用户的做法走一遍：
 * 登录 → 建网络 → 建分组 → 生成注册令牌、拿到加入命令 → 节点加入 → 编辑节点的分组 → 加规则、关系图跟着变 →
 * 启用出口（节点没有声明时怎么说、声明之后怎么变）→ 签发凭据（只显示一次）→ 建、删端口转发 → 退出。
 *
 * 都是真的：真的 controller，界面给出的那一行加入命令原样交给 shell 执行，节点是真的 `i3t`。
 * 界面上做完一件事，再用管理 API 核对它真的落到了 controller 上。
 */

interface ApiNode {
  id: number
  name: string
  virtual_ip: string
  groups: { id: number; name: string }[]
  online: boolean
  declared: { exit: boolean; relay: boolean; forward: boolean }
  exit: { ports: number[] | null } | null
}

const NET = '/networks/1'

let controller: Controller
let page: Page

/** 两个节点：`server` 是在 servers 分组里、后来做端口转发目标的那个；`laptop` 是后加入的。 */
let server: { handle: NodeHandle; id: number; name: string; ip: string }
let laptop: { handle: NodeHandle; id: number; name: string; ip: string }

async function apiNodes(): Promise<ApiNode[]> {
  return controller.api<ApiNode[]>('GET', `${NET}/nodes`)
}

function joinCommand(): Locator {
  return page.getByTestId('join-command')
}

/** 关系图上的一条规则线。画图的库把线画成带说明文字的一组 SVG。 */
function ruleEdge(label: string, enabled: boolean): Locator {
  const state = enabled ? t.access.graph.edgeEnabled : t.access.graph.edgeDisabled
  return page.getByTestId('group-graph').locator(`[aria-label="${t.access.graph.edgeLabel(label, state)}"]`)
}

/**
 * 下拉里的某个节点。按虚拟 IP 认，不按名字：节点的名字取自主机名，同一台机器上加入的几个节点会叫
 * `host`、`host-2`，一个是另一个的开头。
 */
function nodeOption(node: { ip: string }): Locator {
  return page.getByRole('option', { name: new RegExp(`${node.ip.replaceAll('.', '\\.')}(?!\\d)`) })
}

/** 策略页的两种看法：策略表、关系图。 */
async function showPolicies(view: 'list' | 'graph'): Promise<void> {
  await page.getByRole('radio', { name: view === 'list' ? t.access.viewList : t.access.viewGraph }).click()
}

function groupPoint(group: string, members: number): Locator {
  return page.getByTestId('group-graph').locator(`[aria-label="${t.access.graph.groupNodeLabel(group, members)}"]`)
}

test.describe.configure({ mode: 'serial' })

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120_000)
  controller = await Controller.start()
  console.log(`用的程序：${controller.bins}`)
  const context = await browser.newContext({ locale: 'zh-CN' })
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  page = await context.newPage()
})

test.afterAll(async () => {
  await page.context().close()
  await controller.stop()
})

test('用管理令牌登录', async () => {
  // 没登录时任何地址都落到登录页。
  await page.goto(`${controller.baseUrl}/settings/about`)
  await expect(page).toHaveURL(/\/login\?next=/)
  await expect(page.getByRole('heading', { name: t.signIn.title })).toBeVisible()

  const token = page.getByLabel(t.signIn.tokenLabel, { exact: true })
  await token.fill('not-the-admin-token')
  await page.getByRole('button', { name: t.signIn.submit, exact: true }).click()
  await expect(page.getByRole('alert')).toContainText(t.errors.codes.unauthorized)
  await expect(page).toHaveURL(/\/login/)

  await token.fill(controller.adminToken)
  await page.getByRole('button', { name: t.signIn.submit, exact: true }).click()
  // controller 里还没有网络：先去建第一个。
  await expect(page.getByRole('heading', { name: t.networks.welcomeTitle })).toBeVisible()
})

test('建第一个网络', async () => {
  const name = page.getByLabel(t.networks.nameLabel, { exact: true })
  const cidr = page.getByLabel(t.networks.cidrLabel, { exact: true })
  // 两项都有默认值。
  await expect(name).toHaveValue('home')
  await expect(cidr).toHaveValue('10.66.0.0/16')
  await expect(page.getByText(t.networks.cidrHint)).toBeVisible()

  // 写法不对的，在输入框下面就说，不发请求。
  await name.fill('My Network')
  await expect(page.getByText(t.validate.nameCharset)).toBeVisible()
  await cidr.fill('10.66.0.0/31')
  await expect(page.getByText(t.validate.cidrTooSmall(30))).toBeVisible()
  await page.getByRole('button', { name: t.networks.createSubmit }).click()
  expect(await controller.api<unknown[]>('GET', '/networks')).toHaveLength(0)

  await name.fill('home')
  await cidr.fill('10.66.0.0/16')
  await page.getByRole('button', { name: t.networks.createSubmit }).click()

  // 落在总览页；节点不足两个时它就是引导。
  await expect(page.getByRole('heading', { name: t.overview.guide.title })).toBeVisible()
  await expect(page).toHaveURL(/\/n\/1\/overview$/)
  const networks = await controller.api<{ name: string; cidr: string }[]>('GET', '/networks')
  expect(networks).toMatchObject([{ name: 'home', cidr: '10.66.0.0/16' }])
  // 新网络自带内置分组 All 和默认规则 All ⇄ All。
  const rules = await controller.api<{ src: { name: string }; dst: { name: string }; enabled: boolean }[]>(
    'GET',
    `${NET}/rules`,
  )
  expect(rules).toMatchObject([{ src: { name: 'All' }, dst: { name: 'All' }, enabled: true }])
  await clearToasts(page)
})

test('建两个分组：servers、laptops', async () => {
  const g = t.groups
  await goTo(page, t.nav.groups)
  await expect(page.getByTestId('group-row-All')).toContainText(g.builtin)
  for (const name of ['servers', 'laptops']) {
    await page.getByRole('button', { name: g.create }).click()
    const dialog = page.getByRole('dialog', { name: g.createTitle })
    await dialog.getByRole('textbox', { name: g.nameLabel }).fill(name)
    await dialog.getByRole('button', { name: g.createSubmit }).click()
    await expectToast(page, g.created(name))
    await expect(dialog).toBeHidden()
    // 新建之后接着打开它的成员；这里先不加，关掉。
    await page
      .getByRole('dialog', { name: g.membersOf(name) })
      .getByRole('button', { name: t.common.done })
      .click()
  }
  const groups = await controller.api<{ name: string; builtin: boolean }[]>('GET', `${NET}/groups`)
  expect(groups.map((group) => group.name)).toEqual(['All', 'laptops', 'servers'])
  await clearToasts(page)
})

test('生成注册令牌，拿到加入命令，节点加入后出现在界面上', async () => {
  await goTo(page, t.nav.nodes)
  await expect(page.getByText(t.nodes.emptyTitle)).toBeVisible()
  await page.getByRole('button', { name: t.nodes.add }).click()
  const dialog = page.getByRole('dialog', { name: t.addNode.title })
  await expect(dialog).toBeVisible()

  // 生成之前：命令里是占位符，没有东西可以复制，controller 上也没有令牌。
  await expect(joinCommand()).toHaveText(`echo ${t.addNode.tokenPlaceholder} | sudo i3t join`)
  await expect(dialog.getByRole('button', { name: t.addNode.copyCommand })).toBeDisabled()
  expect(await controller.api<unknown[]>('GET', `${NET}/tokens`)).toHaveLength(0)

  // 分组写在令牌上，只能从已有的里面选；"可以承担"是命令的参数。
  await dialog.getByRole('button', { name: t.addNode.optionsTitle }).click()
  await dialog.getByRole('combobox', { name: t.addNode.groupsLabel }).click()
  await page.getByRole('textbox', { name: t.groups.picker.search }).fill('serv')
  await page.keyboard.press('Enter')
  await page.keyboard.press('Escape')
  await expect(page.getByRole('listbox')).toHaveCount(0)
  const relayBox = dialog.getByRole('checkbox', { name: new RegExp(t.addNode.declareRelay) })
  await relayBox.check()
  await expect(joinCommand()).toHaveText(`echo ${t.addNode.tokenPlaceholder} | sudo i3t join --can-relay`)
  await relayBox.uncheck()
  await expect(joinCommand()).toHaveText(`echo ${t.addNode.tokenPlaceholder} | sudo i3t join`)

  await dialog.getByRole('button', { name: t.addNode.generate }).click()
  await expect(joinCommand()).toHaveText(/^echo i3t-[A-Za-z0-9_-]+ \| sudo i3t join$/)
  await expect(dialog.getByText(t.addNode.shownOnce)).toBeVisible()
  await expect(dialog.getByText(t.addNode.waiting)).toBeVisible()
  const tokens = await controller.api<{ groups: { name: string }[] }[]>('GET', `${NET}/tokens`)
  expect(tokens).toMatchObject([{ groups: [{ name: 'servers' }] }])

  // 复制出去的就是屏幕上的那一行。
  await dialog.getByRole('button', { name: t.addNode.copyCommand }).click()
  const command = (await joinCommand().textContent()) ?? ''
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(command)

  // 在"那台机器"上执行它。
  const handle = controller.join(command)

  // 不用刷新：等待区自己变成结果。
  await expect(page.getByTestId('node-joined')).toContainText('10.66.0.1')
  const [joined] = await apiNodes()
  if (joined === undefined) throw new Error('controller 上没有节点')
  expect(joined).toMatchObject({
    virtual_ip: '10.66.0.1',
    groups: [{ name: 'servers' }],
    declared: { exit: false, relay: false },
    forward_target: false,
  })
  server = { handle, id: joined.id, name: joined.name, ip: joined.virtual_ip }
  await expect(page.getByTestId('node-joined')).toContainText(t.addNode.joined(server.name, server.ip))
  // 令牌只能用一次。
  expect(await controller.api<unknown[]>('GET', `${NET}/tokens`)).toHaveLength(0)

  await dialog.getByRole('button', { name: t.addNode.done }).click()
  await expect(dialog).toBeHidden()
  const row = page.getByTestId(`node-row-${server.name}`)
  await expect(row).toBeVisible()
  await expect(row).toContainText('10.66.0.1')
  await expect(row).toContainText('servers')
})

test('令牌只在「添加节点」里：不打算用了就吊销；关掉对话框后复制走的命令照样能用', async () => {
  await goTo(page, t.nav.nodes)
  await page.getByRole('button', { name: t.nodes.add }).click()
  const dialog = page.getByRole('dialog', { name: t.addNode.title })

  // 生成了又不用：吊销之后 controller 上就没有它了，对话框回到生成之前。
  await dialog.getByRole('button', { name: t.addNode.generate }).click()
  await expect(joinCommand()).toHaveText(/^echo i3t-[A-Za-z0-9_-]+ \| sudo i3t join$/)
  await dialog.getByRole('button', { name: t.addNode.revoke, exact: true }).click()
  await expect(joinCommand()).toHaveText(`echo ${t.addNode.tokenPlaceholder} | sudo i3t join`)
  expect(await controller.api<unknown[]>('GET', `${NET}/tokens`)).toHaveLength(0)

  await dialog.getByRole('button', { name: t.addNode.generate }).click()
  await expect(joinCommand()).toHaveText(/^echo i3t-[A-Za-z0-9_-]+ \| sudo i3t join$/)
  const command = (await joinCommand().textContent()) ?? ''
  const secret = command.split(' ')[1] ?? ''

  // 令牌还没用掉：按 Esc 关不掉，点"完成"要先问一句。
  await page.keyboard.press('Escape')
  await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: t.addNode.done }).click()
  const question = page.getByRole('alertdialog', { name: t.addNode.closeWhileWaitingTitle })
  await expect(question).toBeVisible()
  await question.getByRole('button', { name: t.addNode.closeWhileWaitingConfirm, exact: true }).click()
  await expect(dialog).toBeHidden()

  // 令牌还在 controller 上，它的文本界面上哪里都查不回来。
  expect(await controller.api<unknown[]>('GET', `${NET}/tokens`)).toHaveLength(1)
  await expect(page.getByText(secret)).toHaveCount(0)

  // 复制走的命令在关掉对话框之后仍然有效。
  const handle = controller.join(command)
  const joined = (await apiNodes()).find((node) => node.id !== server.id)
  if (joined === undefined) throw new Error('第二个节点没有加入')
  laptop = { handle, id: joined.id, name: joined.name, ip: joined.virtual_ip }

  // 这个节点是在界面之外加入的（对话框已经关了）：节点列表靠轮询发现它，周期是 10 秒。
  await expect(page.getByTestId(`node-row-${laptop.name}`)).toBeVisible({ timeout: 20_000 })
  expect(await controller.api<unknown[]>('GET', `${NET}/tokens`)).toHaveLength(0)
})

test('在节点列表上编辑节点的分组：只能选已有的', async () => {
  await goTo(page, t.nav.nodes)
  const row = page.getByTestId(`node-row-${laptop.name}`)
  await expect(row.getByText(t.nodes.addGroups)).toBeVisible()
  await row.getByRole('button', { name: t.nodes.editGroupsOf(laptop.name) }).click()

  const dialog = page.getByRole('dialog', { name: t.nodes.groupsTitle(laptop.name) })
  await dialog.getByRole('combobox').click()
  const search = page.getByRole('textbox', { name: t.groups.picker.search })
  // 搜索只是筛选：没有这个分组时什么也不会新建。
  await search.fill('nope')
  await expect(page.getByText(t.groups.picker.noneFound)).toBeVisible()
  await page.keyboard.press('Enter')

  // 勾上立即生效，不用点保存。
  await search.fill('lap')
  await page.keyboard.press('Enter')
  await expectToast(page, t.nodes.groupsSaved)
  await page.keyboard.press('Escape')
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await expect(dialog.getByRole('button', { name: t.groups.picker.remove('laptops') })).toBeVisible()
  await dialog.getByRole('button', { name: t.nodes.groupsDone }).click()

  await expect(row).toContainText('laptops')
  const node = (await apiNodes()).find((candidate) => candidate.id === laptop.id)
  expect(node?.groups.map((group) => group.name)).toEqual(['laptops'])
  const groups = await controller.api<{ id: number; name: string }[]>('GET', `${NET}/groups`)
  expect(groups).toHaveLength(3)
  await clearToasts(page)

  // 按分组筛选：只剩它。筛选写在地址里，写的是分组的编号。
  const laptops = groups.find((group) => group.name === 'laptops')?.id ?? 0
  await page.getByRole('button', { name: t.nodes.filter }).click()
  await page.getByRole('checkbox', { name: 'laptops' }).check()
  await page.keyboard.press('Escape')
  await expect(page.getByTestId(`node-row-${server.name}`)).toBeHidden()
  await expect(row).toBeVisible()
  await expect(page).toHaveURL(new RegExp(`[?&]group=${laptops}(?!\\d)`))
  await page.getByRole('button', { name: t.nodes.clearAll }).click()
  await expect(page.getByTestId(`node-row-${server.name}`)).toBeVisible()
})

test('加一条策略，关系图跟着变；停用默认策略后按分组收紧', async () => {
  await goTo(page, t.nav.access)
  await expect(page.getByRole('switch', { name: t.access.ruleSwitch('default') })).toBeChecked()
  await showPolicies('graph')
  await expect(page.getByTestId('group-graph')).toBeVisible()
  // 现在：只有默认策略 All ⇄ All，左右各一张 All，一根线；servers、laptops 还没有策略，写在角上。
  await expect(groupPoint('All', 2)).toHaveCount(2)
  await expect(groupPoint('servers', 1)).toHaveCount(0)
  await expect(page.getByText(t.access.graph.unusedGroups(`laptops${t.common.listSeparator}servers`))).toBeVisible()
  await expect(ruleEdge('default', true)).toHaveCount(1)
  await expect(page.getByTestId('group-graph').locator('.react-flow__edge')).toHaveCount(1)
  await showPolicies('list')

  const d = t.access.dialog
  await page.getByRole('button', { name: t.access.newRule }).click()
  const dialog = page.getByRole('dialog', { name: d.createTitle })
  await dialog.getByRole('combobox', { name: d.srcLabel }).click()
  await page.getByRole('option', { name: /laptops/ }).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await dialog.getByRole('combobox', { name: d.dstLabel }).click()
  await page.getByRole('option', { name: /servers/ }).click()
  // 一句话说出规则的意思，随输入变化。
  const laptops = d.nodesOf('laptops', 1)
  const servers = d.nodesOf('servers', 1)
  await expect(page.getByTestId('rule-sentence')).toContainText(d.sentenceBoth(laptops, servers))
  await dialog.getByRole('radio', { name: d.oneWay }).click()
  await expect(page.getByTestId('rule-sentence')).toContainText(d.sentenceOneWay(laptops, servers))
  // 默认规则还开着，所以这条规则现在不改变谁能访问谁。
  await expect(page.getByTestId('rule-impact')).toContainText(d.impactNone)
  await dialog.getByLabel(new RegExp(`^${d.nameLabel}`)).fill('ssh')
  await dialog.getByRole('button', { name: d.submitCreate }).click()
  await expectToast(page, d.created('ssh'))
  await expect(dialog).toBeHidden()

  // 列表里多了一行，图上多了一条线。
  const rules = await controller.api<
    { id: number; name: string; src: { name: string }; dst: { name: string }; direction: string }[]
  >('GET', `${NET}/rules`)
  const ssh = rules.find((rule) => rule.name === 'ssh')
  expect(ssh).toMatchObject({ src: { name: 'laptops' }, dst: { name: 'servers' }, direction: 'one_way' })
  await expect(page.getByTestId(`rule-row-${ssh?.id ?? 0}`)).toBeVisible()
  await showPolicies('graph')
  await expect(ruleEdge('ssh', true)).toHaveCount(1)
  // laptops 在左栏，servers 在右栏。
  await expect(groupPoint('laptops', 1)).toHaveCount(1)
  await expect(groupPoint('servers', 1)).toHaveCount(1)
  await expect(page.getByTestId('group-graph').locator('.react-flow__edge')).toHaveCount(2)
  await showPolicies('list')
  // 界面上说出来：默认规则开着时别的规则不起限制作用。
  await expect(page.getByText(t.access.allOpenNotice)).toBeVisible()
  await clearToasts(page)

  // 停用默认规则。还有 ssh 连着这两个节点，但少了一个方向，所以要确认。
  await page.getByRole('switch', { name: t.access.ruleSwitch('default') }).click()
  const question = page.getByRole('alertdialog', { name: t.access.disableTitle('default') })
  await expect(question).toContainText(t.access.lossBody(1))
  await question.getByRole('button', { name: t.access.disableConfirm }).click()
  await expectToast(page, t.access.disabledToast('default'))
  await showPolicies('graph')
  await expect(ruleEdge('default', false)).toHaveCount(1)
  await expect(ruleEdge('default', true)).toHaveCount(0)
  await expect(page.getByText(t.access.allOpenNotice)).toHaveCount(0)
  await clearToasts(page)

  // 访问检查用文字说出同一件事：单向。
  const c = t.access.checker
  await page.getByRole('button', { name: t.access.check }).click()
  const check = page.getByTestId('access-check')
  await check.getByRole('combobox', { name: c.from }).click()
  await nodeOption(laptop).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await check.getByRole('combobox', { name: c.to }).click()
  await nodeOption(server).click()
  await expect(page.getByTestId(`check-${laptop.name}-${server.name}`)).toContainText(c.allowed)
  await expect(page.getByTestId(`check-${laptop.name}-${server.name}`)).toContainText(c.byRules('ssh'))
  await expect(page.getByTestId(`check-${server.name}-${laptop.name}`)).toContainText(c.denied)
  await check.getByRole('button', { name: t.common.close }).click()
  await expect(check).toHaveCount(0)

  // 按节点看：laptop 能访问 server，没有谁能访问 laptop。
  await page.getByRole('radio', { name: t.access.graph.byNode }).click()
  await page.getByRole('combobox', { name: t.access.graph.nodePickLabel, exact: true }).click()
  await nodeOption(laptop).click()
  const nodeGraph = page.getByTestId('node-graph')
  await expect(nodeGraph.getByText(laptop.name, { exact: true })).toBeVisible()
  await expect(nodeGraph.getByText(server.name, { exact: true })).toHaveCount(1)
  await page.getByRole('radio', { name: t.access.graph.byGroup }).click()
})

test('启用出口：节点没有声明时说明原因和要执行的命令，声明一到开关自己变为可用', async () => {
  // controller 自己也不答应（界面上的置灰不是唯一的一道关）。
  const refused = await fetch(`${controller.baseUrl}/api/v1${NET}/nodes/${server.id}/exit`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${controller.adminToken}`, 'Content-Type': 'application/json' },
    body: '{}',
  })
  expect(refused.status).toBe(409)
  expect(((await refused.json()) as { error: { code: string } }).error.code).toBe('not_declared')

  // 节点详情页：开关是灰的，旁边写着原因；"怎么声明"点开是要在那台机器上执行的命令。
  await goTo(page, t.nav.nodes)
  await page.getByRole('link', { name: server.name, exact: true }).click()
  await page.getByRole('tab', { name: t.nodes.detail.tabExit }).click()
  const exitRow = page.getByTestId('capability-exit')
  const exitSwitch = exitRow.getByRole('switch', { name: t.nodes.detail.exitSwitch(server.name) })
  await expect(exitSwitch).toBeDisabled()
  await expect(page.getByTestId('not-declared-exit')).toContainText(t.declare.notDeclared(server.name))
  await exitRow.getByRole('button', { name: t.declare.howTo }).click()
  await expect(exitRow.getByText(t.declare.step1(server.name))).toBeVisible()
  await expect(exitRow.getByTestId('declare-command')).toHaveText('i3t set can-exit on')
  await expect(exitRow.getByText(t.declare.waiting)).toBeVisible()

  // 在那台机器上照着做：声明，然后把 i3t 跑起来。
  controller.set(server.handle, 'can-exit', true)
  await controller.run(server.handle)

  // 不用刷新：声明一到，说明自己收起，开关变为可用。
  await expect(exitSwitch).toBeEnabled({ timeout: 30_000 })
  await expect(page.getByTestId('not-declared-exit')).toHaveCount(0)
  await expect(exitRow.getByTestId('declare-command')).toHaveCount(0)

  // 打开就按默认值启用，没有对话框；设置平铺在卡片里，端口限制是其中一行，默认关着。
  await exitSwitch.click()
  await expectToast(page, t.nodes.detail.exitEnabledToast(server.name))
  await expect(exitSwitch).toBeChecked()
  const portsCard = page.getByTestId('exit-ports')
  const portsSwitch = portsCard.getByRole('switch', { name: t.nodes.detail.exitPortsSwitch(server.name) })
  await expect(portsSwitch).not.toBeChecked()
  await expect(portsCard.getByRole('textbox', { name: t.nodes.detail.exitPortsAdd })).toHaveCount(0)
  await clearToasts(page)
  // 打开端口限制、输入一个端口回车、再点一个常用端口：每次都马上保存；关上：又不限了。
  await portsSwitch.click()
  await portsCard.getByRole('textbox', { name: t.nodes.detail.exitPortsAdd }).fill('8443')
  await page.keyboard.press('Enter')
  await expectToast(page, t.nodes.detail.exitSavedToast)
  await clearToasts(page)
  await portsCard.getByRole('button', { name: /^443/ }).click()
  await expectToast(page, t.nodes.detail.exitSavedToast)
  await expect
    .poll(async () => (await apiNodes()).find((candidate) => candidate.id === server.id)?.exit?.ports)
    .toEqual([443, 8443])
  await expect(portsCard.getByRole('list', { name: t.nodes.detail.exitFormPorts })).toContainText('8443')
  await clearToasts(page)
  await portsSwitch.click()
  await expectToast(page, t.nodes.detail.exitSavedToast)
  // 用量卡片上写着还没有代理经这里出去：代理在代理页里建，用户名不再选出口。
  await expect(page.getByTestId('exit-proxies')).toContainText(t.nodes.detail.exitProxies(0))
  const node = (await apiNodes()).find((candidate) => candidate.id === server.id)
  expect(node?.exit).toMatchObject({ ports: null })
  await clearToasts(page)

  // 节点列表按"出口"筛：只剩它。
  await page.goto(`${controller.baseUrl}/n/1/nodes?role=exit`)
  await expect(page.getByTestId(`node-row-${server.name}`)).toBeVisible()
  await expect(page.locator('[data-testid^="node-row-"]')).toHaveCount(1)
})

test('新建端口转发，再删除', async () => {
  await goTo(page, t.nav.forwards)
  const f = t.forwards
  const d = f.dialog
  await expect(page.getByText(f.emptyTitle)).toBeVisible()
  await page.getByRole('button', { name: f.create }).first().click()
  const dialog = page.getByRole('dialog', { name: d.createTitle })
  const listenSide = dialog.getByRole('group', { name: d.listenSide })
  const targetSide = dialog.getByRole('group', { name: d.targetSide })

  await listenSide.getByRole('combobox', { name: d.node }).click()
  await nodeOption(laptop).click()
  // 等第一个下拉收起来再开第二个：收起的动画期间两个列表同时在页面上，选项会认重。
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await targetSide.getByRole('combobox', { name: d.node }).click()
  await nodeOption(server).click()
  // 目标还没打开端口转发：对话框里就能打开，不用去节点上声明。
  await expect(targetSide.getByText(d.targetOff(server.name))).toBeVisible()
  await targetSide.getByRole('button', { name: d.targetTurnOn }).click()
  await expectToast(page, t.nodes.detail.forwardOnToast(server.name))
  await expect(targetSide.getByText(d.targetOff(server.name))).toBeHidden()
  // 即时检查：转发不绕过访问规则。laptop → server 由刚才那条规则允许。
  await expect(page.getByTestId('forward-check')).toContainText(d.checkAllowed(laptop.name, server.name, 'ssh'))

  // 端口写错了，在输入框下面说。
  await listenSide.getByLabel(d.port, { exact: true }).fill('70000')
  await targetSide.getByLabel(d.targetPort, { exact: true }).fill('80')
  await dialog.getByLabel(new RegExp(`^${d.name}`)).fill('web')
  await dialog.getByRole('button', { name: d.submitCreate }).click()
  await expect(listenSide.getByText(t.validate.portFormat)).toBeVisible()
  expect(await controller.api<unknown[]>('GET', `${NET}/forwards`)).toHaveLength(0)

  await listenSide.getByLabel(d.port, { exact: true }).fill('8080')
  await dialog.getByRole('button', { name: d.submitCreate }).click()
  await expect(dialog).toBeHidden()
  await expectToast(page, d.created(laptop.name, '127.0.0.1:8080'))

  const row = page.getByTestId('forward-row-web')
  await expect(row).toBeVisible()
  await expect(row).toContainText(laptop.name)
  await expect(row).toContainText('127.0.0.1:8080')
  await expect(row).toContainText(server.name)
  await expect(row).toContainText('127.0.0.1:80')
  await expect(row).toContainText('TCP')
  const forwards = await controller.api<Record<string, unknown>[]>('GET', `${NET}/forwards`)
  expect(forwards).toMatchObject([
    {
      name: 'web',
      protocol: 'tcp',
      listen_node: laptop.id,
      bind: '127.0.0.1:8080',
      target_node: server.id,
      target_addr: '127.0.0.1:80',
      enabled: true,
    },
  ])
  await clearToasts(page)

  // 目标节点的"端口转发"标签页里列着指向它的这条转发。
  await row.getByRole('link', { name: new RegExp(`${literal(server.name)}$`) }).click()
  await page.getByRole('tab', { name: t.nodes.detail.tabForward }).click()
  await expect(page.getByTestId('capability-forward').getByText('127.0.0.1:8080')).toBeVisible()

  // 删除要确认，确认框里写明后果。
  await goTo(page, t.nav.forwards)
  await page.getByRole('button', { name: t.common.actionsFor('web') }).click()
  await page.getByRole('menuitem', { name: f.menuDelete }).click()
  const question = page.getByRole('alertdialog', { name: f.deleteTitle('web') })
  await expect(question).toContainText(f.deleteBody(laptop.name, '127.0.0.1:8080'))
  // 先取消：什么都没变。
  await question.getByRole('button', { name: t.common.cancel, exact: true }).click()
  await expect(page.getByTestId('forward-row-web')).toBeVisible()
  expect(await controller.api<unknown[]>('GET', `${NET}/forwards`)).toHaveLength(1)

  await page.getByRole('button', { name: t.common.actionsFor('web') }).click()
  await page.getByRole('menuitem', { name: f.menuDelete }).click()
  await question.getByRole('button', { name: f.deleteConfirm }).click()
  await expectToast(page, f.deleted('web'))
  await expect(page.getByTestId('forward-row-web')).toHaveCount(0)
  await expect(page.getByText(f.emptyTitle)).toBeVisible()
  expect(await controller.api<unknown[]>('GET', `${NET}/forwards`)).toHaveLength(0)
  await clearToasts(page)
})

test('换语言：顶栏的语言菜单里换成英文，就地重新渲染，刷新后还是英文；再换回中文', async () => {
  await goTo(page, t.nav.nodes)
  const search = page.getByRole('searchbox')
  await search.fill(server.name.slice(0, 3))
  await expect(page).toHaveURL(/q=/)

  await page.getByRole('button', { name: new RegExp(`^${literal(t.common.language)}`) }).click()
  await page.getByRole('menuitemradio', { name: 'English' }).click()

  // 不刷新：搜索框里的字还在，标题、侧栏、<html lang>、标签页标题都换了。
  await expect(page.getByRole('heading', { level: 1, name: en.nodes.title })).toBeVisible()
  await expect(
    page.getByRole('navigation', { name: en.nav.label }).getByRole('link', { name: en.nav.access }),
  ).toBeVisible()
  await expect(search).toHaveValue(server.name.slice(0, 3))
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
  await expect(page).toHaveTitle(`${en.nodes.title} · ice3tier`)
  await expect(page.locator('main')).not.toContainText(/\p{Script=Han}/u)

  await page.reload()
  await expect(page.getByRole('heading', { level: 1, name: en.nodes.title })).toBeVisible()

  await page.getByRole('button', { name: new RegExp(`^${literal(en.common.language)}`) }).click()
  await page.getByRole('menuitemradio', { name: '简体中文' }).click()
  await expect(page.getByRole('heading', { level: 1, name: t.nodes.title })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-CN')
  await search.clear()
})

test('做过的事都记在操作记录里；总览反映现在的状态', async () => {
  await goTo(page, t.nav.overview)
  // 两个节点了，总览不再是引导。
  await expect(page.getByTestId('overview-status')).toBeVisible()
  await expect(page.getByRole('heading', { name: t.overview.guide.title })).toHaveCount(0)

  await goToAdmin(page, t.nav.settings)
  await page.getByRole('link', { name: t.settings.tabLog }).click()
  await expect(page.getByRole('columnheader', { name: t.settings.log.colEvent })).toBeVisible()
  const log = await controller.api<{ action: string }[]>('GET', '/log')
  const actions = new Set(log.map((entry) => entry.action))
  // 界面上做的每一类修改，controller 都留了记录。
  expect(log.length).toBeGreaterThanOrEqual(8)
  expect([...actions].some((action) => action.startsWith('network.'))).toBe(true)
  expect([...actions].some((action) => action.startsWith('rule.'))).toBe(true)
  expect([...actions].some((action) => action.startsWith('forward.'))).toBe(true)
  await expect(page.getByRole('row')).not.toHaveCount(1)
})

test('刷新后还在登录状态；退出后回到登录页，要重新登录', async () => {
  await page.reload()
  await expect(page.getByRole('columnheader', { name: t.settings.log.colEvent })).toBeVisible()

  await page.getByRole('button', { name: new RegExp(literal(t.switcher.label)) }).click()
  await page.getByRole('menuitem', { name: t.nav.signOut }).click()
  await expect(page.getByRole('heading', { name: t.signIn.title })).toBeVisible()
  await expect(page.getByText(t.signIn.signedOut)).toBeVisible()

  // 退出之后直接打开里面的页面，还是落到登录页。
  await page.goto(`${controller.baseUrl}/n/1/nodes`)
  await expect(page).toHaveURL(/\/login\?next=%2Fn%2F1%2Fnodes/)
  await page.getByLabel(t.signIn.tokenLabel, { exact: true }).fill(controller.adminToken)
  await page.getByRole('button', { name: t.signIn.submit, exact: true }).click()
  // 登录后回到原来要去的地址。
  await expect(page).toHaveURL(/\/n\/1\/nodes$/)
  await expect(page.getByTestId(`node-row-${server.name}`)).toBeVisible()
})
