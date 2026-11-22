import { expect, type Locator, type Page, test } from '@playwright/test'

import { Controller, type NodeHandle } from './controller'
import { goTo, literal, signIn, t } from './helpers'

/**
 * 路由视图：三个真的跑着的节点（一个是 relay），互相连过之后各自上报路由。
 * 拓扑的实时图和路由矩阵画的是 controller 上真的路由矩阵；路径诊断真的去问两端。
 */

const NET = '/networks/1'

interface MatrixReply {
  nodes: { id: number; name: string }[]
  entries: { from: number; to: number; route: { via: string } }[]
}

let controller: Controller
let page: Page
const nodes = {} as Record<'hk' | 'laptop' | 'nas', { handle: NodeHandle; id: number; ip: string }>

function option(ip: string): Locator {
  return page.getByRole('option', { name: new RegExp(`${ip.replaceAll('.', '\\.')}(?!\\d)`) })
}

function nodeLabel(name: string, relay: boolean): string {
  return `[aria-label="${t.topology.nodeLabel(name, relay, true)}"]`
}

async function pick(label: string, ip: string): Promise<void> {
  await page.getByRole('combobox', { name: label }).click()
  await option(ip).click()
  // 收起的动画期间这个列表还在页面上，紧接着打开的下一个列表里的选项会认重。
  await expect(page.getByRole('listbox')).toHaveCount(0)
}

test.describe.configure({ mode: 'serial' })

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120_000)
  controller = await Controller.start()
  page = await browser.newPage({ locale: 'zh-CN' })
})

test.afterAll(async () => {
  await page.close()
  await controller.stop()
})

test('准备：三个节点跑起来，互相连一下', async () => {
  test.setTimeout(120_000)
  await controller.api('POST', '/networks', { name: 'home' })
  const names = ['hk', 'laptop', 'nas'] as const
  for (const [index, name] of names.entries()) {
    const handle = await controller.enroll({ flags: name === 'hk' ? ['--can-relay'] : [] })
    const id = index + 1
    // 名字取自主机名，同一台机器上的几个节点会重名加后缀；改成好认的。
    await controller.api('PATCH', `${NET}/nodes/${id}`, { name })
    nodes[name] = { handle, id, ip: `10.66.0.${id}` }
  }
  for (const name of names) await controller.run(nodes[name].handle)
  await controller.waitOnline(3)
  await controller.api('PUT', `${NET}/nodes/1/relay`, { udp: ['203.0.113.7:20330'], region: 'hk' })

  // 两两连一下：连接本身会被拒绝，但节点之间因此建立了连接，随后各自上报到对方的路。
  controller.touch(nodes.laptop.handle, nodes.nas.ip)
  controller.touch(nodes.nas.handle, nodes.hk.ip)
  controller.touch(nodes.hk.handle, nodes.laptop.ip)
  await expect
    .poll(async () => (await controller.api<MatrixReply>('GET', `${NET}/routes`)).entries.length, { timeout: 40_000 })
    .toBeGreaterThanOrEqual(6)
})

test('拓扑的实时图：三个节点、relay 画在中间，选两个节点看两个方向', async () => {
  await signIn(page, controller)
  await goTo(page, t.nav.topology)
  await expect(page.getByRole('heading', { name: t.topology.title })).toBeVisible()
  const graph = page.getByTestId('topology-graph')
  await expect(graph.locator('.react-flow__node')).toHaveCount(3)
  await expect(graph.locator(nodeLabel('hk', true))).toBeVisible()
  await expect(graph.locator(nodeLabel('laptop', false))).toBeVisible()
  // 三对节点之间都有路：三条线。
  await expect(graph.locator('.react-flow__edge')).toHaveCount(3)

  await pick(t.topology.pickA, nodes.laptop.ip)
  await pick(t.topology.pickB, nodes.nas.ip)
  await expect(page).toHaveURL(/[?&]a=2&b=3/)
  // 两个方向各一段，画在最上面；面板上用文字再说一遍。
  await expect(graph.locator('.react-flow__edge')).toHaveCount(5)
  await expect(page.getByTestId('pair-forward')).toContainText(t.topology.forward('laptop', 'nas'))
  await expect(page.getByTestId('pair-forward')).toContainText(t.routes.direct)
  await expect(page.getByTestId('pair-reverse')).toContainText(t.topology.forward('nas', 'laptop'))

  // 在图上先后点两个节点，和用选择器选一样。
  await graph.locator(nodeLabel('hk', true)).click()
  await expect(page.getByTestId('pair-panel')).toHaveCount(0)
  await graph.locator(nodeLabel('nas', false)).click()
  await expect(page.getByTestId('pair-forward')).toContainText(t.topology.forward('hk', 'nas'))
  await expect(page).toHaveURL(/[?&]a=1&b=3/)
})

test('路由矩阵：每个方向一格，点一格选中这一对', async () => {
  await page.getByRole('radio', { name: t.topology.viewMatrix }).click()
  const matrix = page.getByTestId('route-matrix')
  await expect(matrix).toBeVisible()
  // 选中的那一对跟着切过来了。
  await expect(page.getByTestId('pair-forward')).toContainText(t.topology.forward('hk', 'nas'))
  await expect(matrix.locator('[data-testid^="cell-"]')).toHaveCount(6)
  const cell = page.getByTestId(`cell-${nodes.laptop.id}-${nodes.hk.id}`)
  // 节点说得出直连的方式时（新的节点）写在括号里，旧的节点不写。
  await expect(cell).toHaveAccessibleName(
    new RegExp(`^${literal(t.topology.cellLabel('laptop', 'hk', t.routes.direct))}`),
  )
  await expect(cell).toHaveAccessibleName(new RegExp(literal(t.routes.addr(''))))
  await cell.click()
  await expect(page.getByTestId('pair-forward')).toContainText(t.topology.forward('laptop', 'hk'))
  await expect(cell).toHaveAttribute('aria-pressed', 'true')
  await expect(page).toHaveURL(/view=matrix/)

  // 从选中的这一对去路径诊断：现问两端，两个方向分开写。
  await page.getByTestId('pair-panel').getByRole('link', { name: t.topology.toPath }).click()
  await expect(page).toHaveURL(/\/n\/1\/diagnosis\?a=2&b=1$/)
  await expect(page.getByRole('heading', { name: t.path.title })).toBeVisible()
  const forward = page.getByTestId('path-forward')
  await expect(forward).toHaveAttribute('data-source', 'query')
  await expect(forward).toContainText(t.path.forward('laptop', 'hk'))
  await expect(forward).toContainText(t.path.source.query)
  await expect(forward).toContainText(t.routes.direct)
  await expect(page.getByTestId('path-reverse')).toContainText(t.path.forward('hk', 'laptop'))
})

test('节点详情的路由表连到拓扑和路径诊断', async () => {
  await page.goto(`${controller.baseUrl}/n/1/nodes/${nodes.laptop.id}?tab=routes`)
  const row = page.getByRole('row', { name: /nas/ })
  await expect(row.getByRole('link', { name: t.nodes.detail.routesOnTopology })).toHaveAttribute(
    'href',
    `/n/1/topology?a=${nodes.laptop.id}&b=${nodes.nas.id}`,
  )
  await row.getByRole('link', { name: t.nodes.detail.routesDiagnose }).click()
  await expect(page.getByTestId('path-forward')).toContainText(t.path.forward('laptop', 'nas'))
  await expect(page.getByTestId('path-forward')).toHaveAttribute('data-source', 'query')
})

test('路径诊断：规则不让两个节点互通时，说"不是对端"，给出去访问检查的入口', async () => {
  const forward = page.getByTestId('path-forward')
  // 停用默认规则：两个节点之间不再有访问关系，节点很快收到新配置，再问就是"不是对端"。
  await controller.api('PATCH', `${NET}/rules/1`, { enabled: false })
  await expect(async () => {
    await page.getByRole('button', { name: t.path.query }).click()
    await expect(forward).toHaveAttribute('data-source', 'not_peers', { timeout: 4_000 })
  }).toPass({ timeout: 30_000 })
  await expect(page.getByText(t.path.notPeersTitle).first()).toBeVisible()
  await expect(page.getByRole('link', { name: t.path.toAccess })).toHaveAttribute(
    'href',
    `/n/1/access?check=1&from=${nodes.laptop.id}&to=${nodes.nas.id}`,
  )
  await controller.api('PATCH', `${NET}/rules/1`, { enabled: true })
})
