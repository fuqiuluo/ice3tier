import { type ChildProcess, execFile, spawn } from 'node:child_process'
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { createServer as createTcpServer, type Server as TcpServer } from 'node:net'
import { networkInterfaces } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { expect, type Page, test } from '@playwright/test'

import { en } from '../src/i18n/en'
import { Controller, type NodeHandle } from './controller'
import { clearToasts, goTo, goToAdmin, literal, signIn, t } from './helpers'
import { type ReleaseKit, releaseKit, ReleaseSource } from './release'

/**
 * 把每个页面在"没有数据"和"有数据"时的样子截下来，放到 web/screenshots/，给人看版面有没有问题。
 * 数据都是真的：真的 controller，真的节点用真的令牌加入，其中三个真的跑着；
 * 发布源是一个本机目录，里面有一个用测试钥匙签的新版本（要先 `pnpm e2e:kit`）。
 */

const outDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'screenshots')

let controller: Controller
let page: Page
let kit: ReleaseKit
let release: ReleaseSource
let counter = 0
/** 带一个数的句子写成正则：数换成 `\d+`（`sample` 是样例里用的那个数，句子里别处不能有它）。 */
function counted(sentence: (n: number) => string): RegExp {
  const sample = 987654
  return new RegExp(literal(sentence(sample)).replace(String(sample), '\\d+'))
}

/** 用界面或接口加进来的节点，按用途起了名字。 */
const nodes: Record<string, NodeHandle> = {}
/** 准备数据时建的分组的编号，按名字。 */
const groups: Record<string, number> = {}
/** 经出口下载的目标：这台机器局域网地址上的一个 HTTP 服务。没有私有地址的机器上不造用量。 */
let target: HttpServer
let busy: TcpServer
let targetPort = 0
let busyPort = 0
let lanIp: string | undefined
/** 经 ice3proxy 一直开着的一条连接（curl），和它连着的、一直不结束应答的服务。 */
let hold: ChildProcess | undefined
let holder: HttpServer | undefined

function listenOn(server: HttpServer | TcpServer, host: string): Promise<number> {
  return new Promise((done, fail) => {
    server.once('error', fail)
    server.listen(0, host, () => {
      const address = server.address()
      if (address !== null && typeof address === 'object') done(address.port)
      else fail(new Error('拿不到端口'))
    })
  })
}

/** 一个现在空闲的端口：占一下就放开。 */
async function freePort(): Promise<number> {
  const server = createTcpServer()
  const port = await listenOn(server, '127.0.0.1')
  await new Promise((done) => server.close(done))
  return port
}

/** 经一个 SOCKS5 入口下载 4 MB。异步地等：目标就在这个进程里。 */
function download(proxy: string): Promise<void> {
  return new Promise((done) => {
    execFile(
      'curl',
      ['-s', '-m', '20', '-o', '/dev/null', '-x', proxy, `http://${lanIp ?? ''}:${targetPort}/blob`],
      () => done(),
    )
  })
}

async function shot(name: string, options: { fullPage?: boolean } = {}): Promise<void> {
  counter += 1
  await page.waitForLoadState('networkidle')
  // 整页截图要从页面顶端开始截：滚动过的话，粘在视口上的侧栏和顶栏会画在半中间。
  if (options.fullPage ?? true) await page.evaluate(() => window.scrollTo(0, 0))
  // 等进场动画走完，免得截到半透明的对话框。
  await page.waitForTimeout(250)
  await page.screenshot({
    path: join(outDir, `${String(counter).padStart(2, '0')}-${name}.png`),
    fullPage: options.fullPage ?? true,
  })
}

test.describe.configure({ mode: 'serial' })

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120_000)
  // 每次都从空目录开始：改过名字或者删掉的截图不会留下旧的一份。
  rmSync(outDir, { recursive: true, force: true })
  mkdirSync(outDir, { recursive: true })
  kit = releaseKit()
  controller = await Controller.start({ bins: kit.oldBins })
  page = await browser.newPage({ locale: 'zh-CN', viewport: { width: 1280, height: 800 } })
  const blob = Buffer.alloc(4 * 1024 * 1024, 'i')
  target = createHttpServer((_request, response) => response.end(blob))
  targetPort = await listenOn(target, '0.0.0.0')
  busy = createTcpServer()
  busyPort = await listenOn(busy, '127.0.0.1')
  lanIp = Object.values(networkInterfaces())
    .flat()
    .find(
      (address) => address?.family === 'IPv4' && !address.internal && address.address.startsWith('192.168.'),
    )?.address
})

test.afterAll(async () => {
  hold?.kill('SIGKILL')
  holder?.closeAllConnections()
  holder?.close()
  await page.close()
  controller.stop()
  target.close()
  busy.close()
})

test('登录和第一个网络', async () => {
  await page.goto(`${controller.baseUrl}/`)
  await expect(page.getByRole('heading', { name: t.signIn.title })).toBeVisible()
  await shot('sign-in')

  await page.getByLabel(t.signIn.tokenLabel, { exact: true }).fill('not-the-token')
  await page.getByRole('button', { name: t.signIn.submit, exact: true }).click()
  await expect(page.getByText(t.errors.codes.unauthorized)).toBeVisible()
  await shot('sign-in-wrong-token')

  await signIn(page, controller)
  await expect(page.getByRole('heading', { name: t.networks.welcomeTitle })).toBeVisible()
  await shot('welcome-first-network')

  await page.getByRole('button', { name: t.networks.createSubmit }).click()
  await expect(page.getByRole('heading', { name: t.overview.guide.title })).toBeVisible()
})

test('空的网络：每个页面没有数据时的样子', async () => {
  await clearToasts(page)
  await shot('overview-guide-empty')

  await goTo(page, t.nav.nodes)
  await expect(page.getByText(t.nodes.emptyTitle)).toBeVisible()
  await shot('nodes-empty')

  await page.getByRole('button', { name: t.nodes.add }).click()
  await expect(page.getByRole('dialog', { name: t.addNode.title })).toBeVisible()
  await shot('add-node-before-token', { fullPage: false })
  await page.getByRole('button', { name: t.addNode.done }).click()

  await goTo(page, t.nav.access)
  await expect(page.getByRole('switch', { name: t.access.ruleSwitch('default') })).toBeVisible()
  await shot('access-default-rule-only')
  await page.getByRole('radio', { name: t.access.viewGraph }).click()
  await expect(page.getByTestId('group-graph')).toBeVisible()
  await shot('access-graph-default-only')
  await page.getByRole('radio', { name: t.access.viewList }).click()

  for (const [name, file, marker] of [
    [t.nav.proxies, 'proxies-empty', t.proxies.emptyTitle],
    [t.nav.forwards, 'forwards-empty', t.forwards.emptyTitle],
  ] as const) {
    await goTo(page, name)
    await expect(page.getByText(marker).first()).toBeVisible()
    await shot(file)
  }
  for (const [name, file, marker] of [[t.nav.pairs, 'pairs-empty', t.pairs.emptyTitle]] as const) {
    await goToAdmin(page, name)
    await expect(page.getByText(marker).first()).toBeVisible()
    await shot(file)
  }
})

test('添加节点：令牌、命令、节点加入', async () => {
  await goTo(page, t.nav.overview)
  await page.getByRole('checkbox', { name: new RegExp(literal(t.addNode.declareRelay)) }).check()
  await page.getByRole('button', { name: t.addNode.generate }).click()
  const command = page.getByTestId('join-command')
  await expect(command).toContainText('echo i3t-')
  await shot('overview-guide-token-generated')

  const first = controller.join((await command.textContent()) ?? '')
  // 节点的名字取自主机名（取不出来才叫 node-<编号>），所以不按名字认。
  await expect(page.locator('[data-testid^="guide-node-"]')).toBeVisible()
  await shot('overview-guide-one-node')

  // 第一个节点跑起来；后面再准备其余的。
  await controller.run(first)
  nodes.gw = first
})

test('准备数据', async () => {
  test.setTimeout(180_000)
  const net = '/networks/1'
  // gw-hk 是第一个节点，已经声明了 relay；再补上出口的声明。声明在节点重启后才上报，所以这里在它启动之前就改好了的不算，
  // 直接用加入时的参数准备其余几个。
  for (const name of ['servers', 'home', 'laptops']) {
    groups[name] = (await controller.api<{ id: number }>('POST', `${net}/groups`, { name })).id
  }
  const group = (name: string) => groups[name] ?? 0
  nodes.nas = await controller.enroll({
    groups: [group('servers'), group('home')],
    flags: ['--can-exit'],
  })
  nodes.laptop = await controller.enroll({ groups: [group('laptops')] })
  nodes.office = await controller.enroll({ groups: [group('laptops')] })
  nodes.spare = await controller.enroll()
  // nas 以为自己在容器里：它不能自己更新，界面上要写出做法。
  await controller.run(nodes.nas, { env: { container: 'podman' } })
  await controller.run(nodes.laptop)
  await controller.waitOnline(3)

  // 发布源上有一个新版本。自动更新关着：截图的时候节点不要自己换程序重启。
  await controller.api('PATCH', '/update', { auto_update: false })
  release = new ReleaseSource(join(controller.dir, 'releases'), kit)
  release.publish(kit.newVersion, kit.newProgram)
  await controller.api('PATCH', '/update', { source: release.root })
  await controller.api('POST', '/update/check')

  await controller.api('PATCH', `${net}/nodes/1`, { name: 'gw-hk', groups: [group('servers')] })
  await controller.api('PATCH', `${net}/nodes/2`, { name: 'nas-home' })
  await controller.api('PATCH', `${net}/nodes/3`, { name: 'laptop', pinned_relays: [] })
  await controller.api('PATCH', `${net}/nodes/4`, { name: 'office-pc', routing: 'lowest_cost' })

  await controller.api('PUT', `${net}/nodes/1/relay`, {
    udp: ['203.0.113.7:20330'],
    tcp: ['203.0.113.7:20330'],
    region: 'hk',
    bandwidth_mbps: 200,
  })
  await controller.api('PUT', `${net}/nodes/2/exit`, {
    ports: [80, 443],
    lan: true,
    quota_bytes: 16 * 1024 * 1024,
    quota_reset_day: 1,
    connects_per_minute: 120,
  })
  await controller.api('PATCH', `${net}/nodes/3`, { pinned_relays: [1] })

  await controller.api('POST', `${net}/rules`, {
    name: 'ssh',
    src: group('laptops'),
    dst: group('servers'),
    direction: 'one_way',
  })
  await controller.api('POST', `${net}/rules`, {
    name: '',
    src: group('servers'),
    dst: group('servers'),
    direction: 'both',
  })
  await controller.api('POST', `${net}/rules`, {
    name: 'media',
    src: group('laptops'),
    dst: group('home'),
    direction: 'both',
    enabled: false,
  })

  // 代理：gw-hk 上一个开在（这台机器没有的）局域网地址上的，监听不上；laptop 上一个只给本机的 HTTP 代理。都经 nas-home 出去。
  await controller.api('POST', `${net}/proxies`, {
    name: 'phone',
    node: 1,
    bind: '192.168.1.5:1080',
    exit: 2,
    username: 'phone',
    password: 'phone-password',
  })
  await controller.api('POST', `${net}/proxies`, {
    name: 'fixed-nas',
    node: 3,
    bind: '127.0.0.1:8118',
    protocol: 'http',
    exit: 2,
  })

  // nas 是端口转发的目标：0.1.11 起是管理员的开关，不是节点的声明。
  await controller.api('PATCH', `${net}/nodes/2`, { forward_target: true })
  await controller.api('POST', `${net}/forwards`, {
    name: 'web',
    protocol: 'tcp',
    listen_node: 3,
    bind: '127.0.0.1:8080',
    target_node: 2,
    target_addr: '192.168.1.10:80',
  })
  await controller.api('POST', `${net}/forwards`, {
    name: 'db',
    protocol: 'tcp',
    listen_node: 4,
    bind: '127.0.0.1:5432',
    target_node: 2,
    target_addr: '127.0.0.1:5432',
  })
  await controller.api('POST', `${net}/forwards`, {
    name: 'dns',
    protocol: 'udp',
    listen_node: 3,
    bind: '127.0.0.1:5353',
    target_node: 2,
    target_addr: '192.168.1.1:53',
    enabled: false,
  })
  await controller.api('POST', `${net}/forwards`, {
    name: 'printer',
    protocol: 'tcp',
    listen_node: 2,
    bind: '0.0.0.0:9100',
    target_node: 3,
    target_addr: '127.0.0.1:9100',
    allow_from: ['192.168.1.0/24'],
    enabled: false,
  })
  await controller.api('POST', `${net}/forwards`, {
    name: 'spare-web',
    protocol: 'tcp',
    listen_node: 5,
    bind: '127.0.0.1:8081',
    target_node: 2,
    target_addr: '127.0.0.1:80',
  })

  // 端口写 0 的，和监听在一个被占着的端口上的。
  await controller.api('POST', `${net}/forwards`, {
    name: 'picked',
    protocol: 'tcp',
    listen_node: 3,
    bind: '127.0.0.1:0',
    target_node: 2,
    target_addr: `127.0.0.1:${targetPort}`,
  })
  await controller.api('POST', `${net}/forwards`, {
    name: 'busy',
    protocol: 'tcp',
    listen_node: 3,
    bind: `127.0.0.1:${busyPort}`,
    target_node: 2,
    target_addr: `127.0.0.1:${targetPort}`,
  })
  // laptop 上一个对外的代理，只收本机来的连接；经它从 nas-home 出去下载，造出用量。
  const proxyPort = await freePort()
  await controller.api('POST', `${net}/proxies`, {
    name: 'guests',
    node: 3,
    bind: `0.0.0.0:${proxyPort}`,
    exit: 2,
    username: 'tablet',
    password: 'tablet-password',
    allow_from: ['127.0.0.0/8'],
    class: 'bulk',
  })

  await controller.api('PUT', `${net}/pairs/2/3`, { keep_alive: true })
  await controller.api('POST', '/networks', { name: 'lab' })

  // 让跑着的三个节点互相连一下，路由表里才有东西；节点每 10 秒上报一次。
  controller.touch(nodes.laptop, '10.66.0.1')
  controller.touch(nodes.laptop, '10.66.0.2')
  controller.touch(nodes.nas, '10.66.0.1')
  await expect
    .poll(async () => (await controller.api<{ routes: unknown[] }>('GET', `${net}/nodes/3/routes`)).routes.length, {
      timeout: 30_000,
    })
    .toBeGreaterThan(0)

  if (lanIp !== undefined) {
    // 等 guests 监听上，再经它下载两次。
    await expect
      .poll(
        async () =>
          (await controller.api<{ name: string; status: { code: string } | null }[]>('GET', `${net}/proxies`)).find(
            (proxy) => proxy.name === 'guests',
          )?.status?.code,
        { timeout: 30_000 },
      )
      .toBe('listening')
    await download(`socks5h://tablet:tablet-password@127.0.0.1:${proxyPort}`)
    await download(`socks5h://tablet:tablet-password@127.0.0.1:${proxyPort}`)
    await expect
      .poll(async () => (await controller.api<{ usage: unknown }[]>('GET', `${net}/exits`))[0]?.usage ?? null, {
        timeout: 30_000,
      })
      .not.toBeNull()
  }
})

test('有数据时：总览、节点', async () => {
  await page.reload()
  await goTo(page, t.nav.overview)
  await expect(page.getByTestId('overview-status')).toBeVisible()
  await shot('overview')

  // 访问地图上的卡片真的点得动（React Flow 给不能选、不能拖的节点写了 pointer-events: none）：
  // 左边的下拉打开，右边的分组换成看那个分组，中间的策略去策略页。
  const om = t.overview.map
  const members = (await controller.api<unknown[]>('GET', '/networks/1/nodes')).length
  await page.getByRole('button', { name: new RegExp(`^${literal(om.pickNode)}`) }).click()
  await expect(page.getByRole('menu')).toBeVisible()
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: om.groupLabel('All', members) }).click()
  await expect(page).toHaveURL(/view=group/)
  await page.getByRole('link', { name: new RegExp(`^${literal(om.ruleLabel('default', ''))}`) }).click()
  await expect(page).toHaveURL(/\/access/)

  await goTo(page, t.nav.nodes)
  await expect(page.getByTestId('node-row-gw-hk')).toBeVisible()
  await shot('nodes')

  await page.getByRole('searchbox').fill('lap')
  await page.getByRole('button', { name: t.nodes.filter }).click()
  await page.getByRole('checkbox', { name: 'laptops' }).check()
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('node-row-gw-hk')).toBeHidden()
  await shot('nodes-filtered')
  await page.getByRole('button', { name: t.nodes.clearAll }).click()

  await page.getByRole('searchbox').fill('no-such-node')
  await expect(page.getByText(t.nodes.noMatches)).toBeVisible()
  await shot('nodes-no-matches')
  await page.getByRole('button', { name: t.common.clearFilters }).click()

  await page.getByRole('checkbox', { name: t.nodes.selectOne('laptop') }).check()
  await page.getByRole('checkbox', { name: t.nodes.selectOne('office-pc') }).check()
  await shot('nodes-selection-bar', { fullPage: false })
  await page.getByRole('button', { name: t.nodes.batchAddGroup }).click()
  await expect(page.getByRole('dialog', { name: t.nodes.batchAddTitle(2) })).toBeVisible()
  await shot('nodes-batch-group', { fullPage: false })
  await page.getByRole('button', { name: t.common.cancel, exact: true }).click()
  await page.getByRole('button', { name: t.nodes.batchCancel }).click()

  await page.getByRole('button', { name: t.nodes.add }).click()
  await page.getByRole('button', { name: t.addNode.optionsTitle }).click()
  await page.getByRole('combobox', { name: t.addNode.groupsLabel }).click()
  await page.getByRole('textbox', { name: t.groups.picker.search }).fill('serv')
  await page.keyboard.press('Enter')
  await page.keyboard.press('Escape')
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await page.getByRole('checkbox', { name: new RegExp(literal(t.addNode.declareExit)) }).check()
  await page.getByRole('button', { name: t.addNode.generate }).click()
  await expect(page.getByTestId('join-command')).toContainText('echo i3t-')
  await shot('add-node-waiting', { fullPage: false })
  const extra = controller.join((await page.getByTestId('join-command').textContent()) ?? '')
  nodes.extra = extra
  await expect(page.getByTestId('node-joined')).toBeVisible()
  await shot('add-node-joined', { fullPage: false })
  await page.getByRole('button', { name: t.addNode.done }).click()
})

test('有数据时：节点详情', async () => {
  const d = t.nodes.detail
  const u = t.updates
  await page.getByRole('link', { name: 'gw-hk', exact: true }).click()
  await expect(page.getByRole('combobox', { name: d.groups })).toBeVisible()
  await shot('node-detail-overview')
  await page.getByRole('tab', { name: d.tabRelay }).click()
  await expect(page.getByTestId('capability-relay')).toBeVisible()
  await shot('node-detail-relay')
  // 宽屏：中继页分成两栏。
  await page.setViewportSize({ width: 1680, height: 960 })
  await expect(page.getByTestId('relay-links')).toBeVisible()
  await shot('node-detail-relay-wide', { fullPage: false })
  await page.setViewportSize({ width: 1280, height: 800 })

  await goTo(page, t.nav.nodes)
  await page.getByRole('link', { name: 'nas-home', exact: true }).click()
  await page.getByRole('tab', { name: d.tabExit }).click()
  await expect(page.getByTestId('capability-exit')).toBeVisible()
  await shot('node-detail-exit')
  await page.setViewportSize({ width: 1680, height: 960 })
  await expect(page.getByTestId('exit-usage')).toBeVisible()
  await shot('node-detail-exit-wide', { fullPage: false })
  await page.getByTestId('exit-ports').scrollIntoViewIfNeeded()
  await shot('node-detail-exit-ports', { fullPage: false })
  await page.getByTestId('exit-upstream').scrollIntoViewIfNeeded()
  await shot('node-detail-exit-upstream', { fullPage: false })
  await page.setViewportSize({ width: 1280, height: 800 })
  await page.getByRole('tab', { name: d.tabForward }).click()
  await expect(page.getByTestId('capability-forward')).toBeVisible()
  await shot('node-detail-forward')

  await goTo(page, t.nav.nodes)
  await page.getByRole('link', { name: 'laptop', exact: true }).click()
  await page.getByRole('tab', { name: d.tabExit }).click()
  await page.getByTestId('capability-exit').getByRole('button', { name: t.declare.howTo }).click()
  await expect(page.getByTestId('declare-command')).toBeVisible()
  await shot('node-detail-not-declared')

  // 概览上的"指定的中继"：点开是能搜索的勾选列表。
  await page.getByRole('tab', { name: d.tabOverview }).click()
  await page.getByRole('combobox', { name: d.pinnedLabel }).click()
  await expect(page.getByRole('listbox', { name: d.pinnedLabel })).toBeVisible()
  await shot('node-detail-pinned-relays', { fullPage: false })
  await page.keyboard.press('Escape')

  await page.getByRole('tab', { name: d.tabRoutes }).click()
  await expect(page.getByRole('columnheader', { name: d.routesColMode }).first()).toBeVisible()
  await shot('node-detail-routes')
  await page.setViewportSize({ width: 1680, height: 960 })
  await shot('node-detail-routes-wide', { fullPage: false })
  // 右上角切成星状图：本节点在中间，对端围一圈。
  await page.getByRole('radio', { name: d.routesViewStar }).click()
  await expect(page.getByTestId('routes-star').locator('.react-flow__node-peer').first()).toBeVisible()
  await shot('node-detail-routes-star', { fullPage: false })
  await page.setViewportSize({ width: 1280, height: 800 })
  await shot('node-detail-routes-star-narrow', { fullPage: false })
  // 星状图上的对端点得动：去那个节点的路由，再回来。
  const here = page.url()
  await page.getByTestId('routes-star').locator('.react-flow__node-peer a').first().click()
  await expect(page).not.toHaveURL(here)
  await expect(page).toHaveURL(/tab=routes&view=star/)
  await page.goBack()
  await page.getByRole('radio', { name: d.routesViewTable }).click()

  await page.getByRole('tab', { name: d.tabOverview }).click()
  await page.getByRole('button', { name: d.editIp }).click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await shot('node-edit-ip', { fullPage: false })
  await page.getByRole('button', { name: t.common.cancel, exact: true }).click()

  await page.getByRole('button', { name: d.more }).click()
  await page.getByRole('menuitem', { name: t.nodes.menuDelete }).click()
  await expect(page.getByRole('alertdialog')).toBeVisible()
  await shot('node-delete-confirm', { fullPage: false })
  await page.getByRole('button', { name: t.common.cancel, exact: true }).click()

  await goTo(page, t.nav.nodes)
  await page.getByRole('link', { name: 'office-pc', exact: true }).click()
  await page.getByRole('tab', { name: d.tabRoutes }).click()
  await expect(page.getByText(d.routesOffline).first()).toBeVisible()
  await shot('node-detail-routes-offline')

  // 更新：nas-home 在容器里，不能自己更新；laptop 能，"立即更新"的确认框。
  await goTo(page, t.nav.nodes)
  await page.getByRole('link', { name: 'nas-home', exact: true }).click()
  await page.getByRole('button', { name: u.detail.upgrade(kit.newVersion) }).click()
  await expect(page.getByTestId('node-self-update')).toContainText(u.blocker.container)
  await shot('node-detail-update-manual', { fullPage: false })
  await page.keyboard.press('Escape')

  await goTo(page, t.nav.nodes)
  await page.getByRole('link', { name: 'laptop', exact: true }).click()
  await expect(page.getByRole('button', { name: u.detail.upgrade(kit.newVersion) })).toBeVisible()
  await shot('node-detail-update')
  await page.getByRole('button', { name: u.detail.upgrade(kit.newVersion) }).click()
  await expect(page.getByRole('dialog')).toContainText(u.force.idleBody)
  await shot('node-force-update-dialog', { fullPage: false })
  await page.getByRole('button', { name: t.common.cancel, exact: true }).click()
})

test('有数据时：拓扑和路径诊断', async () => {
  await goTo(page, t.nav.topology)
  const graph = page.getByTestId('topology-graph')
  await expect(graph.locator('.react-flow__node')).toHaveCount(6)
  await expect(graph.locator('.react-flow__edge').first()).toBeAttached()
  await shot('topology')

  await page.getByRole('combobox', { name: t.topology.pickA }).click()
  await page.getByRole('option', { name: /10\.66\.0\.3$/ }).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await page.getByRole('combobox', { name: t.topology.pickB }).click()
  await page.getByRole('option', { name: /nas-home/ }).click()
  await expect(page.getByTestId('pair-panel')).toBeVisible()
  await shot('topology-pair')

  await page.getByRole('radio', { name: t.topology.viewMatrix }).click()
  await expect(page.getByTestId('route-matrix')).toBeVisible()
  await shot('topology-matrix')

  await page.getByTestId('pair-panel').getByRole('link', { name: t.topology.toPath }).click()
  await expect(page.getByTestId('path-forward')).toHaveAttribute('data-source', /query|report/)
  await shot('diagnosis')
})

test('有数据时：访问控制', async () => {
  await goTo(page, t.nav.access)
  await expect(page.getByTestId('rule-row-2')).toBeVisible()
  await shot('access-all-open')

  // 停用默认规则，按分组收紧。
  await page.getByRole('switch', { name: t.access.ruleSwitch('default') }).click()
  await expect(page.getByRole('alertdialog')).toBeVisible()
  await shot('access-disable-default-confirm', { fullPage: false })
  await page.getByRole('button', { name: t.access.disableConfirm }).click()
  await expect(page.getByTestId('unconnected')).toBeVisible()
  await clearToasts(page)
  await shot('access-tightened')
  await page.getByRole('radio', { name: t.access.viewGraph }).click()
  await expect(page.getByTestId('group-graph')).toBeVisible()
  await shot('access-graph')
  await page.getByRole('radio', { name: t.access.viewList }).click()

  const rd = t.access.dialog
  await page.getByRole('button', { name: t.access.newRule }).click()
  const dialog = page.getByRole('dialog', { name: rd.createTitle })
  await dialog.getByRole('combobox', { name: rd.srcLabel }).click()
  await page.getByRole('option', { name: /laptops/ }).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await dialog.getByRole('combobox', { name: rd.dstLabel }).click()
  await page.getByRole('option', { name: /home/ }).click()
  await dialog.getByRole('radio', { name: rd.oneWay }).click()
  await expect(page.getByTestId('rule-impact')).toBeVisible()
  await shot('access-rule-dialog', { fullPage: false })
  await dialog.getByRole('button', { name: t.common.cancel, exact: true }).click()
  await page.getByRole('button', { name: t.common.discardConfirm }).click()

  await page.getByRole('radio', { name: t.access.viewGraph }).click()
  await page.getByRole('radio', { name: t.access.graph.byNode }).click()
  await page.getByRole('combobox', { name: t.access.graph.nodePickLabel, exact: true }).click()
  await page.getByRole('option', { name: /gw-hk/ }).click()
  await expect(page.getByTestId('node-graph').getByText('gw-hk')).toBeVisible()
  await shot('access-node-view')

  const c = t.access.checker
  await page.getByRole('button', { name: t.access.check }).click()
  const check = page.getByTestId('access-check')
  await check.getByRole('combobox', { name: c.from }).click()
  await page.getByRole('option', { name: /laptop/ }).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await check.getByRole('combobox', { name: c.to }).click()
  await page.getByRole('option', { name: /nas-home/ }).click()
  await expect(page.getByTestId('check-laptop-nas-home')).toContainText(c.allowed)
  await shot('access-check', { fullPage: false })
  await check.getByRole('button', { name: t.common.close }).click()
  await expect(check).toHaveCount(0)
  await page.getByRole('radio', { name: t.access.viewList }).click()
})

test('有数据时：分组', async () => {
  const g = t.groups
  await goTo(page, t.nav.groups)
  await expect(page.getByTestId('group-row-servers')).toBeVisible()
  await shot('groups')

  await page.getByRole('button', { name: g.membersOf('servers') }).click()
  await expect(page.getByTestId('group-members-servers')).toBeVisible()
  await shot('groups-members', { fullPage: false })
  await page.getByRole('button', { name: t.common.done }).click()

  await page.getByRole('button', { name: g.create }).click()
  const create = page.getByRole('dialog', { name: g.createTitle })
  await create.getByRole('textbox', { name: g.nameLabel }).fill('my group')
  await create.getByRole('button', { name: g.createSubmit }).click()
  await expect(create.getByText(t.validate.groupCharset)).toBeVisible()
  await shot('groups-create-invalid', { fullPage: false })
  await create.getByRole('button', { name: t.common.cancel, exact: true }).click()
  await page.getByRole('button', { name: t.common.discardConfirm }).click()

  await page.getByRole('button', { name: t.common.actionsFor('home') }).click()
  await page.getByRole('menuitem', { name: g.menuDelete }).click()
  await expect(page.getByRole('alertdialog', { name: g.deleteTitle('home') })).toBeVisible()
  await shot('groups-delete-confirm', { fullPage: false })
  await page.getByRole('button', { name: t.common.cancel, exact: true }).click()

  // 节点详情里选分组：只从已有的里面选，All 总在最前面。
  await page.goto(`${controller.baseUrl}/n/1/nodes/3`)
  await page.getByRole('combobox', { name: t.nodes.detail.groups }).click()
  await expect(page.getByRole('listbox', { name: g.picker.options })).toBeVisible()
  await shot('node-detail-group-picker', { fullPage: false })
  await page.keyboard.press('Escape')
})

test('有数据时：接入', async () => {
  // 代理页：三个代理，一个监听不上（这台机器没有那个局域网地址）；新建代理的对话框。
  const px = t.proxies
  await goTo(page, t.nav.proxies)
  await expect(page.getByTestId('proxy-row-guests')).toContainText(px.status.listening)
  await shot('proxies')
  await page.getByRole('button', { name: px.create }).click()
  const proxyDialog = page.getByRole('dialog', { name: px.dialog.createTitle })
  await proxyDialog.getByRole('combobox', { name: px.dialog.exit }).click()
  await page.getByRole('option', { name: /nas-home/ }).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await proxyDialog.getByRole('combobox', { name: px.dialog.entry }).click()
  await page.getByRole('option', { name: /laptop/ }).click()
  await shot('proxy-dialog', { fullPage: false })
  await proxyDialog.getByRole('button', { name: t.common.cancel, exact: true }).click()
  await page.getByRole('button', { name: t.common.discardConfirm }).click()

  // 出口：nas-home 的出口标签，左边一张设置卡片，右边用量。
  await page.goto(`${controller.baseUrl}/n/1/nodes/2?tab=exit`)
  await expect(page.getByTestId('exit-proxies')).toBeVisible()
  await page.setViewportSize({ width: 1680, height: 960 })
  await shot('node-exit', { fullPage: false })
  await page.setViewportSize({ width: 1280, height: 800 })

  await goTo(page, t.nav.forwards)
  await expect(page.getByTestId('forward-row-web')).toBeVisible()
  await shot('forwards')
  const fd = t.forwards.dialog
  await page.getByRole('button', { name: t.forwards.create }).click()
  const forward = page.getByRole('dialog', { name: fd.createTitle })
  await forward.getByRole('group', { name: fd.listenSide }).getByRole('combobox', { name: fd.node }).click()
  await page.getByRole('option', { name: /laptop/ }).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await forward.getByRole('group', { name: fd.targetSide }).getByRole('combobox', { name: fd.node }).click()
  await page.getByRole('option', { name: /nas-home/ }).click()
  await forward.getByRole('radio', { name: new RegExp(literal(fd.whoOpen)) }).click()
  await expect(page.getByTestId('forward-check')).toBeVisible()
  await shot('forwards-dialog', { fullPage: false })
  // 打开的节点下拉：搜索框、各行和关着的框左边对齐。
  await forward.getByRole('group', { name: fd.targetSide }).getByRole('combobox', { name: fd.node }).click()
  await expect(page.getByRole('listbox')).toBeVisible()
  await shot('forwards-dialog-node-open', { fullPage: false })
  await page.keyboard.press('Escape')
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await forward.getByRole('button', { name: t.common.cancel, exact: true }).click()
  await page.getByRole('button', { name: t.common.discardConfirm }).click()
})

test('有数据时：管理区和设置', async () => {
  await goToAdmin(page, t.nav.pairs)
  await expect(page.getByTestId('pair-row-nas-home-laptop')).toBeVisible()
  await shot('pairs')

  await goToAdmin(page, t.nav.network)
  await expect(page.getByRole('heading', { name: t.networks.basics })).toBeVisible()
  await shot('network')
  // 设置按分区排：左边点一个分区，右边换成它的设置。
  const sections = page.getByRole('navigation', { name: t.networks.sectionsLabel })
  await sections.getByRole('link', { name: t.networks.routing }).click()
  await expect(page.getByRole('form', { name: t.networks.routing })).toBeVisible()
  await shot('network-routing')
  await sections.getByRole('link', { name: t.networks.connection }).click()
  await expect(page.getByRole('form', { name: t.networks.connection })).toBeVisible()
  await shot('network-connection')
  await page.getByRole('button', { name: t.networks.create }).click()
  await expect(page.getByRole('dialog', { name: t.networks.createTitle })).toBeVisible()
  await shot('network-create-dialog', { fullPage: false })
  await page.getByRole('button', { name: t.common.cancel, exact: true }).click()

  await page.getByRole('button', { name: new RegExp(literal(t.switcher.label)) }).click()
  await shot('network-switcher', { fullPage: false })
  await page.keyboard.press('Escape')

  await goToAdmin(page, t.nav.settings)
  await expect(page.getByText(t.settings.session.stored)).toBeVisible()
  await shot('settings-session')
  await page.getByRole('link', { name: new RegExp(literal(t.updates.tab)) }).click()
  await expect(page.getByTestId('release-version')).toHaveText(t.updates.release.latest(kit.newVersion))
  await shot('settings-updates')
  await page.getByRole('button', { name: t.updates.nodes.updateAll }).click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await shot('settings-updates-force-all', { fullPage: false })
  await page.getByRole('button', { name: t.common.cancel, exact: true }).click()

  // 一个在这台机器上自检不过的版本：让 laptop 立即更新到它，自检失败，这个版本被暂停。
  const broken = kit.oldVersion.replace(/\d+$/, (patch) => String(Number(patch) + 7))
  const program = join(controller.dir, 'broken-i3t')
  writeFileSync(program, "#!/bin/sh\necho '这个程序在这台机器上跑不了：缺一个库' >&2\nexit 127\n")
  chmodSync(program, 0o755)
  release.publish(broken, program)
  await controller.api('POST', '/update/check')
  await controller.api('POST', '/networks/1/nodes/3/update', { timing: 'now' })
  await expect
    .poll(async () => (await controller.api<{ paused: unknown[] }>('GET', '/update')).paused.length, {
      timeout: 60_000,
    })
    .toBe(1)
  await page.reload()
  await page.getByRole('button', { name: t.updates.paused.reason }).click()
  await expect(page.getByTestId(`paused-reason-${broken}`)).toContainText('缺一个库')
  await shot('settings-updates-paused')

  const l = t.settings.log
  await page.getByRole('link', { name: t.settings.tabLog }).click()
  await expect(page.getByRole('columnheader', { name: l.colEvent })).toBeVisible()
  await shot('settings-log')
  await page.getByRole('combobox', { name: l.filterAction }).selectOption('proxy')
  await page
    .locator('[data-testid^="log-row-"]')
    .first()
    .getByRole('button', { name: counted((n) => l.filterByRef(l.refLabels.proxy(n))) })
    .first()
    .click()
  await expect(page.getByTestId('log-ref-filter')).toBeVisible()
  await shot('settings-log-filtered')
  await page.getByRole('link', { name: t.settings.tabAbout }).click()
  await expect(page.getByText(t.settings.about.key)).toBeVisible()
  await shot('settings-about')
})

test('诊断：在路径诊断里真的诊断一对在线的节点，每个标签页截一张', async () => {
  test.setTimeout(120_000)
  const ts = t.tests
  const dg = t.diagnosis
  await goTo(page, t.nav.diagnosis)
  await expect(page.getByText(dg.pickHint)).toBeVisible()
  await shot('diagnosis-pick')
  // 下面一格一格的节点：先点的是 A，再点的是 B。
  const grid = page.getByTestId('node-grid')
  await grid.getByRole('button', { name: 'laptop', exact: true }).click()
  await expect(grid.getByRole('button', { name: /^laptop/ })).toHaveAttribute('aria-pressed', 'true')
  await shot('diagnosis-pick-a')
  await grid.getByRole('button', { name: 'gw-hk', exact: true }).click()
  await expect(page.getByTestId('path-forward')).toBeVisible()
  // 完整的诊断默认连吞吐一起量。
  await expect(page.getByRole('checkbox', { name: new RegExp(ts.throughput) })).toBeChecked()
  await page.getByRole('button', { name: dg.run }).click()
  await expect(page.getByTestId('test-state')).toHaveText(ts.state.done, { timeout: 60_000 })
  await expect(page.getByTestId('check-latency')).toHaveAttribute('data-status', 'pass')
  await shot('diagnosis-test')
  // 报告在面板里滚动，整页截图只有一屏：滚到各节再截。
  for (const section of ['path', 'latency', 'routing', 'hosts'] as const) {
    await page.locator(`#report-${section}`).scrollIntoViewIfNeeded()
    await shot(`diagnosis-${section}`, { fullPage: false })
  }
})

test('找不到的东西', async () => {
  await page.goto(`${controller.baseUrl}/n/1/nodes/999`)
  await expect(page.getByText(t.nodes.detail.notFoundTitle)).toBeVisible()
  await shot('node-not-found')
  await page.goto(`${controller.baseUrl}/n/42/overview`)
  await expect(page.getByText(t.networks.notFoundTitle)).toBeVisible()
  await shot('network-not-found')
})

test('窄一些的笔记本宽度', async () => {
  await page.setViewportSize({ width: 1024, height: 720 })
  await page.goto(`${controller.baseUrl}/n/1/nodes`)
  await expect(page.getByTestId('node-row-gw-hk')).toBeVisible()
  await shot('narrow-nodes')
  await page.getByRole('link', { name: 'gw-hk', exact: true }).click()
  await expect(page.getByRole('combobox', { name: t.nodes.detail.groups })).toBeVisible()
  await shot('narrow-node-detail')
  await goTo(page, t.nav.access)
  await expect(page.getByTestId('rule-row-2')).toBeVisible()
  await shot('narrow-access-rules')
  await page.getByRole('radio', { name: t.access.viewGraph }).click()
  await expect(page.getByTestId('group-graph')).toBeVisible()
  await shot('narrow-access-graph')
  await goTo(page, t.nav.forwards)
  await expect(page.getByTestId('forward-row-web')).toBeVisible()
  await shot('narrow-forwards')
  await page.goto(`${controller.baseUrl}/n/1/topology?a=3&b=2`)
  await expect(page.getByTestId('pair-panel')).toBeVisible()
  await shot('narrow-topology-pair')
  await page.goto(`${controller.baseUrl}/n/1/diagnosis?a=3&b=2`)
  await expect(page.getByTestId('path-forward')).toBeVisible()
  await shot('narrow-diagnosis')
  await page.goto(`${controller.baseUrl}/settings/updates`)
  await expect(page.getByTestId('updates-tab')).toBeVisible()
  await shot('narrow-settings-updates')
  await page.getByRole('button', { name: t.nav.collapse }).click()
  await goTo(page, t.nav.overview)
  await expect(page.getByTestId('overview-status')).toBeVisible()
  await shot('narrow-overview-sidebar-collapsed')
})

test('拓扑的骨干', async () => {
  await page.setViewportSize({ width: 1280, height: 800 })
  await page.getByRole('button', { name: t.nav.expand }).click()
  await page.goto(`${controller.baseUrl}/n/1/topology?view=backbone`)
  // 骨干每次现问 relay（最多 3 秒左右），等结果出来再截。这里只有 gw-hk 一个 relay：没有矩阵，只有它的状态。
  await expect(page.getByTestId('backbone').getByText(t.topology.backbone.oneRelay)).toBeVisible({ timeout: 15_000 })
  await shot('topology-backbone')
})

/**
 * ice3proxy（0.1.26 起是代理的一个选项）：gw-hk 的 relay 换一个这台机器上真的连得上的 TCP 地址（它在回环上的节点端口）；
 * gw-hk 上开一个经 nas-home 出去、打开了 ice3proxy 的代理，经它访问本机局域网地址上的服务：一条一直开着的连接，
 * 加一次下载。laptop 上再开一个经 nas-home、也打开了的：两端都不是 relay，不起作用。节点对上只剩连接常驻和拥塞控制。
 * 放在中文这一组的最后，前面截图的编号不变。
 */
test('ice3proxy', async () => {
  test.setTimeout(150_000)
  const net = '/networks/1'
  const px = t.proxies
  const l = px.lane
  const port = Number(/^port = (\d+)$/m.exec(readFileSync(join(nodes.gw?.dir ?? '', 'config.toml'), 'utf8'))?.[1] ?? 0)
  await controller.api('PUT', `${net}/nodes/1/relay`, {
    udp: ['203.0.113.7:20330'],
    tcp: [`127.0.0.1:${port}`],
    region: 'hk',
    bandwidth_mbps: 200,
  })
  // 出口 nas-home：目标端口不限、不限配额，截图的下载不被前面的设置挡住。
  await controller.api('PUT', `${net}/nodes/2/exit`, { ports: null, lan: true, quota_bytes: null })
  const lanePort = await freePort()
  await controller.api('POST', `${net}/proxies`, {
    name: 'hk-nas',
    node: 1,
    bind: `127.0.0.1:${lanePort}`,
    protocol: 'socks5',
    exit: 2,
    username: 'lane',
    password: 'lane-password',
    lane: true,
  })
  await controller.api('POST', `${net}/proxies`, {
    name: 'laptop-nas',
    node: 3,
    bind: `127.0.0.1:${await freePort()}`,
    protocol: 'socks5',
    exit: 2,
    username: 'lane',
    password: 'lane-password',
    lane: true,
  })
  await controller.api('PUT', `${net}/pairs/1/3`, { keep_alive: false, congestion: 'cubic' })
  interface LaneProxy {
    name: string
    lanes: { lanes: { in_use: number; sealed_bytes: number } }[]
  }
  const sides = async () =>
    (await controller.api<LaneProxy[]>('GET', `${net}/proxies`)).find((item) => item.name === 'hk-nas')?.lanes ?? []
  await expect.poll(async () => (await sides()).length, { timeout: 40_000 }).toBe(2)

  if (lanIp !== undefined) {
    holder = createHttpServer((_request, response) => {
      response.writeHead(200, { 'Content-Type': 'text/plain' })
      response.write('holding\n')
    })
    const holdPort = await listenOn(holder, '0.0.0.0')
    const proxy = `socks5h://lane:lane-password@127.0.0.1:${lanePort}`
    hold = spawn('curl', ['-s', '-m', '170', '-o', '/dev/null', '-x', proxy, `http://${lanIp}:${holdPort}/`], {
      stdio: 'ignore',
    })
    await download(proxy)
    await expect
      .poll(async () => (await sides()).some((side) => side.lanes.in_use > 0 && side.lanes.sealed_bytes > 0), {
        timeout: 40_000,
      })
      .toBe(true)
  }

  await goTo(page, t.nav.proxies)
  await expect(page.getByTestId('proxy-lane-hk-nas')).toContainText(lanIp === undefined ? l.effective : l.inUse, {
    timeout: 20_000,
  })
  await expect(page.getByTestId('proxy-lane-laptop-nas')).toContainText(l.blocked)
  await shot('proxies-lanes')
  await page.getByRole('button', { name: l.detailsFor('gw-hk', 'nas-home') }).click()
  await expect(page.getByTestId('lane-details-hk-nas')).toBeVisible()
  await shot('proxies-lanes-details')
  await page.getByRole('button', { name: l.detailsHide, exact: true }).click()

  await page.getByRole('button', { name: px.create }).first().click()
  const create = page.getByRole('dialog', { name: px.dialog.createTitle })
  await create.getByRole('switch', { name: l.title }).click()
  await shot('proxies-dialog-lane', { fullPage: false })
  await create.getByRole('button', { name: t.common.cancel, exact: true }).click()
  await page.getByRole('button', { name: t.common.discardConfirm }).click()

  // 节点对：每一对都列出来，gw-hk ⇄ laptop 改过（自定义），其余写默认。
  await goToAdmin(page, t.nav.pairs)
  await expect(page.getByTestId('pair-setting-gw-hk-laptop')).toContainText(t.pairs.settingCustom)
  await expect(page.getByTestId('pair-setting-nas-home-office-pc')).toContainText(t.pairs.settingDefault)
  await shot('pairs-all')
})

/**
 * 英文的一组：英文通常比中文长，挑长度最要紧的几页（登录、总览、节点列表和详情、出口这种列多的表、
 * 两个对话框、拓扑、1024 宽的页面、节点对）。浏览器的语言是 en-US，界面第一次打开时自己选英文。
 * 放在 screenshots/en/ 下面，编号自己从 1 开始。
 */
test('英文：长度最要紧的几页', async ({ browser }) => {
  test.setTimeout(120_000)
  const dir = join(outDir, 'en')
  mkdirSync(dir, { recursive: true })
  const context = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 800 } })
  const english = await context.newPage()
  let count = 0
  const enShot = async (name: string, options: { fullPage?: boolean } = {}) => {
    count += 1
    await english.waitForLoadState('networkidle')
    if (options.fullPage ?? true) await english.evaluate(() => window.scrollTo(0, 0))
    await english.waitForTimeout(250)
    await english.screenshot({
      path: join(dir, `${String(count).padStart(2, '0')}-${name}.png`),
      fullPage: options.fullPage ?? true,
    })
  }

  await english.goto(`${controller.baseUrl}/`)
  await expect(english.getByRole('heading', { name: en.signIn.title })).toBeVisible()
  await expect(english.locator('html')).toHaveAttribute('lang', 'en')
  await enShot('sign-in')
  await english.getByLabel(en.signIn.tokenLabel, { exact: true }).fill(controller.adminToken)
  await english.getByRole('button', { name: en.signIn.submit, exact: true }).click()

  await expect(english.getByTestId('overview-status')).toBeVisible()
  await enShot('overview')

  await english.goto(`${controller.baseUrl}/n/1/nodes`)
  await expect(english.getByTestId('node-row-gw-hk')).toBeVisible()
  await enShot('nodes')

  await english.getByRole('link', { name: 'gw-hk', exact: true }).click()
  await english.getByRole('tab', { name: en.nodes.detail.tabRelay }).click()
  await expect(english.getByTestId('capability-relay')).toBeVisible()
  await enShot('node-detail-relay')

  await english.goto(`${controller.baseUrl}/n/1/nodes/2?tab=exit`)
  await expect(english.getByTestId('capability-exit')).toBeVisible()
  await enShot('node-detail-exit')

  await english.goto(`${controller.baseUrl}/n/1/nodes`)
  await english.getByRole('button', { name: en.nodes.add }).click()
  await expect(english.getByRole('dialog', { name: en.addNode.title })).toBeVisible()
  await enShot('add-node-dialog', { fullPage: false })
  await english.getByRole('button', { name: en.addNode.done }).click()

  await english.goto(`${controller.baseUrl}/n/1/groups`)
  await expect(english.getByTestId('group-row-servers')).toBeVisible()
  await enShot('groups')
  await english.getByRole('button', { name: en.common.actionsFor('home') }).click()
  await english.getByRole('menuitem', { name: en.groups.menuDelete }).click()
  await expect(english.getByRole('alertdialog', { name: en.groups.deleteTitle('home') })).toBeVisible()
  await enShot('groups-delete-confirm', { fullPage: false })
  await english.getByRole('button', { name: en.common.cancel, exact: true }).click()
  await english.goto(`${controller.baseUrl}/n/1/nodes`)
  await english.getByRole('checkbox', { name: en.nodes.selectOne('laptop') }).check()
  await english.getByRole('checkbox', { name: en.nodes.selectOne('office-pc') }).check()
  await english.getByRole('button', { name: en.nodes.batchRemoveGroup }).click()
  await expect(english.getByRole('dialog', { name: en.nodes.batchRemoveTitle(2) })).toBeVisible()
  await enShot('nodes-batch-group', { fullPage: false })
  await english.getByRole('button', { name: en.common.cancel, exact: true }).click()
  await english.goto(`${controller.baseUrl}/n/1/nodes/3`)
  await english.getByRole('combobox', { name: en.nodes.detail.groups }).click()
  await expect(english.getByRole('listbox', { name: en.groups.picker.options })).toBeVisible()
  await enShot('node-detail-group-picker', { fullPage: false })
  await english.keyboard.press('Escape')

  await english.goto(`${controller.baseUrl}/n/1/forwards`)
  await expect(english.getByTestId('forward-row-web')).toBeVisible()
  const fd = en.forwards.dialog
  await english.getByRole('button', { name: en.forwards.create }).click()
  const forward = english.getByRole('dialog', { name: fd.createTitle })
  await forward.getByRole('group', { name: fd.listenSide }).getByRole('combobox', { name: fd.node }).click()
  await english.getByRole('option', { name: /laptop/ }).click()
  await expect(english.getByRole('listbox')).toHaveCount(0)
  await forward.getByRole('group', { name: fd.targetSide }).getByRole('combobox', { name: fd.node }).click()
  await english.getByRole('option', { name: /nas-home/ }).click()
  await forward.getByRole('radio', { name: new RegExp(literal(fd.whoOpen)) }).click()
  await expect(english.getByTestId('forward-check')).toBeVisible()
  await enShot('forwards-dialog', { fullPage: false })
  await forward.getByRole('button', { name: en.common.cancel, exact: true }).click()
  await english.getByRole('button', { name: en.common.discardConfirm }).click()

  await english.goto(`${controller.baseUrl}/n/1/topology?a=3&b=2`)
  await expect(english.getByTestId('pair-panel')).toBeVisible()
  await enShot('topology-pair')

  // 诊断报告：结果表和各条路的明细在英文里最长。laptop 和 gw-hk 在前面诊断过。
  await english.goto(`${controller.baseUrl}/n/1/diagnosis?a=3&b=1`)
  await expect(english.getByTestId('report-result')).toBeVisible()
  await expect(english.getByTestId('test-state')).toHaveText(en.tests.state.done)
  await enShot('diagnosis')
  await english.locator('#report-latency').scrollIntoViewIfNeeded()
  await expect(english.getByTestId('test-quality')).toBeVisible()
  await enShot('diagnosis-latency', { fullPage: false })

  await english.goto(`${controller.baseUrl}/settings/updates`)
  await expect(english.getByTestId('updates-tab')).toBeVisible()
  await enShot('settings-updates')

  await english.setViewportSize({ width: 1024, height: 720 })
  await english.goto(`${controller.baseUrl}/n/1/nodes`)
  await english.getByRole('link', { name: 'gw-hk', exact: true }).click()
  await expect(english.getByRole('combobox', { name: en.nodes.detail.groups })).toBeVisible()
  await enShot('narrow-node-detail')

  await english.setViewportSize({ width: 1280, height: 800 })
  await english.goto(`${controller.baseUrl}/n/1/pairs`)
  await expect(english.getByTestId('pair-row-gw-hk-laptop')).toBeVisible()
  await expect(english.locator('main')).not.toContainText(/\p{Script=Han}/u)
  await enShot('pairs')

  // 英文的页面上不该有界面自己写的中文（节点报来的原话除外：这几页上没有）。
  await english.goto(`${controller.baseUrl}/n/1/nodes`)
  await expect(english.locator('main')).not.toContainText(/\p{Script=Han}/u)
  await context.close()
})
