import { type ChildProcess, execFile, spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { createServer as createHttpServer, type Server as HttpServer, type ServerResponse } from 'node:http'
import { createServer as createTcpServer } from 'node:net'
import { networkInterfaces } from 'node:os'
import { join } from 'node:path'

import { expect, type Page, test } from '@playwright/test'

import { Controller, type NodeHandle } from './controller'
import { clearToasts, expectToast, goTo, goToAdmin, literal, signIn, t } from './helpers'

/**
 * ice3proxy（lane），0.1.26 起是代理的一个选项：三个真的跑着的节点，都在这台机器的回环地址上。
 *
 * - gw 启用了 relay（TCP 地址是它在回环上的节点端口），也是出口；laptop 上开一个经 gw 出去的代理，新建时打开
 *   ice3proxy：生效，laptop 拨号。经这个代理真的走流量（目标是本机局域网地址上的一个 HTTP 服务）：一条一直开着的
 *   连接让"在用"不是 0，展开看两端的计数，有加密搬运的字节。再在编辑里关掉。
 * - nas 也是出口，但 laptop 和 nas 都不是 relay：laptop 经 nas 的代理打开 ice3proxy 不起作用，界面按原因码说为什么，
 *   给出去启用 relay 的那一步。
 * - 节点对页上没有 ice3proxy 了，只有连接常驻和拥塞控制。
 */

const NET = '/networks/1'
const MB = 1024 * 1024
const px = t.proxies
const l = t.proxies.lane

interface ApiProxy {
  id: number
  name: string
  lane: boolean
  lane_effect: { effective: boolean; dialers: number[]; blocked: { reason: string }[] } | null
  lanes: { node: number; lanes: { in_use: number; sealed_bytes: number } }[]
}

let controller: Controller
let page: Page
let http: HttpServer
let httpPort = 0
let proxyPort = 0
let lanIp: string | undefined
let hold: ChildProcess | undefined
/** 一直不结束的应答：结束测试时一起关掉。 */
const holding: ServerResponse[] = []
const nodes = {} as Record<'gw' | 'laptop' | 'nas', { handle: NodeHandle; id: number }>

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

async function freePort(): Promise<number> {
  const server = createTcpServer()
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  await new Promise((resolve) => server.close(resolve))
  return address !== null && typeof address === 'object' ? address.port : 0
}

/** 节点的端口（UDP；relay 在同一个端口号上听 TCP），`Controller.run` 写在它的配置里。 */
function nodePort(node: NodeHandle): number {
  const match = /^port = (\d+)$/m.exec(readFileSync(join(node.dir, 'config.toml'), 'utf8'))
  return Number(match?.[1] ?? 0)
}

/** 这台机器的一个私有 IPv4 地址：出口访问它要打开"允许访问局域网"，回环地址出口不让访问。 */
function privateIpv4(): string | undefined {
  const candidates = Object.values(networkInterfaces())
    .flat()
    .filter((address) => address !== undefined && address.family === 'IPv4' && !address.internal)
    .map((address) => address?.address ?? '')
  const isPrivate = (ip: string) =>
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    (ip.startsWith('10.') && !ip.startsWith('10.66.'))
  return candidates.find((ip) => ip.startsWith('192.168.')) ?? candidates.find(isPrivate)
}

/** 经代理下载那个文件。异步地等：目标就在这个进程里。 */
function download(): Promise<number> {
  return new Promise((resolve) => {
    execFile(
      'curl',
      [
        '-s',
        '-m',
        '20',
        '-o',
        '/dev/null',
        '-x',
        `socks5h://e2e:e2e-password@127.0.0.1:${proxyPort}`,
        `http://${lanIp ?? ''}:${httpPort}/blob`,
      ],
      (error) => resolve(error === null ? 0 : typeof error.code === 'number' ? error.code : -1),
    )
  })
}

async function proxy(name: string): Promise<ApiProxy | undefined> {
  const list = await controller.api<ApiProxy[]>('GET', `${NET}/proxies`)
  return list.find((item) => item.name === name)
}

test.describe.configure({ mode: 'serial' })

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120_000)
  lanIp = privateIpv4()
  const blob = Buffer.alloc(4 * MB, 'l')
  http = createHttpServer((request, response) => {
    if (request.url === '/hold') {
      // 一条一直开着的连接：它在的时候，经它的那条 ice3proxy 一直在用。
      response.writeHead(200, { 'Content-Type': 'text/plain' })
      response.write('holding\n')
      holding.push(response)
      return
    }
    response.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': blob.length })
    response.end(blob)
  })
  httpPort = await listen(http, '0.0.0.0')
  controller = await Controller.start()
  page = await browser.newPage({ locale: 'zh-CN' })
})

test.afterAll(async () => {
  hold?.kill('SIGKILL')
  for (const response of holding) response.destroy()
  await page.close()
  await controller.stop()
  http.close()
})

test('准备：gw 是 relay（TCP 地址在回环上）也是出口；nas 是出口、不是 relay；laptop 开代理', async () => {
  test.skip(lanIp === undefined, '这台机器没有私有 IPv4 地址，经出口访问局域网目标的测试做不了')
  test.setTimeout(120_000)
  await controller.api('POST', '/networks', { name: 'home' })
  const gw = await controller.enroll({ flags: ['--can-relay', '--can-exit'] })
  const laptop = await controller.enroll()
  const nas = await controller.enroll({ flags: ['--can-exit'] })
  nodes.gw = { handle: gw, id: 1 }
  nodes.laptop = { handle: laptop, id: 2 }
  nodes.nas = { handle: nas, id: 3 }
  for (const name of ['gw', 'laptop', 'nas'] as const) {
    await controller.api('PATCH', `${NET}/nodes/${nodes[name].id}`, { name })
    await controller.run(nodes[name].handle)
  }
  await controller.waitOnline(3)
  const port = nodePort(gw)
  await controller.api('PUT', `${NET}/nodes/${nodes.gw.id}/relay`, {
    udp: [`127.0.0.1:${port}`],
    tcp: [`127.0.0.1:${port}`],
  })
  // 目标在本机的局域网地址上：出口要允许访问局域网。
  for (const name of ['gw', 'nas'] as const) {
    await controller.api('PUT', `${NET}/nodes/${nodes[name].id}/exit`, { ports: null, lan: true })
  }
  proxyPort = await freePort()
})

test('新建代理时打开 ice3proxy：生效，laptop 拨号', async () => {
  test.skip(lanIp === undefined, '没有私有 IPv4 地址')
  await signIn(page, controller)
  await goTo(page, t.nav.proxies)
  await page.getByRole('button', { name: px.create }).first().click()
  const add = page.getByRole('dialog', { name: px.dialog.createTitle })
  await add.getByRole('combobox', { name: px.dialog.exit }).click()
  await page.getByRole('option', { name: /gw/ }).click()
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await add.getByRole('combobox', { name: px.dialog.entry }).click()
  await page.getByRole('option', { name: /laptop/ }).click()
  await add.getByRole('radio', { name: px.dialog.whereLocal }).click()
  await add.getByRole('textbox', { name: px.dialog.port }).fill(String(proxyPort))
  await add.getByRole('textbox', { name: px.dialog.username }).fill('e2e')
  await add.getByLabel(px.dialog.password, { exact: true }).fill('e2e-password')
  await add.getByRole('textbox', { name: px.dialog.name }).fill('laptop-gw')
  const toggle = add.getByRole('switch', { name: l.title })
  await expect(toggle).not.toBeChecked()
  await toggle.click()
  await add.getByRole('button', { name: px.dialog.submitCreate }).click()
  await expectToast(page, px.dialog.created('laptop-gw'))

  expect(await proxy('laptop-gw')).toMatchObject({
    lane: true,
    lane_effect: { effective: true, dialers: [nodes.laptop.id] },
  })
  const row = page.getByTestId('proxy-row-laptop-gw')
  await expect(row).toContainText(px.status.listening, { timeout: 30_000 })
  const cell = page.getByTestId('proxy-lane-laptop-gw')
  await expect(cell).toContainText(l.effective)
  await expect(cell).toContainText(l.dials('laptop'))
  await clearToasts(page)
})

test('流量真的走 ice3proxy：在用的连接、详情里两端的计数', async () => {
  test.skip(lanIp === undefined, '没有私有 IPv4 地址')
  test.setTimeout(120_000)
  // 两个节点各自开好控制连接、报上来之后再开流：之前开的流改走共用的连接。
  await expect.poll(async () => (await proxy('laptop-gw'))?.lanes.length ?? 0, { timeout: 40_000 }).toBe(2)
  hold = spawn(
    'curl',
    [
      '-s',
      '-m',
      '110',
      '-o',
      '/dev/null',
      '-x',
      `socks5h://e2e:e2e-password@127.0.0.1:${proxyPort}`,
      `http://${lanIp ?? ''}:${httpPort}/hold`,
    ],
    { stdio: 'ignore' },
  )
  expect(await download()).toBe(0)

  // 节点每 10 秒上报一次；页面每隔一阵重新取代理。
  const cell = page.getByTestId('proxy-lane-laptop-gw')
  await expect(cell).toContainText(l.inUse, { timeout: 45_000 })
  await cell.getByRole('button', { name: l.detailsFor('laptop', 'gw') }).click()
  const details = page.getByRole('table', { name: l.detailsTitle('laptop', 'gw') })
  await expect(details.getByRole('columnheader', { name: 'gw', exact: true })).toBeVisible()
  await expect(details.getByRole('columnheader', { name: 'laptop', exact: true })).toBeVisible()
  const sealed = details.getByRole('row', { name: new RegExp(`^${literal(l.row.sealed)}`) })
  await expect(sealed).toContainText(/\d(\.\d)? MB/, { timeout: 45_000 })
  await expect(details.getByRole('row', { name: new RegExp(`^${literal(l.row.control)}`) })).toContainText(
    l.row.controlUp,
  )
})

test('在编辑里关掉：只有它打开时那一列也不见了', async () => {
  test.skip(lanIp === undefined, '没有私有 IPv4 地址')
  hold?.kill('SIGKILL')
  hold = undefined
  await page.getByRole('button', { name: t.common.actionsFor('laptop-gw') }).click()
  await page.getByRole('menuitem', { name: px.menuEdit }).click()
  const edit = page.getByRole('dialog', { name: px.dialog.editTitle('laptop-gw') })
  await edit.getByRole('switch', { name: l.title }).click()
  await edit.getByRole('button', { name: t.common.save }).click()
  await expectToast(page, px.dialog.saved('laptop-gw'))
  expect(await proxy('laptop-gw')).toMatchObject({ lane: false, lane_effect: null })
  await expect(page.getByTestId('proxy-lane-laptop-gw')).toHaveCount(0)
  await clearToasts(page)
})

test('两个节点都不是 relay：不起作用，说为什么，给出启用 relay 的那一步', async () => {
  test.skip(lanIp === undefined, '没有私有 IPv4 地址')
  await controller.api('POST', `${NET}/proxies`, {
    name: 'laptop-nas',
    node: nodes.laptop.id,
    bind: `127.0.0.1:${await freePort()}`,
    protocol: 'socks5',
    exit: nodes.nas.id,
    username: 'e2e',
    password: 'e2e-password',
    lane: true,
  })
  await page.reload()
  await expect(page.getByTestId('proxy-lane-laptop-nas')).toContainText(l.blocked)
  const blocked = page.getByTestId('proxy-lane-blocked-laptop-nas')
  await expect(blocked).toContainText(l.reason.noRelay('laptop', 'nas'))
  const fix = blocked.getByRole('link', { name: l.fix.enableRelay('laptop') })
  await expect(fix).toHaveAttribute('href', `/n/1/nodes/${nodes.laptop.id}?tab=relay`)
  await fix.click()
  await expect(page.getByTestId('capability-relay')).toBeVisible()
})

test('节点对页上没有 ice3proxy：只有连接常驻和拥塞控制', async () => {
  test.skip(lanIp === undefined, '没有私有 IPv4 地址')
  await controller.api('PUT', `${NET}/pairs/${nodes.gw.id}/${nodes.laptop.id}`, { keep_alive: true })
  await goToAdmin(page, t.nav.pairs)
  const row = page.getByTestId('pair-row-gw-laptop')
  await expect(row.getByRole('switch', { name: t.pairs.toggle('gw', 'laptop') })).toBeChecked()
  await expect(row.getByRole('combobox', { name: t.pairs.congestionSelect('gw', 'laptop') })).toHaveValue('')
  await expect(page.getByText('ice3proxy')).toHaveCount(0)
})
