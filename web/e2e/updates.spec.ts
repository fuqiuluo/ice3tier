import { chmodSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { expect, type Page, test } from '@playwright/test'

import { Controller, type NodeHandle } from './controller'
import { clearToasts, expectToast, goTo, goToAdmin, literal, signIn, t } from './helpers'
import { platformName, type ReleaseKit, releaseKit, ReleaseSource } from './release'

/**
 * 节点更新，对着一个发布源是本机目录的 controller：
 * 发布用 `i3t-release` 和一把测试钥匙签，controller 和节点都认这把钥匙（`pnpm e2e:kit` 编的）。
 *
 * 三个真的跑着的节点：able 能自己更新（有自己的一份程序文件，由看护的循环拉起来，换了程序能重启）；
 * boxed 以为自己在容器里；locked 的程序在一个不可写的目录里。
 * 走一遍：换发布源、立即检查、节点列表和详情上的标记与做法、确认框、全部更新（able 真的换成新版本重启）、
 * 一个自检不过的版本被暂停、看原因、继续。
 */

const NET = '/networks/1'

interface ApiNode {
  id: number
  name: string
  version: string
  update: { failure: { version: string } | null }
}

let controller: Controller
let page: Page
let kit: ReleaseKit
let release: ReleaseSource
const nodes = {} as Record<'able' | 'boxed' | 'locked', { handle: NodeHandle; id: number }>

/** 版本号的修订号加几：自检不过的那个"坏"版本用。 */
function bump(version: string, by: number): string {
  const [major, minor, patch] = version.split('.')
  return `${major}.${minor}.${Number(patch) + by}`
}

async function apiNode(id: number): Promise<ApiNode> {
  return controller.api<ApiNode>('GET', `${NET}/nodes/${id}`)
}

async function openUpdates(): Promise<void> {
  await goToAdmin(page, t.nav.settings)
  await page.getByRole('link', { name: t.updates.tab }).click()
  await expect(page.getByTestId('updates-tab')).toBeVisible()
}

test.describe.configure({ mode: 'serial' })

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120_000)
  kit = releaseKit()
  controller = await Controller.start({ bins: kit.oldBins })
  page = await browser.newPage({ locale: 'zh-CN' })
})

test.afterAll(async () => {
  await page.close()
  await controller.stop()
})

test('准备：三个节点，一个能自己更新、一个在容器里、一个程序目录不可写', async () => {
  await controller.api('POST', '/networks', { name: 'home' })
  for (const [index, name] of (['able', 'boxed', 'locked'] as const).entries()) {
    const handle = await controller.enroll()
    const id = index + 1
    await controller.api('PATCH', `${NET}/nodes/${id}`, { name })
    nodes[name] = { handle, id }
  }
  await controller.run(nodes.able.handle, { program: controller.ownProgram(nodes.able.handle), supervised: true })
  await controller.run(nodes.boxed.handle, {
    program: controller.ownProgram(nodes.boxed.handle),
    env: { container: 'podman' },
  })
  await controller.run(nodes.locked.handle, { program: controller.ownProgram(nodes.locked.handle, { readOnly: true }) })
  await controller.waitOnline(3)
  release = new ReleaseSource(join(controller.dir, 'releases'), kit)
  release.publish(kit.newVersion, kit.newProgram)
})

test('关掉自动更新，把发布源换成本机目录，立即检查：查到新版本和各平台的包', async () => {
  await signIn(page, controller)
  await openUpdates()

  const u = t.updates
  await page.getByRole('switch', { name: u.auto.label }).click()
  await expectToast(page, u.auto.turnedOff)
  await expect(page.getByText(u.auto.off)).toBeVisible()
  expect((await controller.api<{ auto_update: boolean }>('GET', '/update')).auto_update).toBe(false)

  // 默认的发布源查不到时（这里没有发布，或者连不上）这一块自己展开着；否则点开。
  const dirChoice = page.getByRole('radio', { name: new RegExp(literal(u.source.kindDir)) })
  if (!(await dirChoice.isVisible())) await page.locator('summary', { hasText: u.source.title }).click()
  await dirChoice.click()
  const input = page.getByLabel(u.source.dirLabel)
  await input.fill('releases')
  await expect(page.getByText(u.source.dirInvalid)).toBeVisible()
  await expect(page.getByRole('button', { name: u.source.save, exact: true })).toBeDisabled()
  await input.fill(release.root)
  await page.getByRole('button', { name: u.source.save, exact: true }).click()
  await expectToast(page, u.source.saved)
  await expect(page.getByTestId('source-summary')).toHaveText(u.source.summaryDir(release.root))
  await clearToasts(page)

  await page.getByRole('button', { name: u.release.check }).click()
  await expect(page.getByTestId('check-result')).toHaveText(u.release.found(kit.newVersion, 3))
  await expect(page.getByTestId('release-version')).toHaveText(u.release.latest(kit.newVersion))
  await expect(page.getByTestId(`package-${platformName()}`)).toContainText(`i3t-${platformName()}`)
  // 发布比 controller 新：controller 要手动更新，界面提醒；顶栏的版本号上也有一个去节点更新的小点。
  await expect(page.getByText(u.release.controllerNewer(kit.oldVersion, kit.newVersion))).toBeVisible()
  const badge = page.getByTestId('version-badge')
  await expect(badge).toHaveAttribute('href', '/settings/updates')
  await expect(badge).toHaveAccessibleName(new RegExp(literal(t.version.newer(kit.newVersion))))
  await expect(page.getByTestId('update-summary')).toHaveText(
    u.nodes.summary({ total: 3, up_to_date: 0, updating: 0, outdated: 1, failed: 0, manual: 2 }),
  )
  await expect(page.getByTestId('update-row-boxed')).toContainText(u.state.cannotSelf)
  await expect(
    page.getByTestId('update-row-boxed').getByRole('button', { name: u.force.buttonFor('boxed') }),
  ).toBeDisabled()
  await expect(
    page.getByTestId('update-row-able').getByRole('button', { name: u.force.buttonFor('able') }),
  ).toBeEnabled()
})

test('节点列表标出有新版本和要手动更新的；详情里写出不能自己更新的原因和做法', async () => {
  await goTo(page, t.nav.nodes)
  await expect(page.getByTestId('node-row-able').getByTestId('update-mark-available')).toBeVisible()
  await expect(page.getByTestId('node-row-boxed').getByTestId('update-mark-manual')).toBeVisible()
  const u = t.updates

  // 概览上版本右边的"升级到"：不能自己更新的点开是手动的做法。
  await page.getByRole('link', { name: 'boxed', exact: true }).click()
  await page.getByRole('button', { name: u.detail.upgrade(kit.newVersion) }).click()
  await expect(page.getByTestId('node-self-update')).toContainText(u.blocker.container)
  await expect(page.getByTestId('node-self-update')).toContainText(u.blocker.containerHow)
  await page.keyboard.press('Escape')

  await page.goto(`${controller.baseUrl}/n/1/nodes/${nodes.locked.id}`)
  await page.getByRole('button', { name: u.detail.upgrade(kit.newVersion) }).click()
  await expect(page.getByTestId('node-self-update')).toContainText(u.blocker.read_only_dir)
  await expect(page.getByTestId('node-self-update').locator('pre')).toContainText('curl -fLo i3t')
})

test('立即更新的确认框写出后果；取消就什么都不发', async () => {
  await page.goto(`${controller.baseUrl}/n/1/nodes/${nodes.able.id}`)
  const u = t.updates
  await page.getByRole('button', { name: u.detail.upgrade(kit.newVersion) }).click()
  const dialog = page.getByRole('dialog', { name: u.force.title('able', kit.newVersion) })
  await expect(dialog).toContainText(u.force.idleBody)
  await dialog.getByRole('button', { name: t.common.cancel, exact: true }).click()
  await expect(dialog).toBeHidden()
  expect((await apiNode(nodes.able.id)).version).toBe(kit.oldVersion)
})

test('全部更新（排空后）：跳过的节点写出原因；能更新的那个真的换成新版本重启', async () => {
  test.setTimeout(150_000)
  await openUpdates()
  const u = t.updates
  await page.getByRole('button', { name: u.nodes.updateAll }).click()
  const dialog = page.getByRole('dialog', { name: u.forceAll.title(kit.newVersion) })
  await expect(dialog).toContainText(u.forceAll.body(1))
  await dialog.getByRole('radio', { name: new RegExp(literal(u.force.afterDrain)) }).click()
  await dialog.getByRole('button', { name: u.forceAll.confirmDrain }).click()
  await expect(dialog).toBeHidden()
  const result = page.getByTestId('force-all-result')
  await expect(result).toContainText('able')
  await expect(result).toContainText('boxed')
  await expect(result).toContainText('locked')

  // 节点取包、自检、换程序、以"请重启我"退出，看护的循环把新程序拉起来，连上 controller 才算完。
  await expect
    .poll(async () => (await apiNode(nodes.able.id)).version, { timeout: 120_000, intervals: [1_000] })
    .toBe(kit.newVersion)
  await expect(page.getByTestId('update-row-able')).toContainText(kit.newVersion, { timeout: 20_000 })
  await expect(page.getByTestId('update-row-able')).toContainText(u.state.confirmed(kit.newVersion))
})

test('自检不过的版本：自动更新被暂停，看原因，继续', async () => {
  test.setTimeout(150_000)
  const broken = bump(kit.oldVersion, 7)
  const program = join(controller.dir, 'broken-i3t')
  writeFileSync(program, "#!/bin/sh\necho '这个程序在这台机器上跑不了：缺一个库' >&2\nexit 127\n")
  chmodSync(program, 0o755)
  release.publish(broken, program)

  const u = t.updates
  await page.getByRole('button', { name: u.release.check }).click()
  await expect(page.getByTestId('release-version')).toHaveText(u.release.latest(broken))
  await page.getByRole('switch', { name: u.auto.label }).click()
  await expectToast(page, u.auto.turnedOn)
  await clearToasts(page)

  // able 取包、跑新程序的自检，不过；controller 暂停这个版本。节点的原话（"缺一个库"）作为补充显示。
  const banner = page.getByText(u.paused.title(broken, 'able'))
  await expect(banner).toBeVisible({ timeout: 90_000 })
  const reason = page.getByTestId(`paused-reason-${broken}`)
  await expect(reason).toBeHidden()
  await page.getByRole('button', { name: u.paused.reason }).click()
  await expect(reason).toContainText('缺一个库')
  await expect(page.getByTestId('update-row-able')).toContainText(u.state.failed)
  await expect(page.getByTestId('update-row-able')).toContainText('缺一个库')
  // 设置里「节点更新」旁边有一个红点。
  await expect(page.getByRole('navigation', { name: t.settings.tabsLabel }).getByText(u.pausedDot)).toBeAttached()
  // 节点没有换程序。
  expect((await apiNode(nodes.able.id)).version).toBe(kit.newVersion)

  await page.getByRole('button', { name: u.paused.resume }).click()
  const question = page.getByRole('alertdialog', { name: u.paused.resumeTitle(broken) })
  await expect(question).toContainText(u.paused.resumeBody(broken, 'able'))
  await question.getByRole('button', { name: u.paused.resumeConfirm }).click()
  await expectToast(page, u.paused.resumed(broken))
  await expect(banner).toHaveCount(0)
  expect((await controller.api<{ paused: unknown[] }>('GET', '/update')).paused).toEqual([])
})
