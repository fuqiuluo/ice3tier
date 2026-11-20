import { expect, type Locator, type Page, test } from '@playwright/test'

import { Controller } from './controller'
import { literal, signIn, t } from './helpers'

/**
 * 手机那么宽的屏幕：导航在抽屉里，访问地图竖着排，表格的一行排成一块，对话框贴着底边，
 * 只是说明的东西点一下弹出，页面不横向滚动。
 * 节点只注册、不跑：这里看的是版面，不是连通。
 */

const NET = '/networks/1'
const PHONE = { width: 390, height: 844 }
const LONG_NAME = 'a-node-with-a-rather-long-name'

let controller: Controller
let page: Page

/** 页面和正文都没有横向的滚动：放不下的东西在自己那一块里处理。 */
async function expectNoSidewaysScroll(): Promise<void> {
  const overflow = await page.evaluate(() => {
    const main = document.querySelector('main')
    return {
      page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      main: main === null ? 0 : main.scrollWidth - main.clientWidth,
    }
  })
  expect(overflow).toEqual({ page: 0, main: 0 })
}

async function box(locator: Locator): Promise<{ x: number; y: number; width: number; height: number }> {
  const rect = await locator.boundingBox()
  if (rect === null) throw new Error('这个元素没有画出来')
  return rect
}

function sidebar(): Locator {
  return page.getByRole('navigation', { name: t.nav.label })
}

test.describe.configure({ mode: 'serial' })

test.beforeAll(async ({ browser }) => {
  test.setTimeout(120_000)
  controller = await Controller.start()
  page = await browser.newPage({ locale: 'zh-CN', viewport: PHONE, hasTouch: true, isMobile: true })
  await controller.api('POST', '/networks', { name: 'home' })
  const servers = await controller.api<{ id: number }>('POST', `${NET}/groups`, { name: 'servers' })
  await controller.enroll({ groups: [servers.id] })
  await controller.enroll()
  await controller.api('PATCH', `${NET}/nodes/1`, { name: 'gw' })
  await controller.api('PATCH', `${NET}/nodes/2`, { name: LONG_NAME })
})

test.afterAll(async () => {
  await page.close()
  controller.stop()
})

test('访问地图竖着排：看的那个节点和画布一样宽，按原大小画', async () => {
  await signIn(page, controller)
  const subject = page.getByRole('button', { name: new RegExp(literal(t.overview.map.pickNode)) })
  await expect(subject).toBeVisible()
  // 三列横着排的话，缩到放得下时这一块只有一百来像素宽。
  expect((await box(subject)).width).toBeGreaterThan(300)
  await expectNoSidewaysScroll()
})

test('导航在抽屉里：顶栏的按钮打开，点一项就关上', async () => {
  await expect(sidebar()).toBeHidden()
  await page.getByRole('button', { name: t.nav.openMenu }).click()
  await expect(sidebar()).toBeVisible()
  await sidebar().getByRole('link', { name: t.nav.nodes, exact: true }).click()
  await expect(page).toHaveURL(/\/nodes$/)
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: t.nodes.title, level: 1 })).toBeVisible()
})

test('节点列表一行排成一块：虚拟 IP 在名字下面，长名字截断，不横向滚动', async () => {
  const row = page.getByTestId(`node-row-${LONG_NAME}`)
  const name = row.getByRole('link', { name: LONG_NAME })
  const ip = row.getByText('10.66.0.2', { exact: true })
  await expect(ip).toBeVisible()
  const nameBox = await box(name)
  expect((await box(ip)).y).toBeGreaterThanOrEqual(nameBox.y + nameBox.height)
  const rowBox = await box(row)
  expect(rowBox.x + rowBox.width).toBeLessThanOrEqual(PHONE.width)
  await expectNoSidewaysScroll()
})

test('对话框贴着底边，和屏幕一样宽', async () => {
  await page.getByRole('button', { name: t.nodes.add }).click()
  const dialog = page.getByRole('dialog', { name: t.addNode.title })
  await expect(dialog).toBeVisible()
  // 它是从下面升上来的：等它停住。
  await expect
    .poll(async () => {
      const rect = await box(dialog)
      return { x: rect.x, width: rect.width, bottom: Math.round(rect.y + rect.height) }
    })
    .toEqual({ x: 0, width: PHONE.width, bottom: PHONE.height })
  await page.getByRole('button', { name: t.common.close }).click()
  await expect(dialog).toHaveCount(0)
})

test('节点详情：说明点一下弹出，再点别处收起；页面不横向滚动', async () => {
  await page.getByTestId(`node-row-${LONG_NAME}`).getByRole('link', { name: LONG_NAME }).click()
  await expect(page.getByRole('heading', { name: LONG_NAME, level: 1 })).toBeVisible()
  await expectNoSidewaysScroll()

  const tip = page.getByText(t.nodes.detail.hostnameHint)
  await expect(tip).toHaveCount(0)
  await page.getByRole('button', { name: t.common.details }).first().tap()
  await expect(tip.first()).toBeVisible()
  await page.getByRole('heading', { name: LONG_NAME, level: 1 }).tap()
  await expect(tip).toHaveCount(0)
})

test('策略、代理、端口转发、节点对、设置：都不横向滚动', async () => {
  for (const path of ['access', 'groups', 'proxies', 'forwards', 'pairs', 'topology', 'diagnosis', 'network']) {
    await page.goto(`${controller.baseUrl}/n/1/${path}`)
    await expect(page.locator('main h1').first()).toBeVisible()
    await expectNoSidewaysScroll()
  }
  for (const tab of ['session', 'updates', 'log', 'about']) {
    await page.goto(`${controller.baseUrl}/settings/${tab}`)
    await expect(page.locator('main h1').first()).toBeVisible()
    await expectNoSidewaysScroll()
  }
})
