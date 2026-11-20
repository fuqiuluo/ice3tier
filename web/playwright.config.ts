import { defineConfig, devices } from '@playwright/test'

/**
 * 端到端测试。每个测试文件自己启动一个全新的 controller（见 e2e/controller.ts），用完停掉，
 * 所以这里没有 webServer，也不需要事先开着什么。
 *
 * - flows：从空的 controller 开始把主要流程走一遍；路由视图（拓扑、矩阵、路径诊断）；节点更新；
 *   限额、用量和监听的状态（真的经节点走流量）；独占 TCP（真的经它走流量）；分组（访问真的跟着分组和规则变）；
 *   手机那么宽的屏幕上的版面。`pnpm e2e`
 * - screenshots：把每个页面在有数据和没数据时的样子截下来，放到 screenshots/。`pnpm screenshots`
 */
export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results',
  // 一个文件里的测试共用一个 controller，前一步造出来的数据后一步要用，所以顺序执行。
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  forbidOnly: process.env.CI !== undefined,
  reporter: [['list']],
  use: {
    ...devices['Desktop Chrome'],
    viewport: { width: 1280, height: 800 },
    locale: 'zh-CN',
    timezoneId: 'Asia/Shanghai',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'flows',
      testMatch: [
        'flows.spec.ts',
        'routes.spec.ts',
        'updates.spec.ts',
        'limits.spec.ts',
        'lanes.spec.ts',
        'groups.spec.ts',
        'mobile.spec.ts',
      ],
    },
    { name: 'screenshots', testMatch: 'screenshots.spec.ts' },
  ],
})
