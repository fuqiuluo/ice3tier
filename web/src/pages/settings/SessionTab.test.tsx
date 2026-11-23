import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { session } from '@/auth/session'
import { t } from '@/i18n'
import { makeStatus } from '@/test/fixtures'
import { apiFailure, fakeApi, renderWithApp } from '@/test/harness'

import { SessionTab } from './SessionTab'

const s = t.settings.session

describe('设置里的登录', () => {
  it('安装脚本装出来的 controller：重置的命令是填好了的三条，说明里不再让人去停', async () => {
    fakeApi({ 'GET /status': makeStatus() })
    renderWithApp(<SessionTab />, { route: '/settings/session' })
    const command = await screen.findByTestId('reset-token-command')
    expect(command.textContent).toBe(
      [
        'sudo systemctl stop i3t-controller',
        'sudo -u i3t-controller /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --reset-admin-token',
        'sudo systemctl start i3t-controller',
      ].join('\n'),
    )
    expect(screen.getByText(s.resetService)).toBeVisible()
    expect(screen.queryByText(t.signIn.lostBody)).not.toBeInTheDocument()
  })

  it('用镜像跑的 controller：重置的命令是 docker compose 的三条', async () => {
    fakeApi({ 'GET /status': makeStatus({ data_dir: '/data' }) })
    renderWithApp(<SessionTab />, { route: '/settings/session' })
    expect((await screen.findByTestId('reset-token-command')).textContent).toBe(
      [
        'docker compose stop controller',
        'docker compose run --rm controller --reset-admin-token',
        'docker compose start controller',
      ].join('\n'),
    )
    expect(screen.getByText(s.resetService)).toBeVisible()
  })

  it('别的装法：一条命令，数据目录是这个 controller 的；说明里写先停', async () => {
    fakeApi({ 'GET /status': makeStatus({ data_dir: '/srv/i3t' }) })
    renderWithApp(<SessionTab />, { route: '/settings/session' })
    expect((await screen.findByTestId('reset-token-command')).textContent).toBe(
      'i3t-controller --data-dir /srv/i3t --reset-admin-token',
    )
    expect(screen.getByText(t.signIn.lostBody)).toBeVisible()
  })

  it('取不到 controller 的状态：退回带占位符的那条', async () => {
    fakeApi({ 'GET /status': apiFailure(500, 'internal', '数据库忙') })
    renderWithApp(<SessionTab />, { route: '/settings/session' })
    expect((await screen.findByTestId('reset-token-command')).textContent).toBe(t.signIn.lostCommand)
    expect(screen.getByText(t.signIn.lostBody)).toBeVisible()
  })

  it('令牌存在哪里照实写：保持登录的在浏览器里，没勾的只在这个标签页', () => {
    fakeApi({ 'GET /status': makeStatus() })
    session.signIn('i3t-admin', true)
    const first = renderWithApp(<SessionTab />, { route: '/settings/session' })
    expect(screen.getByText(s.stored)).toBeVisible()
    first.unmount()

    session.signIn('i3t-admin', false)
    renderWithApp(<SessionTab />, { route: '/settings/session' })
    expect(screen.getByText(s.tabOnly)).toBeVisible()
    expect(screen.queryByText(s.stored)).not.toBeInTheDocument()
  })

  it('退出登录：令牌从浏览器里清掉', async () => {
    const user = userEvent.setup()
    fakeApi({ 'GET /status': makeStatus() })
    session.signIn('i3t-admin', true)
    renderWithApp(<SessionTab />, { route: '/settings/session' })
    await user.click(screen.getByRole('button', { name: s.signOut }))
    await waitFor(() => expect(session.token()).toBeNull())
    expect(session.remembered()).toBe(false)
    expect(session.takeSignOutReason()).toBe('manual')
  })
})
