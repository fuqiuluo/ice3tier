import { describe, expect, it } from 'vitest'

import { t } from '@/i18n'
import { makeForward, makeNode } from '@/test/fixtures'

import { forwardAddress, forwardStatusView } from './status'

const s = t.forwards.status
const NODES = [makeNode(1, 'laptop'), makeNode(2, 'gw-home')]
const traffic = { connections: 1, bytes_up: 512, bytes_down: 8192 }

describe('一条转发的状态', () => {
  it('已经下发、在监听：正常，带着连接数和流量', () => {
    const forward = makeForward(1, 'web', { listen: { state: 'listening', local: '127.0.0.1:8080', ...traffic } })
    const view = forwardStatusView(forward, NODES)
    expect(view).toMatchObject({ tone: 'ok', label: s.active, needsAttention: false })
    expect(view.listen?.traffic).toEqual(traffic)
    expect(forwardAddress(forward, view)).toBe('127.0.0.1:8080')
  })

  it('端口写 0：访问地址是节点挑的那个', () => {
    const forward = makeForward(1, 'web', {
      bind: '127.0.0.1:0',
      listen: { state: 'listening', local: '127.0.0.1:41873', ...traffic },
    })
    const view = forwardStatusView(forward, NODES)
    expect(view.listen?.picked).toBe(41873)
    expect(forwardAddress(forward, view)).toBe('127.0.0.1:41873')
  })

  it('已经下发、但端口被占用：红色，原因里有监听节点的名字和端口', () => {
    const forward = makeForward(1, 'web', {
      listen: { state: 'port_in_use', detail: 'Address already in use', ...traffic },
    })
    const view = forwardStatusView(forward, NODES)
    expect(view).toMatchObject({ tone: 'danger', label: t.listen.portInUse, needsAttention: true })
    expect(view.detail).toBe(t.listen.portInUseDetail('laptop', '8080'))
    expect(view.listen?.reported).toBe('Address already in use')
  })

  it('已经下发、节点还没报：等它上报，不说正常', () => {
    const view = forwardStatusView(makeForward(1, 'web', { listen: null }), NODES)
    expect(view).toMatchObject({ tone: 'idle', label: t.listen.pending, needsAttention: false })
  })

  it('controller 知道的问题先说：停用、规则不让、目标没声明', () => {
    expect(forwardStatusView(makeForward(1, 'web', { status: 'disabled', enabled: false }), NODES).label).toBe(
      s.disabled,
    )
    expect(forwardStatusView(makeForward(1, 'web', { status: 'access_denied' }), NODES)).toMatchObject({
      linkToRules: true,
      needsAttention: true,
      detail: s.accessDeniedDetail('laptop', 'gw-home'),
    })
    expect(forwardStatusView(makeForward(1, 'web', { status: 'target_not_declared' }), NODES).tone).toBe('warn')
    expect(forwardStatusView(makeForward(1, 'web', { status: 'target_not_allowed' }), NODES)).toMatchObject({
      tone: 'danger',
      needsAttention: true,
      linkToRules: false,
      label: s.targetNotAllowed,
      detail: s.targetNotAllowedDetail,
    })
  })
})
