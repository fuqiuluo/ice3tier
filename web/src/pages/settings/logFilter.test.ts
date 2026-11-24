import { describe, expect, it } from 'vitest'

import { type LogEntry } from '@/api/types'
import { t } from '@/i18n'

import {
  actorLabel,
  EMPTY_LOG_FILTER,
  hasServerFilter,
  isFiltered,
  logFilterToParams,
  logFilterToQuery,
  logJtis,
  logPathFor,
  logSentence,
  matchesSearch,
  parseLogFilter,
  parseRef,
  refTarget,
} from './logFilter'

const params = (text: string) => new URLSearchParams(text)

describe('操作记录的筛选写在地址里', () => {
  it('什么都没写：没有条件', () => {
    expect(parseLogFilter(params(''))).toEqual(EMPTY_LOG_FILTER)
    expect(isFiltered(EMPTY_LOG_FILTER)).toBe(false)
  })

  it('网络、操作、对象、搜索词都读得出来', () => {
    const filter = parseLogFilter(params('network=2&action=credential.revoke&ref=credential:5&q=phone'))
    expect(filter).toEqual({
      network: 2,
      action: 'credential.revoke',
      ref: { kind: 'credential', id: 5 },
      search: 'phone',
    })
  })

  it('写法不对的条件当作没写：链接可能是手改过的', () => {
    const filter = parseLogFilter(params('network=abc&action=Node!&ref=widget:3'))
    expect(filter).toEqual(EMPTY_LOG_FILTER)
    expect(parseLogFilter(params('network=0')).network).toBeNull()
    expect(parseLogFilter(params('network=1.5')).network).toBeNull()
    expect(parseLogFilter(params('ref=node:0')).ref).toBeNull()
    expect(parseLogFilter(params('ref=node:x')).ref).toBeNull()
  })

  it('写回地址再读出来是一样的；默认值不写进地址', () => {
    const filter = { network: 1, action: 'node', ref: { kind: 'node', id: 3 }, search: 'nas' }
    const written = logFilterToParams(filter)
    expect(written.toString()).toBe('network=1&action=node&ref=node%3A3&q=nas')
    expect(parseLogFilter(written)).toEqual(filter)
    expect(logFilterToParams(EMPTY_LOG_FILTER).toString()).toBe('')
  })
})

describe('交给 controller 的条件', () => {
  it('网络、操作、对象交给 controller；搜索不交', () => {
    const filter = { network: 1, action: 'node', ref: { kind: 'node', id: 3 }, search: 'nas' }
    expect(logFilterToQuery(filter)).toEqual({ network: 1, action: 'node', ref: 'node:3' })
    expect(logFilterToQuery({ ...EMPTY_LOG_FILTER, search: 'x' })).toEqual({
      network: undefined,
      action: undefined,
      ref: undefined,
    })
  })

  it('只有搜索词时不算 controller 那边的条件', () => {
    expect(hasServerFilter({ ...EMPTY_LOG_FILTER, search: 'x' })).toBe(false)
    expect(isFiltered({ ...EMPTY_LOG_FILTER, search: 'x' })).toBe(true)
    expect(hasServerFilter({ ...EMPTY_LOG_FILTER, action: 'group' })).toBe(true)
  })

  it('对象的写法和 controller 认的一样', () => {
    expect(parseRef('forward:12')).toEqual({ kind: 'forward', id: 12 })
    expect(parseRef(' token:1 ')).toEqual({ kind: 'token', id: 1 })
    expect(parseRef('group:7')).toEqual({ kind: 'group', id: 7 })
    expect(parseRef('node')).toBeNull()
    expect(parseRef('route:1')).toBeNull()
  })
})

describe('搜索只在取回的记录里找', () => {
  const entry: LogEntry = {
    id: 9,
    at: 1,
    network: 1,
    action: 'credential.revoke',
    detail: '凭据 #1 phone',
    refs: [],
  }

  it('找说明、操作的名字和操作本身，不分大小写', () => {
    expect(matchesSearch(entry, 'PHONE', '吊销凭据')).toBe(true)
    expect(matchesSearch(entry, '吊销', '吊销凭据')).toBe(true)
    expect(matchesSearch(entry, 'credential.revoke', '吊销凭据')).toBe(true)
    expect(matchesSearch(entry, 'tablet', '吊销凭据')).toBe(false)
    expect(matchesSearch(entry, '  ', '吊销凭据')).toBe(true)
  })
})

describe('MCP 令牌的操作按参数写成一句话', () => {
  const entry = (action: string, params?: Record<string, unknown>): LogEntry => ({
    id: 1,
    at: 1,
    network: null,
    action,
    detail: '',
    refs: [],
    params,
  })
  const say = t.settings.log.sentences

  it('签发：编号、名字、权限、限不限网络', () => {
    const params = { token: 3, name: 'claude-code', jti: 'abc', scopes: ['read', 'nodes:enroll'], expires_at: 9 }
    expect(logSentence(entry('mcp.token.create', { ...params, network: 1, network_name: 'home' }))).toBe(
      say.mcpTokenCreate(3, 'claude-code', 'read、nodes:enroll', 'home'),
    )
    expect(logSentence(entry('mcp.token.create', { ...params, network: null, network_name: null }))).toBe(
      say.mcpTokenCreate(3, 'claude-code', 'read、nodes:enroll', null),
    )
    // 网络的名字没有记下来：写编号。
    expect(logSentence(entry('mcp.token.create', { ...params, network: 7 }))).toBe(
      say.mcpTokenCreate(3, 'claude-code', 'read、nodes:enroll', '#7'),
    )
  })

  it('撤销、换签名密钥', () => {
    expect(logSentence(entry('mcp.token.revoke', { token: 3, name: 'claude-code', jti: 'abc' }))).toBe(
      say.mcpTokenRevoke(3, 'claude-code'),
    )
    expect(logSentence(entry('mcp.key.rotate', { revoked: 2 }))).toBe(say.mcpKeyRotate(2))
  })

  it('参数不全、写法不对的，和别的操作：不写句子，由调用的地方写操作的名字', () => {
    expect(logSentence(entry('mcp.token.create'))).toBeNull()
    expect(logSentence(entry('mcp.token.create', { token: 3, name: 'x' }))).toBeNull()
    expect(logSentence(entry('mcp.token.create', { token: '3', name: 'x', scopes: [] }))).toBeNull()
    expect(logSentence(entry('mcp.token.revoke', { token: 3 }))).toBeNull()
    expect(logSentence(entry('mcp.key.rotate', { revoked: 'many' }))).toBeNull()
    expect(logSentence(entry('node.update', { node: 2, name: 'laptop' }))).toBeNull()
  })

  it('谁做的：MCP 令牌写它的名字；没有就不写；不认识的种类原样写', () => {
    const by = (actor: LogEntry['actor']): LogEntry => ({ ...entry('node.update'), actor })
    expect(actorLabel(by({ kind: 'mcp', name: 'claude-code', jti: 'abc' }))).toBe(
      t.settings.log.actor.mcp('claude-code'),
    )
    expect(actorLabel(by(null))).toBeNull()
    expect(actorLabel(entry('node.update'))).toBeNull()
    expect(actorLabel(by({ kind: 'oidc', name: 'alice', jti: 'x' }))).toBe('oidc alice')
  })

  it('搜索用的 jti：做这件事的令牌的，和这条记录说的那个令牌的', () => {
    expect(logJtis({ ...entry('node.update'), actor: { kind: 'mcp', name: 'a', jti: 'abc' } })).toEqual(['abc'])
    expect(logJtis(entry('mcp.token.revoke', { token: 3, name: 'a', jti: 'def' }))).toEqual(['def'])
    expect(logJtis(entry('node.update', { node: 2 }))).toEqual([])
  })
})

describe('记录里提到的东西，点了去哪里', () => {
  it('网络里的东西去它所在的页面，列表页上那一行亮出来', () => {
    expect(refTarget({ kind: 'node', id: 3 }, 1)).toBe('/n/1/nodes/3')
    expect(refTarget({ kind: 'rule', id: 2 }, 1)).toBe('/n/1/access?rule=2')
    expect(refTarget({ kind: 'group', id: 9 }, 1)).toBe('/n/1/groups?focus=9')
    expect(refTarget({ kind: 'credential', id: 5 }, 1)).toBe('/n/1/proxies')
    expect(refTarget({ kind: 'proxy', id: 6 }, 1)).toBe('/n/1/proxies')
    expect(refTarget({ kind: 'forward', id: 7 }, 1)).toBe('/n/1/forwards?focus=7')
    // 用掉的令牌默认不列出，要切到"全部"。
    expect(refTarget({ kind: 'token', id: 8 }, 1)).toBeNull()
  })

  it('网络本身去它的设置页，不需要记录属于哪个网络', () => {
    expect(refTarget({ kind: 'network', id: 4 }, null)).toBe('/n/4/network')
  })

  it('不知道是哪个网络的、不认识的种类：不做成链接', () => {
    expect(refTarget({ kind: 'node', id: 3 }, null)).toBeNull()
    expect(refTarget({ kind: 'gadget', id: 3 }, 1)).toBeNull()
  })

  it('一样东西的操作记录：按它筛、限定在它的网络里', () => {
    expect(logPathFor({ kind: 'node', id: 3 }, 1)).toBe('/settings/log?network=1&ref=node%3A3')
  })
})
