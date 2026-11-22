import { QueryClient } from '@tanstack/react-query'
import { render, type RenderResult } from '@testing-library/react'
import { type ReactElement } from 'react'
import { MemoryRouter } from 'react-router'
import { vi } from 'vitest'

import { configureClient } from '@/api/client'
import { type Network } from '@/api/types'
import { Providers } from '@/App'
import { NetworkContext } from '@/pages/networks/context'

/**
 * 组件测试用的两样东西：一个假的管理 API（接住 fetch，按"方法 路径"应答），
 * 和一个把组件连同它需要的上下文一起渲染出来的函数。
 */

export interface ApiCall {
  method: string
  /** 不带 `/api/v1` 前缀，也不带查询参数。 */
  path: string
  query: URLSearchParams
  body: unknown
  headers: Record<string, string>
}

/** 一个接口的应答：一个 JSON 值（按 200 回），`undefined`（回 204），或者一个现成的应答（见 {@link apiFailure}）。 */
export type Reply = object | undefined

/** 根据请求算出应答。 */
export type Handler = (call: ApiCall) => Reply

export type Routes = Record<string, Reply | Handler>

/** controller 拒绝请求时的应答：`{ error: { code, message } }`。 */
export function apiFailure(status: number, code: string, message: string): Response {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

export interface FakeApi {
  /** 收到过的请求，按先后。 */
  calls: ApiCall[]
  /** 某个接口被调过的那些次。`key` 是 `"POST /networks/1/tokens"` 这样的写法。 */
  callsTo: (key: string) => ApiCall[]
  /** 换掉或者加上一些接口的应答。 */
  use: (routes: Routes) => void
}

/**
 * 接住 `fetch`。`routes` 的键是 `"GET /networks/1/nodes"` 这样的写法；没列出来的接口回 404，和真的 controller 一样。
 * 默认已经登录（令牌是 `test-token`）。
 */
export function fakeApi(routes: Routes = {}): FakeApi {
  let table = { ...routes }
  const calls: ApiCall[] = []

  const handler: typeof fetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input), 'http://controller.test')
    const call: ApiCall = {
      method: init?.method ?? 'GET',
      path: url.pathname.replace(/^\/api\/v1/, ''),
      query: url.searchParams,
      body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined,
      headers: (init?.headers ?? {}) as Record<string, string>,
    }
    calls.push(call)
    const key = `${call.method} ${call.path}`
    if (!(key in table)) return Promise.resolve(apiFailure(404, 'not_found', `测试里没有准备这个接口：${key}`))
    const route = table[key]
    const reply = typeof route === 'function' ? (route as Handler)(call) : route
    if (reply instanceof Response) return Promise.resolve(reply)
    if (reply === undefined) return Promise.resolve(new Response(null, { status: 204 }))
    return Promise.resolve(
      new Response(JSON.stringify(reply), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
  }

  vi.stubGlobal('fetch', vi.fn(handler))
  configureClient({ getToken: () => 'test-token', onUnauthorized: () => undefined, onReachability: () => undefined })

  return {
    calls,
    callsTo: (key) => calls.filter((call) => `${call.method} ${call.path}` === key),
    use: (more) => {
      table = { ...table, ...more }
    },
  }
}

export const NETWORK: Network = {
  id: 1,
  name: 'home',
  domain: 'home.i3t',
  cidr: '10.66.0.0/16',
  routing: 'direct_first',
  max_relay_hops: 2,
  reach: 'any',
  created_at: 1_794_000_000,
  nodes: 0,
  class: null,
  ack_eliciting_threshold: 3,
  max_ack_delay_ms: 2,
  bundle_small_packets: true,
  vnet_offload: true,
  vnet_mtu: 1280,
  defaults: {
    routing: 'direct_first',
    max_relay_hops: 2,
    reach: 'any',
    class: null,
    ack_eliciting_threshold: 3,
    max_ack_delay_ms: 2,
    bundle_small_packets: true,
    vnet_offload: true,
    vnet_mtu: 1280,
  },
}

interface RenderOptions {
  /** 一开始所在的地址。 */
  route?: string
  /** 给了就把组件放进这个网络的页面里（`useNetwork()` 拿得到）。 */
  network?: Network
}

/** 把组件连同路由、查询缓存、确认框、通知一起渲染出来。每次都是新的查询缓存，测试之间不串。 */
export function renderWithApp(ui: ReactElement, options: RenderOptions = {}): RenderResult & { client: QueryClient } {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 5_000 }, mutations: { retry: false } },
  })
  const content = options.network === undefined ? ui : <NetworkContext value={options.network}>{ui}</NetworkContext>
  const result = render(
    <MemoryRouter initialEntries={[options.route ?? '/']}>
      <Providers client={client}>{content}</Providers>
    </MemoryRouter>,
  )
  return Object.assign(result, { client })
}
