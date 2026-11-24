import { t } from '@/i18n'

import { type ErrorBody, type KnownErrorCode } from './types'

/** 管理 API 所有路径的前缀。WebUI 和 API 同源，所以这里没有主机名。 */
export const API_PREFIX = '/api/v1'

/** Prometheus 的指标。不在 `API_PREFIX` 下面，也不要管理令牌。 */
export const METRICS_PATH = '/metrics'

/**
 * MCP 端点在 `API_PREFIX` 下面的路径：AI Agent 连的是它。它认的是 MCP 令牌，不认管理令牌；
 * 签发、列出、撤销 MCP 令牌的接口在它下面（`/mcp/tokens`），只认管理令牌。
 */
export const MCP_PATH = '/mcp'

/**
 * 一次失败的请求。
 *
 * `code` 给程序看：服务器给的错误码原样放在这里；连不上时是 `network`；应答不是约定的格式时是 `http_<状态码>`。
 * `message` 是服务器给的原话，没给就按状态码写一句；显示给人看时用 {@link errorMessage}，它按码和当前的语言写。
 */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  /** controller 给的原话；它没有给（连不上、不是约定的应答）时是 `null`。 */
  readonly server: string | null
  /** 比 `code` 更具体的一层；controller 说不出来、或者它比这个字段旧时是 `null`。 */
  readonly what: string | null
  /** 请求里出问题的那一项；不是某一项的问题时是 `null`。 */
  readonly field: string | null

  constructor(
    status: number,
    code: string,
    message: string,
    server: string | null = null,
    what: string | null = null,
    field: string | null = null,
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.server = server
    this.what = what
    this.field = field
  }

  is(...codes: KnownErrorCode[]): boolean {
    return (codes as string[]).includes(this.code)
  }

  /** 连不上 controller（请求根本没有得到应答）。 */
  get isNetwork(): boolean {
    return this.code === 'network'
  }
}

interface ClientHooks {
  /** 现在登录用的管理令牌；没登录时是 `null`。 */
  getToken: () => string | null
  /** 带着令牌的请求得到了 401：令牌作废了，要回到登录页。 */
  onUnauthorized: () => void
  /** 每次请求之后报告 controller 连不连得上，用来显示和撤掉"连接断开"的横幅。 */
  onReachability: (reachable: boolean) => void
}

let hooks: ClientHooks = {
  getToken: () => null,
  onUnauthorized: () => undefined,
  onReachability: () => undefined,
}

export function configureClient(next: Partial<ClientHooks>): void {
  hooks = { ...hooks, ...next }
}

export type Query = Record<string, string | number | undefined>

export interface RequestOptions {
  body?: unknown
  query?: Query
  /** 用这个令牌而不是已登录的那个。登录页检查令牌时用；这时 401 不会触发退出。 */
  token?: string
  signal?: AbortSignal
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

function buildUrl(path: string, query?: Query): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined) search.set(key, String(value))
  }
  const suffix = search.size > 0 ? `?${search.toString()}` : ''
  return `${API_PREFIX}${path}${suffix}`
}

function isErrorBody(value: unknown): value is ErrorBody {
  if (typeof value !== 'object' || value === null || !('error' in value)) return false
  const { error } = value
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string' &&
    'message' in error &&
    typeof error.message === 'string'
  )
}

async function toApiError(response: Response): Promise<ApiError> {
  let parsed: unknown
  try {
    parsed = await response.json()
  } catch {
    parsed = undefined
  }
  if (isErrorBody(parsed)) {
    const { code, message, what, field } = parsed.error
    return new ApiError(
      response.status,
      code,
      message,
      message,
      typeof what === 'string' ? what : null,
      typeof field === 'string' ? field : null,
    )
  }
  // 不是 controller 写的应答（例如开发时代理报的 502）：按状态码说一句。
  return new ApiError(response.status, `http_${response.status}`, t.errors.http(response.status))
}

/**
 * 发一个请求，返回解析好的应答体。`204` 返回 `undefined`。
 *
 * 失败时抛出 {@link ApiError}；被 `signal` 取消时抛出原来的 `AbortError`。
 */
export async function request<T>(method: Method, path: string, options: RequestOptions = {}): Promise<T> {
  const token = options.token ?? hooks.getToken()
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token !== null) headers.Authorization = `Bearer ${token}`

  let body: string | undefined
  if (method !== 'GET' && method !== 'DELETE') {
    // POST、PUT、PATCH 都要带 JSON 请求体，没有要写的字段时写 {}。
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.body ?? {})
  }

  let response: Response
  try {
    response = await fetch(buildUrl(path, options.query), { method, headers, body, signal: options.signal })
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    hooks.onReachability(false)
    throw new ApiError(0, 'network', t.errors.network)
  }
  hooks.onReachability(true)

  if (!response.ok) {
    const error = await toApiError(response)
    if (response.status === 401 && options.token === undefined) hooks.onUnauthorized()
    throw error
  }
  if (response.status === 204) return undefined as T
  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError(response.status, 'bad_response', t.errors.badResponse)
  }
}

/**
 * 这几个错误码太笼统，光看码说不清是什么问题：界面写自己的一句，controller 的原话作为补充（{@link errorDetail}）。
 * 别的码本身就说清了问题，原话不再显示。
 */
const VAGUE_CODES: readonly string[] = ['invalid_request', 'not_found', 'conflict', 'internal']

function codeText(code: string): string | undefined {
  const codes: Record<KnownErrorCode, string> = t.errors.codes
  return Object.hasOwn(codes, code) ? codes[code as KnownErrorCode] : undefined
}

/**
 * 码加上 `what` 才说得清的几种（分组的错误）。`what` 是 `group`、`builtin` 时只会是分组的事，
 * 所以不必知道是哪个请求。分组名字的写法不对（`what` 是 `empty`、`too_long`、`malformed`）不在这里：
 * 别的名字也用这几个 `what`，由分组的表单自己写（`groupNameFailure`）。
 */
function specificText(error: ApiError): string | undefined {
  if (error.code === 'not_found' && error.what === 'group') return t.errors.group.notFound
  if (error.code === 'name_taken' && error.what === 'group') return t.errors.group.nameTaken
  if (error.code === 'invalid_request' && error.what === 'builtin') return t.errors.group.builtin
  return undefined
}

/**
 * 把任何抛出来的东西写成一句可以显示的话，用当前的语言。管理 API 的错误按错误码写界面自己的话，
 * 不用 controller 的原话（它是中文的，见 {@link errorDetail}）。
 */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'network') return t.errors.network
    if (error.code === 'bad_response') return t.errors.badResponse
    return specificText(error) ?? codeText(error.code) ?? t.errors.http(error.status)
  }
  if (error instanceof Error && error.message !== '') return error.message
  return t.errors.unknown
}

/**
 * controller 对这次错误的原话，作为 {@link errorMessage} 下面的补充显示；码已经说清楚时是 `null`。
 * 原话是 controller 写的中文，界面没有办法翻译它。
 */
export function errorDetail(error: unknown): string | null {
  if (!(error instanceof ApiError) || error.server === null) return null
  if (specificText(error) !== undefined) return null
  const known = codeText(error.code) !== undefined
  if (known && !VAGUE_CODES.includes(error.code)) return null
  return error.server === errorMessage(error) ? null : error.server
}
