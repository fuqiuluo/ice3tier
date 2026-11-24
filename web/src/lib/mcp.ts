import { API_PREFIX, MCP_PATH } from '@/api/client'
import { type McpScope } from '@/api/types'

/**
 * MCP 令牌的固定值：有哪些权限、哪些管的是整个 controller 的事、能签多久。和 controller 的一致
 * （`crates/i3t-model/src/admin/mcp.rs`）。
 */

/** 现在有的全部权限，按文档里列出的顺序。 */
export const MCP_SCOPES = [
  'read',
  'nodes:enroll',
  'nodes:write',
  'config:write',
  'tests:run',
  'updates:write',
  'networks:write',
] as const satisfies readonly McpScope[]

/** 管整个 controller 的事的权限（更新设置、建删网络）：不能签给只限一个网络的令牌。 */
const GLOBAL_SCOPES: readonly string[] = ['updates:write', 'networks:write'] satisfies McpScope[]

export function isGlobalScope(scope: string): boolean {
  return GLOBAL_SCOPES.includes(scope)
}

const DAY = 24 * 60 * 60

/** 一个 MCP 令牌最长能用多久，天。签发时必须写过期时间，不能比这更长。 */
export const MCP_MAX_LIFETIME_DAYS = 90

/** 签发时可以选的有效期，天。最长的那个就是上限。 */
export const MCP_LIFETIME_DAYS = [1, 7, 30, MCP_MAX_LIFETIME_DAYS] as const

export const DEFAULT_MCP_LIFETIME_DAYS = 30

export function lifetimeSecs(days: number): number {
  return days * DAY
}

/**
 * Agent 要连的 MCP 端点：管理 API 的地址加上 MCP 的路径。WebUI 和管理 API 同源，
 * 所以 `origin` 就是打开这个界面的地址（`window.location.origin`）。
 */
export function mcpEndpoint(origin: string): string {
  return `${origin}${API_PREFIX}${MCP_PATH}`
}
