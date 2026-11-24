import { t } from '@/i18n'
import { MCP_MAX_LIFETIME_DAYS } from '@/lib/mcp'
import { MAX_GROUP_NAME_LEN, MAX_TITLE_LEN } from '@/lib/validate'

import { ApiError, errorDetail, errorMessage } from './client'
import { type KnownErrorCode } from './types'

export interface FormFailure<F extends string> {
  /** 这个错误说的是哪个字段；说不清时是 `null`，显示在整个表单上。 */
  field: F | null
  /** 按错误码写的一句，用当前的语言。 */
  message: string
  /** controller 的原话，码太笼统时作为补充显示（见 `errorDetail`）。 */
  detail: string | null
}

/**
 * 把一次失败的提交归到表单的某个字段上。
 *
 * controller 的错误码能说明问题出在哪一类东西上（名字被占用、地址段重叠），
 * `map` 写明这个表单里每种错误码对应哪个字段；没有列出的错误显示在表单底部。
 */
export function formFailure<F extends string>(
  error: unknown,
  map: Partial<Record<KnownErrorCode, F>>,
): FormFailure<F> | null {
  if (error === null || error === undefined) return null
  const message = errorMessage(error)
  const detail = errorDetail(error)
  if (error instanceof ApiError) {
    const field = (map as Partial<Record<string, F>>)[error.code]
    if (field !== undefined) return { field, message, detail }
  }
  return { field: null, message, detail }
}

/**
 * 新建、改名分组被拒绝时：名字的写法不对、被占用，写在名字下面，用和提交之前的校验一样的话；
 * 别的写在表单底部。
 */
export function groupNameFailure(error: unknown): FormFailure<'name'> | null {
  if (error instanceof ApiError) {
    if (error.code === 'name_taken') return { field: 'name', message: errorMessage(error), detail: null }
    if (error.code === 'invalid_request' && error.field === 'name') {
      const message =
        error.what === 'empty'
          ? t.validate.groupRequired
          : error.what === 'too_long'
            ? t.validate.groupTooLong(MAX_GROUP_NAME_LEN)
            : error.what === 'malformed'
              ? t.validate.groupCharset
              : null
      if (message !== null) return { field: 'name', message, detail: null }
    }
  }
  return formFailure(error, {})
}

/** 签发 MCP 令牌的表单里的几项。`lifetime` 是请求里的 `expires_in_secs`。 */
export type McpTokenField = 'name' | 'scopes' | 'network' | 'lifetime'

/**
 * 签发 MCP 令牌被拒绝时：controller 说了是请求里的哪一项（`field`），就写在那一项下面，
 * 按 `what` 用界面自己的话写；说不清是哪一项的写在表单底部。
 */
export function mcpTokenFailure(error: unknown): FormFailure<McpTokenField> | null {
  if (error instanceof ApiError) {
    const e = t.settings.mcp.errors
    const at = (field: McpTokenField, message: string): FormFailure<McpTokenField> => ({ field, message, detail: null })
    switch (error.field) {
      case 'name':
        return at('name', error.what === 'empty' ? t.validate.titleRequired : e.nameMalformed(MAX_TITLE_LEN))
      case 'scopes':
        return at(
          'scopes',
          error.what === 'empty' ? e.scopesEmpty : error.what === 'not_allowed' ? e.scopesGlobal : e.scopesUnknown,
        )
      case 'network':
        // 选的网络在这期间被删掉了。
        return at('network', error.code === 'not_found' ? e.networkGone : errorMessage(error))
      case 'expires_in_secs':
        return at('lifetime', e.lifetime(MCP_MAX_LIFETIME_DAYS))
    }
  }
  return formFailure(error, {})
}

/** 某个字段该显示的服务器错误。 */
export function fieldError<F extends string>(failure: FormFailure<F> | null, field: F): string | null {
  return failure !== null && failure.field === field ? failure.message : null
}

/** 表单底部该显示的服务器错误。 */
export function formError<F extends string>(failure: FormFailure<F> | null): string | null {
  return failure !== null && failure.field === null ? failure.message : null
}

/** 表单底部那条错误的补充：controller 的原话。 */
export function formErrorDetail<F extends string>(failure: FormFailure<F> | null): string | null {
  return failure !== null && failure.field === null ? failure.detail : null
}
