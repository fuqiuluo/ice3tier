import { useQuery } from '@tanstack/react-query'
import { KeyRound, Plus } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'

import { api } from '@/api/endpoints'
import { q, useAction } from '@/api/queries'
import { type McpTokenInfo, type McpTokenState, type Network } from '@/api/types'
import { useConfirm } from '@/components/confirm'
import { CodeBlock, CopyText } from '@/components/copy'
import { EmptyState, ErrorState, SkeletonRows } from '@/components/states'
import { StatusText, type Tone } from '@/components/status'
import { Table, Td, Th, Tr } from '@/components/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardHeader } from '@/components/ui/card'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { mcpEndpoint } from '@/lib/mcp'
import { formatDateTime, formatFullTime, formatRemaining } from '@/lib/time'
import { useNow } from '@/lib/useNow'
import { networkPath } from '@/pages/networks/context'

import { McpTokenDialog } from './McpTokenDialog'

const m = t.settings.mcp

/** 表格的列数：名字、状态、权限、网络、过期时间、操作。 */
const COLUMNS = 6

/** 比界面新的 controller 可能报出这里不认识的状态：查不到，用不活动的灰，名字原样写出来。 */
const STATE_TONES: Partial<Record<string, Tone>> = {
  active: 'ok',
  expired: 'idle',
  revoked: 'idle',
  unknown: 'idle',
} satisfies Record<McpTokenState, Tone>

/** 一项权限：写它的代码（各语言、命令行、JWT 里都是这个写法），悬停看它管什么。不认识的只写代码。 */
function Scope({ scope }: { scope: string }) {
  const name = m.scopeNames[scope]
  const hint = m.scopeHints[scope]
  return (
    <Tooltip content={name !== undefined && hint !== undefined ? m.scopeTip(name, hint) : undefined}>
      <Badge tabIndex={0} className="font-mono font-normal">
        {scope}
      </Badge>
    </Tooltip>
  )
}

interface TokenRowProps {
  token: McpTokenInfo
  networks: readonly Network[]
  revoking: boolean
  onRevoke: (token: McpTokenInfo) => void
}

/** 一个令牌一行。名字下面是它的 jti：操作记录里靠它认是哪一个，名字可以重复。 */
function TokenRow({ token, networks, revoking, onRevoke }: TokenRowProps) {
  const now = useNow()
  const active = token.state === 'active'
  const network = networks.find((candidate) => candidate.id === token.network)
  const remaining = active ? formatRemaining(token.expires_at, now) : null
  return (
    <Tr dimmed={!active} data-testid={`mcp-token-row-${token.id}`} data-state={token.state}>
      <Td cell="main">
        <div className="font-medium">{token.name}</div>
        <div className="mt-0.5 flex items-center gap-1 text-xs text-muted-foreground">
          {/* JWT 里的字段名，各种语言里都一样。 */}
          <span aria-hidden>JTI</span>
          <CopyText value={token.jti} className="text-xs" />
        </div>
      </Td>
      <Td cell="row" label={m.colState} className="whitespace-nowrap">
        <Tooltip content={token.revoked_at === null ? undefined : m.revokedAt(formatFullTime(token.revoked_at))}>
          <span tabIndex={token.revoked_at === null ? undefined : 0} className="rounded-sm">
            <StatusText tone={STATE_TONES[token.state] ?? 'idle'}>{m.state[token.state] ?? token.state}</StatusText>
          </span>
        </Tooltip>
      </Td>
      <Td cell="row" label={m.colScopes}>
        <span className="inline-flex flex-wrap gap-1">
          {token.scopes.map((scope) => (
            <Scope key={scope} scope={scope} />
          ))}
        </span>
      </Td>
      <Td cell="row" label={m.colNetwork} className="text-[13px] whitespace-nowrap">
        {token.network === null ? (
          <span className="text-muted-foreground">{m.anyNetwork}</span>
        ) : network === undefined ? (
          <span className="text-muted-foreground">{m.networkGone(token.network)}</span>
        ) : (
          <Link to={networkPath(network.id)} className="rounded-sm hover:text-primary hover:underline">
            {network.name}
          </Link>
        )}
      </Td>
      <Td cell="row" label={m.colExpires} className="whitespace-nowrap">
        <div className="text-[13px] tabular">{formatDateTime(token.expires_at)}</div>
        {remaining !== null ? <div className="text-xs text-muted-foreground">{m.remaining(remaining)}</div> : null}
      </Td>
      <Td cell="end" className="text-right">
        {/* 过期的、撤销了的没有什么可撤销的。 */}
        {active ? (
          <Button
            size="sm"
            variant="ghost"
            pending={revoking}
            onClick={() => onRevoke(token)}
            aria-label={m.revokeFor(token.name)}
          >
            {m.revoke}
          </Button>
        ) : null}
      </Td>
    </Tr>
  )
}

/**
 * 设置里的「MCP 令牌」：controller 自己就是一个 MCP Server，这里签发、列出、撤销 Agent 连它时带的令牌。
 * 这些接口只认管理令牌，MCP 令牌自己做不了（不然 Agent 能给自己升权限）。
 *
 * 上面一块是端点的地址，带复制；下面是签过的令牌：还能用的、过期的、撤销的都在（过期 30 天之后 controller 清掉）。
 * 签发在对话框里，JWT 只在签发之后显示一次；撤销之前问一句，它不能恢复。
 */
export function McpTab() {
  const confirm = useConfirm()
  const tokens = useQuery(q.mcpTokens())
  // 只限一个网络的令牌写网络的名字；签发时也从这里选。
  const networks = useQuery(q.networks())
  const [issuing, setIssuing] = useState(false)
  const endpoint = mcpEndpoint(window.location.origin)

  const revoke = useAction(null, {
    mutationFn: (token: McpTokenInfo) => api.revokeMcpToken(token.id),
    success: (_data, token) => m.revoked(token.name),
  })

  const onRevoke = async (token: McpTokenInfo) => {
    const confirmed = await confirm({
      tone: 'danger',
      title: m.revokeTitle(token.name),
      body: m.revokeBody,
      confirmLabel: m.revokeConfirm,
    })
    if (confirmed) revoke.mutate(token)
  }

  const list = tokens.data ?? []
  const empty = tokens.isSuccess && list.length === 0
  const allNetworks = networks.data ?? []
  const issueButton = (
    <Button variant="primary" size="sm" onClick={() => setIssuing(true)}>
      <Plus aria-hidden />
      {m.issue}
    </Button>
  )

  return (
    <div className="space-y-12" data-testid="mcp-tab">
      <Card className="max-w-[44rem]">
        <CardHeader title={m.endpointTitle} description={m.endpointBody} />
        <CodeBlock copy={endpoint} label={m.endpointTitle} testId="mcp-endpoint">
          {endpoint}
        </CodeBlock>
      </Card>
      <Card>
        {/* 空的时候签发的按钮在下面那一块里，这里不再放一个。 */}
        <CardHeader title={m.title} description={m.body} action={empty ? undefined : issueButton} />
        {tokens.isError && tokens.data === undefined ? (
          <ErrorState title={m.loadFailed} error={tokens.error} onRetry={() => void tokens.refetch()} />
        ) : empty ? (
          <EmptyState icon={KeyRound} title={m.emptyTitle} description={m.emptyBody} action={issueButton} />
        ) : (
          <Table stack>
            <thead>
              <tr>
                <Th>{m.colName}</Th>
                <Th>{m.colState}</Th>
                <Th>{m.colScopes}</Th>
                <Th>{m.colNetwork}</Th>
                <Th>{m.colExpires}</Th>
                <Th className="w-0">
                  <span className="sr-only">{t.common.moreActions}</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {tokens.isPending ? <SkeletonRows columns={COLUMNS} rows={3} /> : null}
              {list.map((token) => (
                <TokenRow
                  key={token.id}
                  token={token}
                  networks={allNetworks}
                  revoking={revoke.isPending && revoke.variables.id === token.id}
                  onRevoke={(target) => void onRevoke(target)}
                />
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {/* 每次打开都是一份新的状态：上一次签发的令牌不会留在这里。 */}
      {issuing ? <McpTokenDialog networks={allNetworks} onClose={() => setIssuing(false)} /> : null}
    </div>
  )
}
