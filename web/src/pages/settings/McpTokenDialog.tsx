import { useId, useState } from 'react'

import { api } from '@/api/endpoints'
import { fieldError, formError, formErrorDetail, mcpTokenFailure } from '@/api/formErrors'
import { useAction } from '@/api/queries'
import { type CreateMcpToken, type McpScope, type McpTokenInfo, type Network, type NetworkId } from '@/api/types'
import { CodeBlock } from '@/components/copy'
import { FormDialog } from '@/components/form-dialog'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogBody, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field } from '@/components/ui/field'
import { Input, NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n'
import { claudeMcpAddCommand } from '@/lib/commands'
import { formatList } from '@/lib/format'
import {
  DEFAULT_MCP_LIFETIME_DAYS,
  isGlobalScope,
  lifetimeSecs,
  MCP_LIFETIME_DAYS,
  MCP_MAX_LIFETIME_DAYS,
  MCP_SCOPES,
  mcpEndpoint,
} from '@/lib/mcp'
import { formatDateTime } from '@/lib/time'
import { cn } from '@/lib/utils'
import { validateTitle } from '@/lib/validate'

const m = t.settings.mcp

/** 新开的表单里勾着的权限：只读。别的由管理员自己加。 */
const DEFAULT_SCOPES: readonly McpScope[] = ['read']

/** 刚签发的令牌。JWT 只在这里：对话框关了就没有了。 */
interface Issued {
  info: McpTokenInfo
  token: string
}

interface McpTokenDialogProps {
  networks: readonly Network[]
  onClose: () => void
}

/**
 * 签发一个 MCP 令牌：先填表（名字、限不限网络、有效期、权限），签发之后同一个位置换成结果——
 * JWT（只显示这一次）和把它配进客户端的命令。
 *
 * 选了网络，管整个 controller 的两项权限就不能勾（controller 也会拒绝），那两行改写原因。
 * controller 拒绝时说了是哪一项的，写在那一项下面（`mcpTokenFailure`）。
 *
 * JWT 只放在这个组件的状态里：不进查询库的缓存，不写进浏览器的存储，也不打进日志。
 * 每次打开都是新的一份状态，上一次签发的不会留着。
 */
export function McpTokenDialog({ networks, onClose }: McpTokenDialogProps) {
  const d = m.dialog
  const scopesId = useId()
  const [name, setName] = useState('')
  const [network, setNetwork] = useState<NetworkId | null>(null)
  const [days, setDays] = useState<number>(DEFAULT_MCP_LIFETIME_DAYS)
  const [scopes, setScopes] = useState<ReadonlySet<McpScope>>(new Set(DEFAULT_SCOPES))
  const [touched, setTouched] = useState(false)
  const [issued, setIssued] = useState<Issued | null>(null)

  const issue = useAction(null, {
    mutationFn: async (body: CreateMcpToken) => {
      const { token, ...info } = await api.createMcpToken(body)
      // JWT 在这里就和别的分开：这次修改的结果会留在查询库的缓存里一阵，里面不能有它。
      setIssued({ info, token })
      return info
    },
    toastError: false,
  })

  if (issued !== null) return <IssuedDialog issued={issued} networks={networks} onClose={onClose} />

  const failure = mcpTokenFailure(issue.error)
  const nameProblem = validateTitle(name, true)
  const scopesProblem = scopes.size === 0 ? m.errors.scopesEmpty : null
  const scopesError = (touched ? scopesProblem : null) ?? fieldError(failure, 'scopes')
  const scopesErrorId = `${scopesId}-error`

  const chooseNetwork = (next: NetworkId | null) => {
    setNetwork(next)
    // 只限一个网络的令牌不能带管整个 controller 的权限：选了网络就把勾着的去掉。
    if (next !== null) setScopes((current) => new Set([...current].filter((scope) => !isGlobalScope(scope))))
    issue.reset()
  }

  const toggleScope = (scope: McpScope, on: boolean) => {
    setScopes((current) => {
      const next = new Set(current)
      if (on) next.add(scope)
      else next.delete(scope)
      return next
    })
    issue.reset()
  }

  const dirty =
    name !== '' ||
    network !== null ||
    days !== DEFAULT_MCP_LIFETIME_DAYS ||
    scopes.size !== DEFAULT_SCOPES.length ||
    DEFAULT_SCOPES.some((scope) => !scopes.has(scope))

  return (
    <FormDialog
      open
      onClose={onClose}
      title={d.title}
      dirty={dirty}
      submitLabel={d.submit}
      pending={issue.isPending}
      error={formError(failure)}
      errorDetail={formErrorDetail(failure)}
      onSubmit={() => {
        setTouched(true)
        if (nameProblem !== null || scopesProblem !== null) return
        issue.mutate({
          name: name.trim(),
          // 按固定的顺序交出去，和勾的先后无关。
          scopes: MCP_SCOPES.filter((scope) => scopes.has(scope)),
          ...(network === null ? {} : { network }),
          expires_in_secs: lifetimeSecs(days),
        })
      }}
    >
      <Field label={d.name} hint={d.nameHint} error={(touched ? nameProblem : null) ?? fieldError(failure, 'name')}>
        {(props) => (
          <Input
            {...props}
            name="name"
            value={name}
            autoFocus
            placeholder={d.namePlaceholder}
            onChange={(event) => {
              setName(event.target.value)
              issue.reset()
            }}
          />
        )}
      </Field>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field label={d.network} hint={d.networkHint} error={fieldError(failure, 'network')}>
          {(props) => (
            <NativeSelect
              {...props}
              value={network ?? ''}
              onChange={(event) => chooseNetwork(event.target.value === '' ? null : Number(event.target.value))}
            >
              <option value="">{m.anyNetwork}</option>
              {networks.map((candidate) => (
                <option key={candidate.id} value={candidate.id}>
                  {candidate.name}
                </option>
              ))}
            </NativeSelect>
          )}
        </Field>
        <Field label={d.lifetime} hint={d.lifetimeHint(MCP_MAX_LIFETIME_DAYS)} error={fieldError(failure, 'lifetime')}>
          {(props) => (
            <NativeSelect
              {...props}
              value={days}
              onChange={(event) => {
                setDays(Number(event.target.value))
                issue.reset()
              }}
            >
              {MCP_LIFETIME_DAYS.map((choice) => (
                <option key={choice} value={choice}>
                  {t.time.days(choice)}
                </option>
              ))}
            </NativeSelect>
          )}
        </Field>
      </div>
      <fieldset aria-describedby={scopesError !== null ? scopesErrorId : undefined}>
        <legend className="text-[13px] font-medium text-foreground">{d.scopes}</legend>
        <div className="mt-2.5 space-y-2.5">
          {MCP_SCOPES.map((scope) => {
            const id = `${scopesId}-${scope}`
            const blocked = network !== null && isGlobalScope(scope)
            return (
              <div key={scope} className="flex items-start gap-2.5" data-testid={`mcp-scope-${scope}`}>
                <Checkbox
                  id={id}
                  className="mt-0.5"
                  checked={scopes.has(scope)}
                  disabled={blocked}
                  aria-describedby={`${id}-hint`}
                  onCheckedChange={(checked) => toggleScope(scope, checked === true)}
                />
                <div className="min-w-0">
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <label htmlFor={id} className={cn('text-sm', blocked && 'text-muted-foreground')}>
                      {m.scopeNames[scope]}
                    </label>
                    <code className="font-mono text-xs text-muted-foreground">{scope}</code>
                  </div>
                  {/* 不能勾的那两行写为什么不能，而不是它管什么。 */}
                  <p id={`${id}-hint`} className="text-[13px] text-muted-foreground">
                    {blocked ? d.globalOnly : m.scopeHints[scope]}
                  </p>
                </div>
              </div>
            )
          })}
        </div>
        {scopesError !== null ? (
          <p id={scopesErrorId} role="alert" className="mt-2.5 text-[13px] text-danger">
            {scopesError}
          </p>
        ) : null}
      </fieldset>
    </FormDialog>
  )
}

interface IssuedDialogProps {
  issued: Issued
  networks: readonly Network[]
  onClose: () => void
}

/**
 * 签发的结果：JWT 和把它配进 Claude Code 的那一行命令，各带一个复制；别的客户端怎么填写在下面。
 * 不能用 Esc 误关，只能点"完成"：JWT 只在这里显示这一次。
 */
function IssuedDialog({ issued, networks, onClose }: IssuedDialogProps) {
  const i = m.issued
  const { info, token } = issued
  const endpoint = mcpEndpoint(window.location.origin)
  const command = claudeMcpAddCommand(endpoint, token)
  // 只限一个网络的写它的名字；刚选的网络这时要是没有了（别处删的），写编号。
  const network =
    info.network === null
      ? null
      : (networks.find((candidate) => candidate.id === info.network)?.name ?? `#${info.network}`)

  return (
    <Dialog open onOpenChange={(next) => (next ? undefined : onClose())}>
      <DialogContent
        title={i.title}
        description={i.summary(info.name, formatList(info.scopes), network, formatDateTime(info.expires_at))}
        dismissible={false}
        className="md:max-w-2xl"
      >
        <DialogBody className="space-y-5">
          <section className="space-y-2">
            <h3 className="text-sm font-semibold">{i.token}</h3>
            <CodeBlock copy={token} copyLabel={i.copyToken} label={i.token} testId="mcp-token">
              {/* JWT 很长，中间没有可以折行的地方，让它在任意处断开。 */}
              <span className="break-all">{token}</span>
            </CodeBlock>
            <p className="text-[13px] font-medium text-warn">{i.shownOnce}</p>
          </section>
          <section className="space-y-2">
            <h3 className="text-sm font-semibold">{i.claude}</h3>
            <CodeBlock copy={command} copyLabel={i.copyCommand} label={i.claude} testId="mcp-claude-command">
              {command}
            </CodeBlock>
            <p className="text-[13px] break-words text-muted-foreground">{i.otherClients(endpoint)}</p>
          </section>
        </DialogBody>
        <DialogFooter>
          <Button variant="primary" onClick={onClose}>
            {t.common.done}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
