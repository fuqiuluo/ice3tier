import { useQuery } from '@tanstack/react-query'
import { Eye, EyeOff, RefreshCw } from 'lucide-react'
import { useId, useState } from 'react'
import { Link } from 'react-router'

import { api } from '@/api/endpoints'
import { fieldError, formError, formErrorDetail, formFailure } from '@/api/formErrors'
import { q, useAction } from '@/api/queries'
import { type Network, type NodeId, type Proxy, type ProxyInput, type ProxyProtocol } from '@/api/types'
import { CodeBlock } from '@/components/copy'
import { FormDialog } from '@/components/form-dialog'
import { NodeSelect } from '@/components/node'
import { Notice } from '@/components/notice'
import { Button } from '@/components/ui/button'
import { Field } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { Tooltip } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { formatSocketAddr, isLoopbackHost, parseIpv4, parseSocketAddr } from '@/lib/cidr'
import { proxyUrl, randomSecret } from '@/lib/proxy'
import { validatePort } from '@/lib/validate'
import { networkPath } from '@/pages/networks/context'

const s = t.proxies
const d = s.dialog

type Where = 'local' | 'all' | 'mesh' | 'custom'

/** 监听地址怎么选：本机、所有地址、入口节点的虚拟 IP、自己填。 */
function whereOf(host: string, virtualIp: string | undefined): Where {
  if (isLoopbackHost(host)) return 'local'
  if (host === '0.0.0.0') return 'all'
  if (virtualIp !== undefined && host === virtualIp) return 'mesh'
  return 'custom'
}

interface ProxyDialogProps {
  network: Network
  /** 要改的那个；新建时是 `null`。 */
  proxy: Proxy | null
  onClose: () => void
}

/**
 * 新建或修改一个代理，按顺序填：出口（只能选打开了出口的节点）、入口（不能和出口是同一台）、协议、监听地址、端口、
 * 用户名和密码（开在本机以外时必填，能随机生成，能看）、要不要 ice3proxy（默认关：打开时这个代理的流一直走它，
 * 开不了时退回共用连接）。底下直接写出设备里要填的代理地址；策略不允许入口访问出口时当场说。
 */
export function ProxyDialog({ network, proxy, onClose }: ProxyDialogProps) {
  const nodes = useQuery(q.nodes(network.id))
  const all = nodes.data ?? []
  const parsed = proxy === null ? null : parseSocketAddr(proxy.bind)
  const [exit, setExit] = useState<NodeId | null>(proxy?.exit ?? null)
  const [entry, setEntry] = useState<NodeId | null>(proxy?.node ?? null)
  const entryNode = all.find((node) => node.id === entry)
  const exitNode = all.find((node) => node.id === exit)
  const initialWhere = parsed === null ? 'all' : whereOf(parsed.host, entryNode?.virtual_ip)
  const [protocol, setProtocol] = useState<ProxyProtocol>(proxy?.protocol ?? 'mixed')
  const [where, setWhere] = useState<Where>(initialWhere)
  const [custom, setCustom] = useState(parsed !== null && initialWhere === 'custom' ? parsed.host : '')
  const [port, setPort] = useState(parsed?.port.toString() ?? '1080')
  const [name, setName] = useState(proxy?.name ?? '')
  const [username, setUsername] = useState(proxy?.username ?? (proxy === null ? randomSecret(6) : ''))
  const [password, setPassword] = useState(proxy?.password ?? (proxy === null ? randomSecret(16) : ''))
  const [showPassword, setShowPassword] = useState(proxy === null)
  // ice3proxy：新建时默认关；比界面旧的 controller 不写，按关着算。
  const [lane, setLane] = useState(proxy?.lane === true)
  const laneId = useId()
  const laneHintId = useId()
  const [touched, setTouched] = useState(false)
  const [dirty, setDirty] = useState(false)

  const host =
    where === 'local'
      ? '127.0.0.1'
      : where === 'all'
        ? '0.0.0.0'
        : where === 'mesh'
          ? (entryNode?.virtual_ip ?? '')
          : custom.trim()
  const loopback = isLoopbackHost(host)
  const exitProblem = exit === null ? t.validate.pickNode : null
  const entryProblem = entry === null ? t.validate.pickNode : entry === exit ? d.entrySame : null
  const portProblem = validatePort(port)
  const addressProblem =
    where === 'custom' && parseIpv4(host) === null && !host.includes(':') ? t.validate.ipFormat : null
  const authProblem =
    (username.trim() === '') !== (password === '')
      ? d.authIncomplete
      : !loopback && username.trim() === ''
        ? d.authRequired
        : null
  const valid = [exitProblem, entryProblem, portProblem, addressProblem, authProblem].every((p) => p === null)

  // 策略不允许入口访问出口时代理用不了：当场说。
  const check = useQuery({
    ...q.check(network.id, entry ?? 0, exit ?? 0),
    enabled: entry !== null && exit !== null && entry !== exit,
  })

  const save = useAction(network.id, {
    mutationFn: (input: ProxyInput) =>
      proxy === null ? api.createProxy(network.id, input) : api.updateProxy(network.id, proxy.id, input),
    success: (saved) => (proxy === null ? d.created(saved.name) : d.saved(saved.name)),
    toastError: false,
  })
  const failure = formFailure(save.error, {
    conflict: 'port',
    name_taken: 'name',
    exit_not_enabled: 'exit',
    exit_is_node: 'exit',
    access_denied: 'exit',
    credentials_incomplete: 'username',
  } as const)

  const change =
    <T,>(setter: (value: T) => void) =>
    (value: T) => {
      setter(value)
      setDirty(true)
      save.reset()
    }

  const submit = () => {
    setTouched(true)
    if (!valid || exit === null || entry === null) return
    save.mutate(
      {
        ...(name.trim() === '' ? {} : { name: name.trim() }),
        node: entry,
        bind: formatSocketAddr(host, Number(port)),
        protocol,
        exit,
        username: username.trim(),
        password,
        lane,
      },
      { onSuccess: onClose },
    )
  }

  const shown = (problem: string | null) => (touched ? problem : null)
  const preview =
    entry !== null && portProblem === null
      ? proxyUrl({
          protocol,
          host: where === 'all' ? `<${s.lanHost}>` : host,
          port: Number(port),
          username: username.trim(),
          password,
        })
      : null

  return (
    <FormDialog
      open
      onClose={onClose}
      title={proxy === null ? d.createTitle : d.editTitle(proxy.name)}
      dirty={dirty}
      requireDirty={proxy !== null}
      submitLabel={proxy === null ? d.submitCreate : t.common.save}
      pending={save.isPending}
      error={formError(failure)}
      errorDetail={formErrorDetail(failure)}
      onSubmit={submit}
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field label={d.exit} hint={d.exitHint} error={shown(exitProblem) ?? fieldError(failure, 'exit')}>
          {(props) => (
            <NodeSelect
              {...props}
              nodes={all}
              value={exit}
              onChange={change(setExit)}
              disabledReason={(node) => (node.exit === null ? d.exitOff : null)}
            />
          )}
        </Field>
        <Field label={d.entry} hint={d.entryHint} error={shown(entryProblem) ?? fieldError(failure, 'entry')}>
          {(props) => (
            <NodeSelect
              {...props}
              nodes={all}
              value={entry}
              onChange={change(setEntry)}
              disabledReason={(node) => (node.id === exit ? d.entrySame : null)}
            />
          )}
        </Field>
      </div>

      {check.data?.allowed === false && entryNode !== undefined && exitNode !== undefined ? (
        <Notice tone="warn">
          {d.accessDenied(entryNode.name, exitNode.name)}{' '}
          <Link to={networkPath(network.id, 'access')} className="text-primary hover:underline">
            {d.goPolicies}
          </Link>
        </Notice>
      ) : null}

      <Field label={d.protocol} hint={protocol === 'mixed' ? d.mixedHint : undefined}>
        {() => (
          <Segmented
            aria-label={d.protocol}
            value={protocol}
            onChange={change(setProtocol)}
            options={[
              { value: 'mixed', label: d.protocolMixed },
              { value: 'socks5', label: s.protocol.socks5 },
              { value: 'http', label: s.protocol.http },
            ]}
          />
        )}
      </Field>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-[minmax(0,1fr)_8rem]">
        <Field label={d.address} hint={d.whereHint[where]} error={shown(addressProblem)}>
          {() => (
            <div className="space-y-2">
              <Segmented
                aria-label={d.address}
                value={where}
                onChange={change(setWhere)}
                options={[
                  { value: 'local', label: d.whereLocal },
                  { value: 'all', label: d.whereAll },
                  { value: 'mesh', label: d.whereMesh },
                  { value: 'custom', label: d.whereCustom },
                ]}
              />
              {where === 'custom' ? (
                <Input
                  aria-label={d.whereCustom}
                  value={custom}
                  placeholder="192.168.1.5"
                  onChange={(event) => change(setCustom)(event.target.value)}
                />
              ) : null}
            </div>
          )}
        </Field>
        <Field label={d.port} error={shown(portProblem) ?? fieldError(failure, 'port')}>
          {(props) => (
            <Input
              {...props}
              inputMode="numeric"
              value={port}
              onChange={(event) => change(setPort)(event.target.value)}
            />
          )}
        </Field>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field
          label={d.username}
          error={shown(authProblem) ?? fieldError(failure, 'username')}
          hint={loopback ? d.authOptional : d.authRequired}
        >
          {(props) => (
            <Input
              {...props}
              autoComplete="off"
              spellCheck={false}
              value={username}
              onChange={(event) => change(setUsername)(event.target.value)}
            />
          )}
        </Field>
        <Field label={d.password}>
          {(props) => (
            <div className="flex items-center gap-1">
              <Input
                {...props}
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                spellCheck={false}
                className="font-mono"
                value={password}
                onChange={(event) => change(setPassword)(event.target.value)}
              />
              <Tooltip content={showPassword ? d.hidePassword : d.showPassword}>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={showPassword ? d.hidePassword : d.showPassword}
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
                </Button>
              </Tooltip>
              <Tooltip content={d.generate}>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={d.generate}
                  onClick={() => {
                    change(setPassword)(randomSecret(16))
                    setShowPassword(true)
                  }}
                >
                  <RefreshCw aria-hidden />
                </Button>
              </Tooltip>
            </div>
          )}
        </Field>
      </div>

      <div className="flex items-start justify-between gap-4">
        <div>
          <label htmlFor={laneId} className="text-[13px] font-medium">
            {s.lane.title}
          </label>
          <p id={laneHintId} className="mt-0.5 text-[13px] text-muted-foreground">
            {s.lane.switchHint}
          </p>
        </div>
        <Switch id={laneId} aria-describedby={laneHintId} checked={lane} onCheckedChange={change(setLane)} />
      </div>

      <Field label={d.name} error={fieldError(failure, 'name')}>
        {(props) => (
          <Input
            {...props}
            placeholder={d.namePlaceholder}
            value={name}
            onChange={(event) => change(setName)(event.target.value)}
          />
        )}
      </Field>

      {preview !== null ? (
        <div>
          <p className="mb-1.5 text-[13px] font-medium">{d.preview}</p>
          <CodeBlock copy={preview}>{preview}</CodeBlock>
        </div>
      ) : null}
    </FormDialog>
  )
}
