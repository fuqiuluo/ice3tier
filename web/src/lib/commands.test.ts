import { describe, expect, it } from 'vitest'

import {
  buildJoinCommand,
  claudeMcpAddCommand,
  declareCommand,
  declareConfig,
  downloadCommands,
  installCommand,
  joinFlags,
  NO_DECLARATIONS,
  programFor,
  resetTokenCommands,
  startCommand,
} from './commands'
import { INSTALL_SCRIPT, INSTALL_SYSTEMS, RELEASE_BASE } from './product'

const TOKEN = 'i3t-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE_x-9'

describe('加入网络的命令', () => {
  it('什么都没勾：echo <令牌> | sudo i3t join', () => {
    expect(buildJoinCommand(TOKEN, NO_DECLARATIONS)).toBe(`echo ${TOKEN} | sudo i3t join`)
  })

  it('每一项声明对应一个 --can-* 参数', () => {
    expect(buildJoinCommand(TOKEN, { ...NO_DECLARATIONS, relay: true })).toBe(
      `echo ${TOKEN} | sudo i3t join --can-relay`,
    )
    expect(buildJoinCommand(TOKEN, { ...NO_DECLARATIONS, exit: true })).toBe(`echo ${TOKEN} | sudo i3t join --can-exit`)
    expect(buildJoinCommand(TOKEN, { ...NO_DECLARATIONS, forward: true })).toBe(
      `echo ${TOKEN} | sudo i3t join --can-forward`,
    )
  })

  it('全勾时参数的顺序固定，和勾选的先后无关', () => {
    const expected = `echo ${TOKEN} | sudo i3t join --can-exit --can-relay --can-forward`
    expect(buildJoinCommand(TOKEN, { exit: true, relay: true, forward: true })).toBe(expected)
    expect(buildJoinCommand(TOKEN, { forward: true, relay: true, exit: true })).toBe(expected)
    expect(joinFlags({ forward: true, relay: false, exit: true })).toEqual(['--can-exit', '--can-forward'])
    expect(joinFlags(NO_DECLARATIONS)).toEqual([])
  })

  it('令牌生成之前，令牌的位置上是占位符，原样显示', () => {
    expect(buildJoinCommand({ placeholder: '<注册令牌>' }, { ...NO_DECLARATIONS, relay: true })).toBe(
      'echo <注册令牌> | sudo i3t join --can-relay',
    )
  })

  it('始终是一行', () => {
    for (const system of INSTALL_SYSTEMS) {
      expect(buildJoinCommand(TOKEN, { exit: true, relay: true, forward: true }, system)).not.toMatch(/[\r\n]/)
      expect(installCommand(system)).not.toMatch(/[\r\n]/)
    }
  })

  it('脚本装的是系统服务，加入要 root；macOS 和 Linux 是同一行', () => {
    expect(programFor('linux')).toBe('sudo i3t')
    expect(buildJoinCommand(TOKEN, NO_DECLARATIONS, 'macos')).toBe(buildJoinCommand(TOKEN, NO_DECLARATIONS, 'linux'))
  })

  it('Windows 上执行的是当前目录里的 i3t.exe', () => {
    expect(buildJoinCommand(TOKEN, { ...NO_DECLARATIONS, exit: true }, 'windows')).toBe(
      `echo ${TOKEN} | .\\i3t.exe join --can-exit`,
    )
    expect(programFor('windows')).toBe('.\\i3t.exe')
  })

  it('真正的令牌（i3t- 加 base64url）不需要引号', () => {
    expect(buildJoinCommand('i3t-abc_DEF-123', NO_DECLARATIONS)).toBe('echo i3t-abc_DEF-123 | sudo i3t join')
  })

  it('带着 shell 会误解的字符时加引号，不让它变成另一条命令', () => {
    expect(buildJoinCommand('a b; rm -rf ~', NO_DECLARATIONS)).toBe(`echo 'a b; rm -rf ~' | sudo i3t join`)
    expect(buildJoinCommand(`it's`, NO_DECLARATIONS)).toBe(`echo 'it'\\''s' | sudo i3t join`)
    expect(buildJoinCommand('a "b"', NO_DECLARATIONS, 'windows')).toBe('echo "a `"b`"" | .\\i3t.exe join')
  })
})

describe('把 MCP 端点加进 Claude Code 的命令', () => {
  const ENDPOINT = 'https://ctl.example.com:8443/api/v1/mcp'
  const JWT = 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJjbGF1ZGUtY29kZSJ9.c2lnbmF0dXJl_x-9'

  it('claude mcp add --transport http ice3tier <端点> --header "Authorization: Bearer <JWT>"', () => {
    expect(claudeMcpAddCommand(ENDPOINT, JWT)).toBe(
      `claude mcp add --transport http ice3tier ${ENDPOINT} --header "Authorization: Bearer ${JWT}"`,
    )
  })

  it('始终是一行', () => {
    expect(claudeMcpAddCommand(ENDPOINT, JWT)).not.toMatch(/[\r\n]/)
  })

  it('IPv6 的字面地址带方括号，加引号，不让 shell 当成通配', () => {
    expect(claudeMcpAddCommand('http://[::1]:8443/api/v1/mcp', JWT)).toBe(
      `claude mcp add --transport http ice3tier 'http://[::1]:8443/api/v1/mcp' --header "Authorization: Bearer ${JWT}"`,
    )
  })

  it('令牌里带着 shell 会误解的字符时，请求头改用单引号，不让它变成另一条命令', () => {
    expect(claudeMcpAddCommand(ENDPOINT, 'a"; rm -rf ~; "')).toBe(
      `claude mcp add --transport http ice3tier ${ENDPOINT} --header 'Authorization: Bearer a"; rm -rf ~; "'`,
    )
    expect(claudeMcpAddCommand(ENDPOINT, '$(id)')).toBe(
      `claude mcp add --transport http ice3tier ${ENDPOINT} --header 'Authorization: Bearer $(id)'`,
    )
  })
})

describe('其余给用户执行的命令', () => {
  it('安装：Linux 和 macOS 是一行安装脚本，Windows 把程序下载到当前目录', () => {
    expect(installCommand('linux')).toBe(`curl -fsSL ${INSTALL_SCRIPT} | sh`)
    expect(installCommand('macos')).toBe(installCommand('linux'))
    expect(installCommand('windows')).toBe(`curl.exe -fLo i3t.exe ${RELEASE_BASE}/i3t-windows-x86_64.exe`)
  })

  it('启动：服务加入之后自己启动，只有 Windows 要自己来', () => {
    expect(startCommand('linux')).toBeNull()
    expect(startCommand('macos')).toBeNull()
    expect(startCommand('windows')).toBe('.\\i3t.exe run')
  })

  it('手动替换程序：每个平台取发布页上对应的文件', () => {
    expect(downloadCommands('linux-x86_64')).toEqual([
      `curl -fLo i3t ${RELEASE_BASE}/i3t-linux-x86_64`,
      'sudo install -m 755 i3t /usr/local/bin/i3t',
    ])
    expect(downloadCommands('macos-aarch64')[0]).toBe(`curl -fLo i3t ${RELEASE_BASE}/i3t-macos-aarch64`)
    expect(downloadCommands('windows-x86_64')).toEqual([`curl.exe -fLo i3t.exe ${RELEASE_BASE}/i3t-windows-x86_64.exe`])
  })

  it('声明和撤回：i3t set can-… on / off', () => {
    expect(declareCommand('exit')).toBe('i3t set can-exit on')
    expect(declareCommand('relay')).toBe('i3t set can-relay on')
    expect(declareCommand('forward')).toBe('i3t set can-forward on')
    expect(declareCommand('relay', false)).toBe('i3t set can-relay off')
  })

  it('改配置文件的写法', () => {
    expect(declareConfig('exit')).toBe('[declare]\nexit = true')
  })

  it('重置管理令牌：安装脚本装出来的 controller 是停、以服务的用户执行、再启动三条', () => {
    expect(resetTokenCommands('/var/lib/i3t-controller')).toEqual([
      'sudo systemctl stop i3t-controller',
      'sudo -u i3t-controller /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --reset-admin-token',
      'sudo systemctl start i3t-controller',
    ])
  })

  it('重置管理令牌：用镜像跑的 controller 是 docker compose 的三条，不是宿主机上的命令', () => {
    expect(resetTokenCommands('/data')).toEqual([
      'docker compose stop controller',
      'docker compose run --rm controller --reset-admin-token',
      'docker compose start controller',
    ])
  })

  it('重置管理令牌：别的装法只给执行的那一条；目录里有 shell 会误解的字符时加引号', () => {
    expect(resetTokenCommands('/srv/i3t')).toEqual(['i3t-controller --data-dir /srv/i3t --reset-admin-token'])
    expect(resetTokenCommands('/srv/my data')).toEqual([`i3t-controller --data-dir '/srv/my data' --reset-admin-token`])
    expect(resetTokenCommands("/srv/it's")).toEqual([`i3t-controller --data-dir '/srv/it'\\''s' --reset-admin-token`])
  })
})
