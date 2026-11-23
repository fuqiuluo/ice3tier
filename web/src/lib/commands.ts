import {
  type Capability,
  CAPABILITY_CONFIG_KEY,
  CAPABILITY_FLAG,
  CONTROLLER_IMAGE,
  CONTROLLER_SERVICE,
  INSTALL_SCRIPT,
  type InstallSystem,
  PLATFORMS,
  type PlatformId,
  RELEASE_BASE,
} from './product'

/**
 * 界面上给出的、要用户拿到机器上去执行的命令。都是纯函数：同样的输入给出同样的一行，方便测试。
 * 显示在屏幕上的和复制到剪贴板的是同一个字符串，始终是一行。
 */

/** 加入时在本地声明"这台机器可以承担"的三项。它们是命令的参数，不属于令牌。 */
export interface JoinDeclarations {
  exit: boolean
  relay: boolean
  forward: boolean
}

export const NO_DECLARATIONS: JoinDeclarations = { exit: false, relay: false, forward: false }

/** 声明对应的命令行参数，顺序固定（和 `i3t join --help` 列出的一致）。 */
export function joinFlags(declare: JoinDeclarations): string[] {
  const order: Capability[] = ['exit', 'relay', 'forward']
  return order.filter((capability) => declare[capability]).map((capability) => `--${CAPABILITY_FLAG[capability]}`)
}

/** Windows 上发布的只有这一个平台的程序。 */
const WINDOWS_PLATFORM: PlatformId = 'windows-x86_64'

/**
 * 加入命令里怎么调用节点程序。脚本把节点装成了系统服务，它的状态只有 root 能动；
 * Windows 上在下载到的目录里直接执行。
 */
export function programFor(system: InstallSystem): string {
  return system === 'windows' ? '.\\i3t.exe' : 'sudo i3t'
}

/** 不含引号也不会被 shell 误解的字符。注册令牌是 `i3t-` 加 base64url，都在这里面。 */
const SHELL_SAFE = /^[A-Za-z0-9_.=+/-]+$/

function quote(value: string, windows: boolean): string {
  if (SHELL_SAFE.test(value)) return value
  return windows ? `"${value.replaceAll('"', '`"')}"` : `'${value.replaceAll("'", `'\\''`)}'`
}

/**
 * 重置管理令牌要执行的命令，一行一条，填好了这个 controller 的数据目录。重置不要公开地址。
 * 数据目录是安装脚本装出来的那个时，照部署文档给三条：停服务、以服务的用户执行、再启动
 * （数据库的连接串在数据目录里，不用另外给）。数据目录是镜像里的那个时，给 `docker compose` 的三条。
 * 别的装法不知道它是怎么跑起来的，只给执行的那一条，停和启动、数据库的连接串由用户自己照启动时的做。
 */
export function resetTokenCommands(dataDir: string): string[] {
  if (dataDir === CONTROLLER_IMAGE.dataDir) {
    const { service } = CONTROLLER_IMAGE
    return [
      `docker compose stop ${service}`,
      `docker compose run --rm ${service} --reset-admin-token`,
      `docker compose start ${service}`,
    ]
  }
  const args = `--data-dir ${quote(dataDir, false)} --reset-admin-token`
  if (dataDir !== CONTROLLER_SERVICE.dataDir) return [`i3t-controller ${args}`]
  const { unit, user, program } = CONTROLLER_SERVICE
  return [`sudo systemctl stop ${unit}`, `sudo -u ${user} ${program} ${args}`, `sudo systemctl start ${unit}`]
}

/** 令牌还没生成时，命令里令牌的位置上显示的占位符。它只给人看，不会被复制走，所以不加引号。 */
export interface TokenPlaceholder {
  placeholder: string
}

/** 加入命令的三段：令牌前面的、令牌（或占位符）、令牌后面的。界面上令牌那一段的样子和别的不一样。 */
export interface JoinCommandParts {
  before: string
  token: string
  after: string
}

export function joinCommandParts(
  token: string | TokenPlaceholder,
  declare: JoinDeclarations,
  system: InstallSystem = 'linux',
): JoinCommandParts {
  return {
    before: 'echo ',
    token: typeof token === 'string' ? quote(token, system === 'windows') : token.placeholder,
    after: ` | ${[programFor(system), 'join', ...joinFlags(declare)].join(' ')}`,
  }
}

/**
 * 加入网络的那一行命令：`echo <令牌> | sudo i3t join [--can-exit] [--can-relay] [--can-forward]`。
 *
 * 令牌从标准输入读，所以用 echo 接管道，整行可以一次复制。
 * 令牌生成之前传占位符：先让用户看懂命令的结构，令牌会出现在哪里。
 */
export function buildJoinCommand(
  token: string | TokenPlaceholder,
  declare: JoinDeclarations,
  system: InstallSystem = 'linux',
): string {
  const { before, token: shown, after } = joinCommandParts(token, declare, system)
  return `${before}${shown}${after}`
}

/**
 * 安装的那一行。Linux 和 macOS 是安装脚本：装好程序，登记为系统服务，加入之后服务自己启动。
 * Windows 是把程序下载到当前目录。
 */
export function installCommand(system: InstallSystem): string {
  if (system === 'windows') return downloadCommands(WINDOWS_PLATFORM).join(' && ')
  return `curl -fsSL ${INSTALL_SCRIPT} | sh`
}

/** 加入之后还要自己启动节点的系统上，启动的命令；服务会自己启动的系统上没有这一步。 */
export function startCommand(system: InstallSystem): string | null {
  return system === 'windows' ? `${programFor(system)} run` : null
}

/** 只下载节点程序、放到能直接执行的地方，不装服务：手动替换程序时用。每个平台是一行或两行。 */
export function downloadCommands(platformId: PlatformId): string[] {
  const target = PLATFORMS.find((candidate) => candidate.id === platformId) ?? PLATFORMS[0]
  const url = `${RELEASE_BASE}/${target.file}`
  if (target.windows) return [`curl.exe -fLo i3t.exe ${url}`]
  return [`curl -fLo i3t ${url}`, 'sudo install -m 755 i3t /usr/local/bin/i3t']
}

/** 在节点上声明（或者撤回）一项"可以承担"。 */
export function declareCommand(capability: Capability, on = true): string {
  return `i3t set ${CAPABILITY_FLAG[capability]} ${on ? 'on' : 'off'}`
}

/** 不用命令、直接改 config.toml 时要写的两行。 */
export function declareConfig(capability: Capability): string {
  return `[declare]\n${CAPABILITY_CONFIG_KEY[capability]} = true`
}
