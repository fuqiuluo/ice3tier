import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { kitDir } from './release'

/**
 * 测试用的 controller 和节点：真的程序，真的管理 API，不是模拟。
 *
 * 程序从 `I3T_BIN_DIR` 找；没设时依次试 `pnpm e2e:kit` 编出来的那一组（`web/.e2e/release-kit/old`，认测试用的发布钥匙，
 * 节点更新的测试要它），仓库里的 `target/agent-web/release`、`target/release` 和 `target/lead/release`，
 * 用第一个两样程序都在的目录。
 * 界面用的是 `pnpm build` 的产物，由 controller 自己从 `--static-dir` 提供，和正式部署时一样。
 *
 * controller 的数据存在 PostgreSQL 里：每个 controller 在测试用的服务器上用一个新的空库。服务器在哪里由环境变量
 * `I3T_TEST_DATABASE_URL` 说，先在仓库的根目录执行 `export $(scripts/test-postgres.sh start)`。
 */

const here = dirname(fileURLToPath(import.meta.url))
const webRoot = resolve(here, '..')
const repoRoot = resolve(webRoot, '..')

function binDir(): string {
  const candidates = [
    process.env.I3T_BIN_DIR,
    join(kitDir(), 'old'),
    join(repoRoot, 'target/agent-web/release'),
    join(repoRoot, 'target/release'),
    join(repoRoot, 'target/lead/release'),
  ].filter((dir): dir is string => dir !== undefined && dir !== '')
  for (const dir of candidates) {
    if (['i3t-controller', 'i3t'].every((name) => existsSync(join(dir, name)))) return dir
  }
  throw new Error(
    `找不到 i3t-controller 和 i3t。先构建：在 web/ 里执行 pnpm e2e:kit，或者 cargo build --release -p i3t-controller-bin -p i3t，或者用 I3T_BIN_DIR 指出它们在哪。试过的目录：${candidates.join('、')}`,
  )
}

/**
 * 代替 systemd 的看护：节点以 75（"请重启我"）退出就马上重新拉起，自己更新的节点换了程序之后靠它重启；
 * 别的退出码（包括被停掉）就不再拉。
 */
const SUPERVISOR = `while :; do "$PROGRAM" --state-dir "$STATE" run; code=$?; [ "$code" -eq 75 ] || exit "$code"; done`

export interface RunOptions {
  /** 用这个程序文件，而不是共用的那一个。自己更新的节点会替换它，所以不能是共用的。 */
  program?: string
  /** 多给的环境变量，例如 `container=podman` 让节点以为自己在容器里。 */
  env?: Record<string, string>
  /** 由看护的循环拉起来，见 {@link SUPERVISOR}。 */
  supervised?: boolean
}

interface Running {
  child: ChildProcess
  /** 看护的循环和节点在一个单独的进程组里，停的时候一起停。 */
  group: boolean
}

/** controller 没有绑上交给它的端口：有别的进程先占了。 */
class PortTaken extends Error {}

function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer()
    server.unref()
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      server.close(() => {
        if (address !== null && typeof address === 'object') resolvePort(address.port)
        else reject(new Error('拿不到空闲端口'))
      })
    })
  })
}

function sendSignal(child: ChildProcess, group: boolean, signal: NodeJS.Signals): void {
  try {
    if (group && child.pid !== undefined) process.kill(-child.pid, signal)
    else child.kill(signal)
  } catch {
    // 已经退出了。
  }
}

/** 等子进程结束再删它的工作目录：直接 `rmSync` 会和正在写状态文件的退场流程撞出 ENOTEMPTY。 */
async function terminate(child: ChildProcess, group: boolean, timeoutMs = 5_000): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return
  await new Promise<void>((resolveExit) => {
    let settled = false
    const done = () => {
      if (settled) return
      settled = true
      clearTimeout(escalate)
      clearTimeout(giveUp)
      child.off('close', done)
      resolveExit()
    }
    child.once('close', done)
    sendSignal(child, group, 'SIGTERM')
    const escalate = setTimeout(() => sendSignal(child, group, 'SIGKILL'), timeoutMs)
    const giveUp = setTimeout(done, timeoutMs + 2_000)
  })
}

async function waitFor<T>(
  what: string,
  probe: () => Promise<T | undefined> | T | undefined,
  timeoutMs = 15_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = await probe()
    if (value !== undefined) return value
    if (Date.now() > deadline) throw new Error(`等了 ${timeoutMs} 毫秒，${what}还是没有发生`)
    await new Promise((done) => setTimeout(done, 100))
  }
}

export interface NodeHandle {
  /** 节点的状态目录。 */
  dir: string
  /** `i3t join` 打印的内容。 */
  output: string
  /** 节点跑起来之后，它本机 SOCKS5 入口的端口。 */
  socksPort?: number
}

export class Controller {
  readonly baseUrl: string
  readonly adminToken: string
  readonly dir: string
  /** 这次用的 `i3t-controller` 和 `i3t` 所在的目录。 */
  readonly bins: string
  private readonly process: ChildProcess
  private readonly nodes: Running[] = []
  private readonly readOnly: string[] = []
  private nodeCount = 0

  private constructor(options: {
    baseUrl: string
    adminToken: string
    dir: string
    bins: string
    process: ChildProcess
  }) {
    this.baseUrl = options.baseUrl
    this.adminToken = options.adminToken
    this.dir = options.dir
    this.bins = options.bins
    this.process = options.process
  }

  /**
   * 启动一个全新的、空的 controller。管理令牌从它第一次启动时打印的内容里取。
   * `bins` 指定程序所在的目录；节点更新的测试要用认测试钥匙的那一组。
   *
   * 端口是先挑好再交给它去绑的，中间隔着一小会儿，挑的时候也只试了 TCP（节点端口它 TCP、UDP 都要）：
   * 偶尔会被别的进程拿走。那样就换一组端口从头再来。
   */
  static async start(options: { bins?: string } = {}): Promise<Controller> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await Controller.startOnce(options)
      } catch (error) {
        if (!(error instanceof PortTaken) || attempt >= 5) throw error
      }
    }
  }

  private static async startOnce(options: { bins?: string }): Promise<Controller> {
    const bins = options.bins ?? binDir()
    const dist = join(webRoot, 'dist')
    if (!existsSync(join(dist, 'index.html'))) throw new Error('web/dist 里没有构建产物，先执行 pnpm build')

    const dir = mkdtempSync(join(tmpdir(), 'i3t-web-e2e-'))
    const created = spawnSync('sh', [join(repoRoot, 'scripts', 'test-postgres.sh'), 'database', 'web_e2e'], {
      encoding: 'utf8',
    })
    if (created.status !== 0) throw new Error(`建不了测试用的数据库：${created.stderr.trim()}`)
    const database = created.stdout.trim()
    const nodePort = await freePort()
    const adminPort = await freePort()
    const child = spawn(
      join(bins, 'i3t-controller'),
      [
        '--data-dir',
        join(dir, 'controller'),
        '--public-addr',
        `127.0.0.1:${nodePort}`,
        '--listen',
        `127.0.0.1:${nodePort}`,
        '--admin-listen',
        `127.0.0.1:${adminPort}`,
        '--static-dir',
        dist,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, I3T_DATABASE_URL: database } },
    )
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()))
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()))
    let exited: number | null = null
    // `close` 在它的输出都读完之后才来，`exit` 可能比最后一段标准错误早：下面要看标准错误里说了什么。
    child.on('close', (code) => (exited = code ?? -1))
    /** controller 已经退出的话抛出来。没绑上端口的单独认出来，好换一组端口重来。 */
    const failIfExited = () => {
      if (exited === null) return
      const message = `controller 启动后就退出了（${exited}）：\n${stderr}`
      throw /Address already in use/.test(stderr) ? new PortTaken(message) : new Error(message)
    }

    const baseUrl = `http://127.0.0.1:${adminPort}`
    try {
      // 令牌单独占一行，前面有缩进：43 个 base64url 字符。
      const adminToken = await waitFor('controller 打印管理令牌', () => {
        failIfExited()
        return /^\s+([A-Za-z0-9_-]{43})\s*$/m.exec(stdout)?.[1]
      })
      await waitFor('管理 API 开始应答', async () => {
        // 令牌是先打出来的，端口后绑：绑不上多半到这一步才看得出来。
        failIfExited()
        try {
          const response = await fetch(`${baseUrl}/api/v1/status`, {
            headers: { Authorization: `Bearer ${adminToken}` },
          })
          return response.ok ? true : undefined
        } catch {
          return undefined
        }
      })
      const controller = new Controller({ baseUrl, adminToken, dir, bins, process: child })
      // 发布源默认是项目的 GitHub Release。测试不该连外网，更不该让节点被真的发布更新掉：换成一个空目录。
      // 要测更新的地方自己再把它指到准备好的发布上。
      const empty = join(dir, 'no-releases')
      mkdirSync(empty)
      await controller.api('PATCH', '/update', { source: empty })
      return controller
    } catch (error) {
      await terminate(child, false, 1_000)
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
      throw error
    }
  }

  /** 直接调管理 API：用来准备数据，或者核对界面做的事真的落到了 controller 上。 */
  async api<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await fetch(`${this.baseUrl}/api/v1${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.adminToken}`, 'Content-Type': 'application/json' },
      body: method === 'GET' || method === 'DELETE' ? undefined : JSON.stringify(body ?? {}),
    })
    const text = await response.text()
    if (!response.ok) throw new Error(`${method} ${path} → ${response.status} ${text}`)
    return (text === '' ? undefined : JSON.parse(text)) as T
  }

  /**
   * 测试里的"那台机器"上的 `sudo`：原样执行后面的命令。界面给出的加入命令带着 sudo（节点是系统服务），
   * 测试里的节点是当前用户的一个普通进程，不需要、也不该真的提权。
   */
  private sudoDir(): string {
    const dir = join(this.dir, 'sudo')
    if (!existsSync(dir)) {
      mkdirSync(dir)
      writeFileSync(join(dir, 'sudo'), '#!/bin/sh\nexec "$@"\n', { mode: 0o755 })
    }
    return dir
  }

  /**
   * 在一个新的状态目录里执行界面上给出的那一行加入命令（`echo <令牌> | sudo i3t join …`），原样交给 shell。
   * join 只和 controller 说话，不需要把节点跑起来。
   */
  join(command: string): NodeHandle {
    this.nodeCount += 1
    const dir = join(this.dir, `node-${this.nodeCount}`)
    mkdirSync(dir, { recursive: true })
    const result = spawnSync('sh', ['-c', command], {
      env: {
        ...process.env,
        PATH: `${this.sudoDir()}:${this.bins}:${process.env.PATH ?? ''}`,
        I3T_STATE_DIR: dir,
      },
      encoding: 'utf8',
    })
    if (result.status !== 0)
      throw new Error(`加入命令失败（${result.status}）：${command}\n${result.stdout}\n${result.stderr}`)
    return { dir, output: result.stdout }
  }

  /** 生成一个令牌并用它加入：准备数据时用，不经过界面。 */
  async enroll(options: { groups?: number[]; flags?: string[] } = {}, network = 1): Promise<NodeHandle> {
    const created = await this.api<{ token: string }>('POST', `/networks/${network}/tokens`, {
      groups: options.groups ?? [],
    })
    return this.join(`echo ${created.token} | i3t join ${(options.flags ?? []).join(' ')}`)
  }

  /** 在节点上改本地声明，和用户在那台机器上敲 `i3t set …` 一样。 */
  set(node: NodeHandle, capability: 'can-exit' | 'can-relay' | 'can-forward', on: boolean): void {
    const result = spawnSync(join(this.bins, 'i3t'), ['--state-dir', node.dir, 'set', capability, on ? 'on' : 'off'], {
      encoding: 'utf8',
    })
    if (result.status !== 0) throw new Error(`i3t set 失败：${result.stderr}`)
  }

  /**
   * 给节点一份它自己的程序文件，放在它的状态目录旁边。自己更新的节点要替换程序文件，不能动共用的那一个。
   * `readOnly` 时放进一个不可写的目录：节点会报"程序所在的目录不可写"，不能自己更新。
   */
  ownProgram(node: NodeHandle, options: { from?: string; readOnly?: boolean } = {}): string {
    const directory = join(node.dir, options.readOnly === true ? 'ro-bin' : 'bin')
    mkdirSync(directory, { recursive: true })
    const program = join(directory, 'i3t')
    copyFileSync(options.from ?? join(this.bins, 'i3t'), program)
    chmodSync(program, 0o755)
    if (options.readOnly === true) {
      chmodSync(directory, 0o555)
      this.readOnly.push(directory)
    }
    return program
  }

  /**
   * 把一个已经加入的节点跑起来，让它在界面上显示为在线。
   * 一台机器上跑好几个节点，所以先把它的端口改成不冲突的。
   */
  async run(node: NodeHandle, options: RunOptions = {}): Promise<void> {
    const configPath = join(node.dir, 'config.toml')
    const udp = await freePort()
    const socks = await freePort()
    const http = await freePort()
    // 本机的组网入口（`[proxy]`）0.1.15 起默认关着，只通到组网里的节点：测试用它去连别的节点（`touch`）。
    // 去互联网要经代理（`/proxies`）。
    let config = readFileSync(configPath, 'utf8').replace(/^port = \d+$/m, `port = ${udp}`)
    config = /^socks5 = /m.test(config)
      ? config
          .replace(/^socks5 = .*$/m, `socks5 = "127.0.0.1:${socks}"`)
          .replace(/^http = .*$/m, `http = "127.0.0.1:${http}"`)
      : `${config.trimEnd()}\n\n[proxy]\nsocks5 = "127.0.0.1:${socks}"\nhttp = "127.0.0.1:${http}"\n`
    writeFileSync(configPath, config)
    // 每个节点用自己的一份程序文件：万一它被更新了，换掉的也只是这一份，不是构建出来的那一个。
    const program = options.program ?? this.ownProgram(node)
    const env = { ...process.env, ...options.env }
    const child =
      options.supervised === true
        ? spawn('sh', ['-c', SUPERVISOR], {
            stdio: 'ignore',
            env: { ...env, PROGRAM: program, STATE: node.dir },
            detached: true,
          })
        : spawn(program, ['--state-dir', node.dir, 'run'], { stdio: 'ignore', env })
    this.nodes.push({ child, group: options.supervised === true })
    node.socksPort = socks
  }

  /**
   * 让 `from` 经它本机的代理入口去连 `targetVirtualIp` 上一个没人监听的端口。
   * 连接本身会被拒绝，但两个节点之间因此建立了连接，随后各自上报到对方的路径：路由表里就有了真实的数据。
   */
  touch(from: NodeHandle, targetVirtualIp: string): void {
    if (from.socksPort === undefined) throw new Error('这个节点还没有跑起来')
    spawnSync('curl', [
      '-s',
      '-m',
      '8',
      '-o',
      '/dev/null',
      '-x',
      `socks5h://127.0.0.1:${from.socksPort}`,
      `http://${targetVirtualIp}:9/`,
    ])
  }

  /** 等到 controller 看到这么多节点在线。 */
  async waitOnline(count: number, network = 1): Promise<void> {
    await waitFor(`${count} 个节点在线`, async () => {
      const overview = await this.api<{ online: number }>('GET', `/networks/${network}/overview`)
      return overview.online >= count ? true : undefined
    })
  }

  async stop(): Promise<void> {
    await Promise.all([
      ...this.nodes.map(({ child, group }) => terminate(child, group)),
      terminate(this.process, false),
    ])
    // 不可写的目录里的文件删不掉，先改回可写。
    for (const directory of this.readOnly) chmodSync(directory, 0o755)
    rmSync(this.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
  }
}
