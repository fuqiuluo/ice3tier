# ice3tier WebUI

controller 的管理界面。React + TypeScript + Vite，只通过管理 API 和 controller 交互。

## 开发

需要 Node 22 或更新的版本和 pnpm。

```sh
pnpm install
pnpm dev
```

开发服务器在 `http://localhost:5173`，把 `/api` 代理到 controller 的管理地址，默认 `http://127.0.0.1:20332`。地址在别处时用 `I3T_CONTROLLER` 指定，或者把 `.env.example` 复制成 `.env.local` 再改。

本机跑一个 controller，在仓库的根目录执行。它要一个 PostgreSQL：`scripts/test-postgres.sh start` 起一个测试用的，`scripts/test-postgres.sh database dev` 在上面新建一个空库，打印它的连接串。

```sh
cargo build --release -p i3t-controller-bin -p i3t
export $(scripts/test-postgres.sh start)
target/release/i3t-controller --data-dir /tmp/i3t-dev --public-addr 127.0.0.1:20331 \
  --database-url "$(scripts/test-postgres.sh database dev)"
```

第一次启动时打印的管理令牌用来登录。

## 检查和测试

```sh
pnpm lint
pnpm typecheck
pnpm test
pnpm e2e
```

`pnpm e2e` 用真的 controller 和节点跑 Playwright 测试，先用 `pnpm e2e:kit` 编好要用的程序，并在仓库的根目录执行 `export $(scripts/test-postgres.sh start)`，起好测试用的 PostgreSQL。

## 构建

```sh
pnpm build
```

产物在 `dist/`。构建 controller 时 `web/dist` 存在就会编进程序；运行时也可以用 `--static-dir web/dist` 指定。
