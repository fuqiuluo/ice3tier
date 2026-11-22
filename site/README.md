# ice3tier 文档站

Astro Starlight。页面在 `src/content/docs/`：中文在根下，英文在 `en/` 下，两边的路径一一对应。

## 开发

需要 pnpm；pnpm 和 Node 的版本写在 `package.json` 里，pnpm 自己取。

```sh
pnpm install
pnpm dev
```

开发服务器在 `http://localhost:4321`。

## 检查和构建

```sh
pnpm check
pnpm build
```

产物在 `dist/`，是纯静态文件。

## 发布

推到 `main`、改动里有 `site/` 时，`.github/workflows/site.yml` 构建并发布到 GitHub Pages。站点的地址和它挂在哪个路径下由构建时的 `SITE_URL`、`SITE_BASE` 说；都不设时按放在根上构建。

正文里的站内链接写相对路径（`../relay/`）；组件里的站内路径经过 `src/lib/base.ts` 的 `withBase`。这样站点挂在子路径下也不会跳错。
