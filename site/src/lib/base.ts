/**
 * 站点挂在哪个路径下。直接放在域名根上时是空的；GitHub Pages 的项目站点是 `/仓库名`。
 * 组件里写站内的绝对路径（`/en/`）都要经过 {@link withBase}；Markdown 正文里的站内链接写相对路径。
 */
const BASE = import.meta.env.BASE_URL.replace(/\/$/, '')

/** 给站内的绝对路径补上站点的路径前缀。站外的地址原样返回。 */
export function withBase(path: string): string {
  return path.startsWith('/') ? `${BASE}${path}` : path
}

/** 去掉地址里的路径前缀，剩下的是站内的绝对路径。 */
export function withoutBase(pathname: string): string {
  if (BASE === '' || !pathname.startsWith(BASE)) return pathname
  return pathname.slice(BASE.length) || '/'
}
