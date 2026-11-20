import { useSyncExternalStore } from 'react'

/** 窄屏（手机）：外壳换成抽屉式的导航。和样式里的 `md` 断点是同一条线。 */
export const NARROW_SCREEN = '(max-width: 767.98px)'

/** 没有悬停的设备（手机、平板的触屏）：悬停才出现的东西要换一种办法给出来。 */
export const NO_HOVER = '(hover: none)'

/** 现在这一刻成不成立，不订阅。事件处理里用。 */
export function matchesMedia(query: string): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia(query).matches
}

/**
 * 一条媒体查询现在成不成立，变了就重新渲染。布局尽量用样式里的断点写；只有行为要跟着变的地方才用它
 * （抽屉在窗口变宽之后要关上）。没有 `matchMedia` 的环境（测试）里一律不成立。
 */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (listener) => {
      if (typeof window.matchMedia !== 'function') return () => undefined
      const media = window.matchMedia(query)
      media.addEventListener('change', listener)
      return () => media.removeEventListener('change', listener)
    },
    () => matchesMedia(query),
  )
}
