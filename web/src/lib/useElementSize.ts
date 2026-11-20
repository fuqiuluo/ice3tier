import { useCallback, useRef, useState } from 'react'

export interface ElementSize {
  width: number
  height: number
}

const UNKNOWN: ElementSize = { width: 0, height: 0 }

/**
 * 一个元素现在有多大，变了就重新渲染。给"排法要跟着自己那一块的大小变、样式里又写不出来"的地方用（画图的画布）。
 * 还没量到时（也包括不做布局的测试环境）宽和高都是 0。
 */
export function useElementSize(): [(element: HTMLElement | null) => void, ElementSize] {
  const [size, setSize] = useState<ElementSize>(UNKNOWN)
  const observer = useRef<ResizeObserver | null>(null)

  const ref = useCallback((element: HTMLElement | null) => {
    observer.current?.disconnect()
    observer.current = null
    if (element === null) return
    observer.current = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect
      if (rect === undefined) return
      const next = { width: Math.round(rect.width), height: Math.round(rect.height) }
      setSize((current) => (current.width === next.width && current.height === next.height ? current : next))
    })
    observer.current.observe(element)
  }, [])

  return [ref, size]
}
