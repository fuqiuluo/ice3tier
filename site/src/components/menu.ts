/**
 * 顶栏下拉菜单的行为：点按钮开合；点别处、按 Esc、焦点离开时合上；上下键在条目之间移动。
 * 标记见 LanguageSelect.astro 和 ThemeSelect.astro。
 */
class Menu extends HTMLElement {
  private trigger = this.querySelector<HTMLButtonElement>('.i3t-menu-trigger')
  private popup = this.querySelector<HTMLElement>('.i3t-menu-popup')

  connectedCallback(): void {
    this.trigger?.addEventListener('click', () => this.toggle())
    this.addEventListener('keydown', (event) => this.onKey(event))
    this.addEventListener('focusout', (event) => {
      if (!(event.relatedTarget instanceof Node) || !this.contains(event.relatedTarget)) this.close()
    })
    document.addEventListener('click', (event) => {
      if (event.target instanceof Node && !this.contains(event.target)) this.close()
    })
  }

  private items(): HTMLElement[] {
    return [...(this.popup?.querySelectorAll<HTMLElement>('.i3t-menu-item') ?? [])]
  }

  private toggle(): void {
    if (this.popup?.hidden) this.open()
    else this.close()
  }

  open(): void {
    if (!this.popup || !this.trigger) return
    this.popup.hidden = false
    this.trigger.setAttribute('aria-expanded', 'true')
  }

  close(): void {
    if (!this.popup || !this.trigger || this.popup.hidden) return
    this.popup.hidden = true
    this.trigger.setAttribute('aria-expanded', 'false')
  }

  private onKey(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      this.close()
      this.trigger?.focus()
      return
    }
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
    event.preventDefault()
    this.open()
    const items = this.items()
    const at = items.indexOf(document.activeElement as HTMLElement)
    const step = event.key === 'ArrowDown' ? 1 : -1
    items[(at + step + items.length) % items.length]?.focus()
  }
}

if (!customElements.get('i3t-menu')) customElements.define('i3t-menu', Menu)

export { Menu }
