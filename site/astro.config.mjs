import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'
import react from '@astrojs/react'

const REPO = 'https://github.com/fuqiuluo/ice3tier'

// 发布到哪里由构建时的环境变量说：SITE_URL 是站点的地址，SITE_BASE 是它挂在哪个路径下
// （GitHub Pages 的项目站点是 /仓库名）。都不设时按放在根上构建，本机预览就是这样。
export default defineConfig({
  site: process.env.SITE_URL || undefined,
  base: process.env.SITE_BASE || '/',
  devToolbar: { enabled: false },
  integrations: [
    starlight({
      title: 'ice3tier',
      logo: { src: './src/assets/logo.svg' },
      favicon: '/favicon.svg',
      defaultLocale: 'root',
      locales: {
        root: { label: '简体中文', lang: 'zh-CN' },
        en: { label: 'English', lang: 'en' },
      },
      social: [{ icon: 'github', label: 'GitHub', href: REPO }],
      editLink: { baseUrl: `${REPO}/edit/main/site/` },
      customCss: ['@fontsource-variable/inter', './src/styles/theme.css'],
      components: {
        Hero: './src/components/Hero.astro',
        PageTitle: './src/components/PageTitle.astro',
        LanguageSelect: './src/components/LanguageSelect.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
      },
      expressiveCode: {
        // 命令常常很长：折行，不横向滚动。不要终端窗口那样的标题栏。
        defaultProps: { wrap: true, frame: 'none' },
        themes: ['min-dark', 'min-light'],
        styleOverrides: {
          borderRadius: '0.25rem',
          borderColor: 'var(--doc-line)',
          codeBackground: 'var(--doc-surface)',
          codeFontSize: '0.875rem',
          codeLineHeight: '1.6',
          codePaddingBlock: '0.9375rem',
          codePaddingInline: '1rem',
          frames: {
            frameBoxShadowCssValue: 'none',
            inlineButtonBorderOpacity: '0',
            inlineButtonBackgroundIdleOpacity: '0',
            inlineButtonForeground: 'var(--doc-muted)',
          },
        },
      },
      sidebar: [
        {
          label: '开始',
          translations: { en: 'Start' },
          items: ['start/intro'],
        },
        {
          label: '部署',
          translations: { en: 'Deployment' },
          items: ['deploy/overview', 'deploy/controller', 'deploy/nodes', 'deploy/relay', 'deploy/verify'],
        },
        {
          label: '维护',
          translations: { en: 'Maintenance' },
          items: ['maintain/upgrade', 'maintain/backup', 'maintain/admin-token', 'maintain/uninstall'],
        },
        {
          label: '开关与设置',
          translations: { en: 'Switches and settings' },
          items: [{ autogenerate: { directory: 'switches' } }],
        },
        {
          label: '参考',
          translations: { en: 'Reference' },
          items: ['reference/install-script', 'reference/other-install', 'reference/troubleshooting'],
        },
      ],
    }),
    react(),
  ],
})
