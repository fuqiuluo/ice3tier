import type { Messages } from '../messages'

export const signIn: Messages['signIn'] = {
  title: 'Sign in to ice3tier',
  tokenLabel: 'Admin token',
  show: 'Show token',
  hide: 'Hide token',
  remember: 'Stay signed in',
  submit: 'Sign in',
  empty: 'Enter the admin token',
  expired: 'Session expired',
  signedOut: 'Signed out',
  lostTitle: 'Lost the token?',
  lostBody: 'Stop the controller, then run it once as below. It prints a new token; the old one stops working.',
  lostCommand: 'i3t-controller --data-dir <data-dir> --public-addr <host:port> --reset-admin-token',
}

export const nav: Messages['nav'] = {
  label: 'Main navigation',
  console: 'Console',
  overview: 'Overview',
  nodes: 'Nodes',
  groupControl: 'Access control',
  groups: 'Groups',
  access: 'Policies',
  groupAccess: 'Traffic',
  proxies: 'Proxies',
  forwards: 'Port forwards',
  groupDiagnose: 'Diagnostics',
  topology: 'Topology',
  diagnosis: 'Path diagnosis',
  groupManage: 'Manage',
  pairs: 'Node pairs',
  network: 'Network',
  settings: 'Settings',
  collapse: 'Collapse sidebar',
  expand: 'Expand sidebar',
  openMenu: 'Open navigation',
  closeMenu: 'Close navigation',
  toggleGroup: (name, open) => `${open ? 'Collapse' : 'Expand'} ${name}`,
  signOut: 'Sign out',
  skipToContent: 'Skip to content',
  breadcrumb: 'Breadcrumb',
}

export const switcher: Messages['switcher'] = {
  label: 'Switch network',
  current: 'Current network',
  nodes: (n) => (n === 1 ? '1 node' : `${n} nodes`),
  manage: 'Network settings',
  heading: 'Networks',
  switched: (name) => `Switched to ${name}`,
}
