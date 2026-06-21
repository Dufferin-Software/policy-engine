// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

// Light/dark theme storage for controller-web.
//
// The palette lives in CSS variables (see src/index.css). Dark is the
// default and is represented by the absence of the `light` class on
// <html>; light mode adds it. The operator's choice is remembered in
// localStorage so it survives reloads. The no-flash bootstrap in
// index.html applies the stored class before React mounts; this module
// owns the runtime toggle and keeps it in sync.

export type Theme = 'dark' | 'light'

const THEME_KEY = 'dsw_theme'

export function getTheme(): Theme {
  return localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark'
}

function apply(theme: Theme) {
  document.documentElement.classList.toggle('light', theme === 'light')
}

export function setTheme(theme: Theme) {
  localStorage.setItem(THEME_KEY, theme)
  apply(theme)
  window.dispatchEvent(new Event('dsw-theme-changed'))
}

export function toggleTheme(): Theme {
  const next: Theme = getTheme() === 'light' ? 'dark' : 'light'
  setTheme(next)
  return next
}

/** Re-assert the stored theme. Safe to call before render. */
export function initTheme() {
  apply(getTheme())
}
