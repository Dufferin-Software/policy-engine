// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { useEffect, useState } from 'react'
import { getTheme, initTheme, toggleTheme, type Theme } from '../lib/theme'

// Light/dark switch for the header. Shows the icon for the theme you'd get
// by clicking: a sun while in dark mode (click for light), a moon while in
// light mode (click for dark).
export default function ThemeToggle() {
  const [theme, setThemeState] = useState<Theme>(getTheme())

  useEffect(() => {
    const sync = () => {
      initTheme() // re-assert the class (covers cross-tab `storage` events)
      setThemeState(getTheme())
    }
    window.addEventListener('dsw-theme-changed', sync)
    window.addEventListener('storage', sync) // sync across tabs
    return () => {
      window.removeEventListener('dsw-theme-changed', sync)
      window.removeEventListener('storage', sync)
    }
  }, [])

  const isDark = theme === 'dark'

  return (
    <button
      onClick={() => setThemeState(toggleTheme())}
      className="text-gray-400 hover:text-gray-100 p-1.5 rounded hover:bg-gray-800 transition-colors"
      title={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
    >
      {isDark ? (
        // Sun
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          viewBox="0 0 24 24"
        >
          <circle cx="12" cy="12" r="4" />
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M12 2v2m0 16v2m10-10h-2M4 12H2m15.07-7.07-1.41 1.41M6.34 17.66l-1.41 1.41m12.73 0-1.41-1.41M6.34 6.34 4.93 4.93"
          />
        </svg>
      ) : (
        // Moon
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z"
          />
        </svg>
      )}
    </button>
  )
}
