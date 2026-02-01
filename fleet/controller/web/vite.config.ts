// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
    proxy: {
      '/graphql': {
        target: 'http://localhost:8443',
        changeOrigin: true,
      },
      '/ws/events': {
        target: 'ws://localhost:8443',
        ws: true,
        configure: (proxy) => {
          proxy.on('error', () => {});
        },
      },
      '/ws/rule-events': {
        target: 'ws://localhost:8443',
        ws: true,
        configure: (proxy) => {
          proxy.on('error', () => {});
        },
      },
    },
  },
})
