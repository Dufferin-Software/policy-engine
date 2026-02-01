// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/graphql': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/schema.graphql': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/ws/events': {
        target: 'ws://localhost:8080',
        ws: true,
        configure: (proxy) => {
          proxy.on('error', () => {});
        },
      },
      '/ws/rule-events': {
        target: 'ws://localhost:8080',
        ws: true,
        configure: (proxy) => {
          proxy.on('error', () => {});
        },
      },
    },
  },
})
