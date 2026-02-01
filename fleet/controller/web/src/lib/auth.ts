// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

// Operator-session token storage for controller-web. See
// docs/login-flow.md for the full flow.
//
// Tokens live in localStorage so they survive a reload but not a tab
// close-and-reopen across browser-quit. localStorage is XSS-reachable;
// the controller's CSP and the fact that we don't render user-supplied
// HTML anywhere are what keep that bounded. The trade is honest: nobody
// in this product holds anything more sensitive than a dsw_ token, and
// HttpOnly cookies would have made the WS `?token=` path uglier without
// changing the threat model meaningfully.

const TOKEN_KEY = 'dsw_token'
const USER_KEY = 'dsw_username'
const EXPIRES_KEY = 'dsw_expires_at' // unix seconds

export function getToken(): string | null {
  const t = localStorage.getItem(TOKEN_KEY)
  if (!t) return null
  const exp = Number(localStorage.getItem(EXPIRES_KEY) ?? '0')
  if (exp && Date.now() / 1000 > exp) {
    clearToken()
    return null
  }
  return t
}

export function getUsername(): string | null {
  return localStorage.getItem(USER_KEY)
}

export function setSession(token: string, username: string, expiresAt: number) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, username)
  localStorage.setItem(EXPIRES_KEY, String(expiresAt))
  window.dispatchEvent(new Event('dsw-auth-changed'))
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
  localStorage.removeItem(EXPIRES_KEY)
  window.dispatchEvent(new Event('dsw-auth-changed'))
}

/**
 * Build a WebSocket URL with `?token=` appended. The bearer can't ride
 * in a header on WS upgrade from the browser, so the controller accepts
 * it as a query-string param on /ws/* endpoints. See
 * `src/http.rs::ws_events_handler`.
 *
 * `extraParams` is merged in; provide `node`, `interface`, etc. here.
 */
export function wsUrl(path: string, extraParams: Record<string, string> = {}): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = new URL(`${protocol}//${window.location.host}${path}`)
  for (const [k, v] of Object.entries(extraParams)) {
    url.searchParams.set(k, v)
  }
  const token = getToken()
  if (token) url.searchParams.set('token', token)
  return url.toString()
}

/**
 * Call the logout endpoint, then clear local state regardless of the
 * response (network errors should not strand the user in a logged-in UI
 * with a dead token).
 */
export async function logout(): Promise<void> {
  const token = getToken()
  if (token) {
    try {
      await fetch('/api/v1/logout', {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
      })
    } catch {
      // Ignore — we're about to drop local state anyway.
    }
  }
  clearToken()
}

export interface LoginResult {
  ok: true
  username: string
  expiresAt: number
}
export interface LoginError {
  ok: false
  error: string
}

export async function login(username: string, password: string): Promise<LoginResult | LoginError> {
  let resp: Response
  try {
    resp = await fetch('/api/v1/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
  } catch (e) {
    return { ok: false, error: `network error: ${e instanceof Error ? e.message : String(e)}` }
  }

  if (resp.status === 401) {
    return { ok: false, error: 'invalid credentials' }
  }
  if (!resp.ok) {
    return { ok: false, error: `server error (${resp.status})` }
  }
  const body = (await resp.json()) as { token: string; username: string; expires_at: number }
  setSession(body.token, body.username, body.expires_at)
  return { ok: true, username: body.username, expiresAt: body.expires_at }
}
