// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  ApolloClient,
  ApolloProvider,
  HttpLink,
  InMemoryCache,
  from,
} from '@apollo/client'
import { setContext } from '@apollo/client/link/context'
import { onError } from '@apollo/client/link/error'
import './index.css'
import App from './App.tsx'
import Login from './components/Login.tsx'
import { clearToken, getToken } from './lib/auth'

const httpLink = new HttpLink({ uri: '/graphql' })

// Inject the operator's session token on every Apollo request. See
// docs/login-flow.md for the full bearer-token flow.
const authLink = setContext((_, { headers }) => {
  const token = getToken()
  return {
    headers: {
      ...headers,
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  }
})

// If the controller rejects our token (expired, revoked, restarted with a
// fresh DB), drop the local session and let the root re-render to the
// login screen. The error link only fires for `networkError`s — actix
// returns the auth failure as a 401 with a JSON body, which Apollo
// surfaces here, not as a GraphQL error.
const authErrorLink = onError(({ networkError }) => {
  const status =
    networkError && 'statusCode' in networkError
      ? (networkError as { statusCode?: number }).statusCode
      : undefined
  if (status === 401) {
    clearToken()
  }
})

const client = new ApolloClient({
  link: from([authErrorLink, authLink, httpLink]),
  cache: new InMemoryCache(),
})

function Root() {
  const [token, setToken] = useState<string | null>(getToken())

  useEffect(() => {
    const onChange = () => setToken(getToken())
    window.addEventListener('dsw-auth-changed', onChange)
    window.addEventListener('storage', onChange) // sync across tabs
    return () => {
      window.removeEventListener('dsw-auth-changed', onChange)
      window.removeEventListener('storage', onChange)
    }
  }, [])

  if (!token) {
    return <Login onSuccess={() => setToken(getToken())} />
  }
  return (
    <ApolloProvider client={client}>
      <App />
    </ApolloProvider>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
)
