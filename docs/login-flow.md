# controller-web login flow

This document describes operator authentication for the controller's web UI
and REST/GraphQL surface. It is the companion to `docs/authentication.md`
(which describes the older `POLICY_ENGINE_API_TOKEN` flow on the agent's
own GraphQL daemon).

## Summary

The controller exposes a single bearer-token scheme, backed by the
`api_tokens` table. Two kinds of tokens live in that table:

| Kind      | Minted by                         | Lifetime               | Revoked by                       |
| --------- | --------------------------------- | ---------------------- | -------------------------------- |
| `static`  | `policy-controller-mint-token` bin or `createApiToken` mutation | Operator-chosen (default: none) | `revokeApiToken` mutation        |
| `session` | `POST /api/v1/login`              | 12h (`SESSION_TTL_S`)  | `POST /api/v1/logout` or expiry  |

Both ride the same `Authorization: Bearer dsw_…` header (and `?token=`
query param for WebSocket endpoints). The middleware (`src/auth.rs`)
doesn't care about the kind — `kind` is bookkeeping for the operator UI
and for "kill all sessions" semantics, not an authorisation axis.

The web UI itself was previously unauthenticated; this design closes that
gap without changing the wire format of the API.

## Operator accounts

Stored in the `operators` table:

```sql
operators(
    id, username UNIQUE, password_hash, created_at,
    last_login_at, disabled_at
)
```

`password_hash` is the full **argon2id** PHC string
(`$argon2id$v=19$m=…$t=…$p=…$<salt>$<hash>`). Parameters are embedded in
the string, so cost can be retuned over time without a migration: future
verifies still work against historical hashes; on next successful login
we could re-hash to bring the row up to current cost (not yet wired —
see "Future work").

Disabled operators (`disabled_at IS NOT NULL`) cannot log in but their
existing session tokens stay valid until they expire. If you need to
immediately cut someone off, revoke each of their session rows via
`revokeApiToken` after flipping `disabled_at`. Eventually we'll grow a
"revoke all sessions for operator X" action.

### Bootstrapping the first operator

The first operator has to be created out-of-band because the login
endpoint won't authenticate against an empty table:

```
sudo -u policy-controller policy-controller-add-operator --username alice
Password: ********
Confirm:  ********
Operator "alice" created (id=1). They can now log in at /login.
```

Trust model matches the existing `policy-controller-mint-token` bin:
opens the SQLite DB directly. Anyone with filesystem access to
`controller.db` can already read every event and mint tokens, so adding
an operator from the same path does not widen the boundary.

For automation, pass `--password-file path/to/pw` instead of being
prompted (and ensure the file is mode 0600).

## Login

```
POST /api/v1/login
Content-Type: application/json

{ "username": "alice", "password": "…" }
```

Success → `200 OK`:

```json
{
  "token": "dsw_<base64url-32-bytes>",
  "expires_at": 1716583200,
  "username": "alice"
}
```

The client (controller-web) stores `token`, `username`, and `expires_at`
in `localStorage` and includes the token on every subsequent request.

Failure → `401 Unauthorized` with body `{"error": "invalid credentials"}`.
**The same response is returned for unknown user, wrong password, and
disabled account.** The login path also runs a dummy argon2 verify on
the "user not found" branch so timing doesn't leak account existence.

### Session token shape

A successful login does:

1. `argon2.verify_password(submitted, operators.password_hash)` — constant-time.
2. Resolve the operator's tenant (see "Tenant binding" below).
3. `api_tokens.create_session(name = "session:<username>:<ts>", tenant_id, expires_at = now + 12h, created_by = "login:<username>")`.
4. `UPDATE operators SET last_login_at = ?`.

The `name` includes the unix timestamp so the same operator can hold
multiple concurrent sessions (laptop + workstation) without violating
the `UNIQUE(name)` constraint.

### Tenant binding

Every `api_tokens` row carries a `tenant_id`. Login picks the tenant for
the new session row from the operator's role bindings
(`RbacStore::operator_tenant_ids`, which is `SELECT DISTINCT
roles.tenant_id FROM operator_roles JOIN roles …`):

| Operator tenant memberships | Login behaviour                                           |
| --------------------------- | --------------------------------------------------------- |
| Zero roles bound            | Default to `tenant_id = 1` (`default`). Session has zero permissions until roles are granted. |
| Exactly one tenant          | Bind that tenant on the session row.                      |
| Multiple tenants            | `409 Conflict` with `{"error": "operator has role bindings in multiple tenants; tenant selection on login is not yet implemented"}`. The UI doesn't have a tenant picker yet; when it does, this becomes a `tenant` field on the login request validated against the membership list. |

The `tenant_id` carried on the session row is what `auth.rs` hands to
`RbacStore::resolve(token_id, operator_id, tenant_id)` on every
subsequent request, which is what populates `Principal.tenant_slug` —
the value all tenant-scoped read paths (`apiTokens`, `enrollmentTokens`,
`onlineNodes`, `pendingGenerations`, audit log, etc.) filter on.

Static (CLI-minted) tokens get their tenant from the
`--tenant-id` flag on `policy-controller-mint-token` (default 1).
Static tokens minted via the `createApiToken` GraphQL mutation inherit
the caller's `principal.tenant_id`.

## Logout

```
POST /api/v1/logout
Authorization: Bearer dsw_…
```

Returns `200 OK` with `{"revoked": true}` if a row was flipped to
`revoked_at = now`, `{"revoked": false}` if the token was already
revoked / expired / unknown (idempotent).

The endpoint sits behind the same `bearer_auth` middleware as
`/graphql`, so a caller without a valid bearer can't reach it — that's
fine, there's nothing to log out from.

The frontend clears `localStorage` unconditionally after calling logout,
so a network failure doesn't strand the user in a logged-in UI with a
dead token.

## Frontend wiring

`fleet/controller/web/src/lib/auth.ts` is the single source of truth:

- `getToken()` / `setSession()` / `clearToken()` manage `localStorage`,
  with automatic expiry check (`expires_at` is checked on every
  `getToken()` call).
- `wsUrl(path, params)` builds a WebSocket URL with `?token=` appended.
  Browsers can't set custom headers on WS upgrade, so the bearer rides
  in the query string (matches `src/http.rs::ws_events_handler`).
- `login(username, password)` calls `/api/v1/login` and stores the
  result.
- `logout()` calls `/api/v1/logout` and clears local state regardless
  of network outcome.

Apollo Client gets two extra links in `main.tsx`:

```ts
const authLink = setContext((_, { headers }) => {
  const token = getToken()
  return { headers: { ...headers, ...(token ? { authorization: `Bearer ${token}` } : {}) } }
})

const authErrorLink = onError(({ networkError }) => {
  if (networkError && networkError.statusCode === 401) clearToken()
})
```

The root component listens for `dsw-auth-changed` (dispatched on
set/clear) and the cross-tab `storage` event, so a logout on tab A
re-renders tab B to the login screen.

## Why localStorage instead of HttpOnly cookies?

Cookies would have meant CSRF middleware on every state-changing
endpoint and either same-site rules or a CSRF token round-trip on the
WS handshake. The WS path is the deal-breaker: it already accepts
`?token=` in the URL because the browser can't attach headers to a WS
upgrade, and putting the token in the URL while *also* relying on a
cookie for auth doesn't materially reduce XSS exposure.

The trade is honest:

- **Risk:** XSS in the controller UI can read the token. We don't render
  user-supplied HTML; the bundle is statically served.
- **Reward:** one auth path for HTTP and WS; no CSRF apparatus.

The trade may flip when/if controller-web grows a tenant picker
that lets a multi-tenant operator switch tenants mid-session.

## Threat model notes

- **Brute force.** Login does an argon2id verify on every attempt
  (~50ms). No rate-limiter is wired yet; add one before exposing the
  controller to the public internet. (Today the controller assumes
  network-layer access control.)
- **Token theft.** Stolen `dsw_…` tokens are as good as the operator.
  Mitigations: short TTL (12h), revoke via logout. No HttpOnly cookie,
  no device binding — see above.
- **DB compromise.** All credentials at rest are argon2id (operators)
  or SHA-256 (api_tokens). The latter assumes 32 bytes of entropy in
  the plaintext, which `rand::thread_rng().fill_bytes` provides.
- **Timing.** `OperatorStore::verify_password` runs argon2 on the
  unknown-user branch too. Username enumeration via timing is bounded
  by argon2's own variance.

## Future work

- **Re-hash on login.** On successful login, if the stored hash's params
  are below current target cost, re-hash and `UPDATE operators`. Trivial
  to add — `argon2::PasswordHash::params(&stored)` reveals the cost
  inline.
- **"Sign out everywhere"** UI action that runs
  `UPDATE api_tokens SET revoked_at = ? WHERE kind = 'session' AND created_by = ?`.
- **Password reset.** No mail layer yet; the bootstrap bin is the
  fallback (operator-side: `policy-controller-add-operator --username
  alice` over the same username will fail with UNIQUE — needs a `--reset`
  flag or a separate `set-password` bin).
- **Rate limiting / lockout** on the login endpoint.
- **OIDC / SSO.** Out of scope until there's a target IdP.
- **Tenant picker on login.** Multi-tenant operators currently can't log
  in (409 from the membership-collision branch). Once controller-web
  grows a tenant selector, login should accept an optional `tenant`
  field and validate it against `operator_tenant_ids`.
