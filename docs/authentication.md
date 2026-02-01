# API Authentication

By default policy-engine runs with no authentication — any client that can
reach the HTTP port can execute GraphQL queries and mutations.  This is
intentional for local development and lab use, where the server typically
listens on `127.0.0.1`.

For production deployments the daemon supports **Bearer token authentication**
controlled by a single environment variable.

## Enabling authentication

Set `POLICY_ENGINE_API_TOKEN` before starting the daemon:

```bash
export POLICY_ENGINE_API_TOKEN="$(openssl rand -hex 32)"
systemctl restart policy-engine
```

When the variable is set the daemon logs:

```
Bearer token authentication enabled
```

When it is absent:

```
Bearer token authentication disabled (POLICY_ENGINE_API_TOKEN not set)
```

## Making authenticated requests

Include the token in every request as an HTTP `Authorization` header:

```
Authorization: Bearer <token>
```

### curl examples

```bash
# GraphQL query
curl -s http://localhost:8080/graphql \
  -H "Authorization: Bearer $POLICY_ENGINE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ status { version uptime_secs } }"}'

# Prometheus metrics scrape
curl -s http://localhost:8080/metrics \
  -H "Authorization: Bearer $POLICY_ENGINE_API_TOKEN"

# Schema SDL export
curl -s http://localhost:8080/schema.graphql \
  -H "Authorization: Bearer $POLICY_ENGINE_API_TOKEN"
```

### policy-client CLI

Pass the token via the `--token` flag or the `POLICY_ENGINE_API_TOKEN`
environment variable (the client reads it automatically if set):

```bash
policy-client --token "$POLICY_ENGINE_API_TOKEN" status
# or
POLICY_ENGINE_API_TOKEN=... policy-client status
```

### GraphQL Playground

The playground (`/playground`) requires auth when a token is configured.  Open
the playground in a browser and add the header in the **HTTP HEADERS** panel:

```json
{
  "Authorization": "Bearer <your-token>"
}
```

## Public endpoints

The `/health` endpoint is always accessible without a token, regardless of
configuration.  This allows load-balancer health checks to work without
embedding a secret.

All other endpoints (`/graphql`, `/metrics`, `/schema.graphql`, `/ws/events`,
`/playground`) require a valid token when auth is configured.

## Token management

The daemon does not manage token lifecycle — rotation is done by restarting the
service with a new value of `POLICY_ENGINE_API_TOKEN`.  For secrets management
in production, the recommended approach is to store the token in a secrets
manager (e.g. HashiCorp Vault, AWS Secrets Manager) and inject it into the
systemd unit via a drop-in override:

```ini
# /etc/systemd/system/policy-engine.service.d/auth.conf
[Service]
EnvironmentFile=/run/secrets/policy-engine
```

Where `/run/secrets/policy-engine` contains:

```
POLICY_ENGINE_API_TOKEN=<token>
```

Then restrict permissions:

```bash
chmod 600 /run/secrets/policy-engine
chown root:root /run/secrets/policy-engine
```

## Security notes

- Token comparison is done with a simple string equality check — there is no
  timing-safe comparison.  Tokens should be long (≥ 32 random bytes / 64 hex
  characters) so that brute-force is infeasible regardless.
- The daemon does not support multiple tokens, roles, or per-client
  authorisation.  All authenticated clients have full read/write access.
- The daemon supports native TLS — see [tls.md](tls.md).  A reverse proxy
  (nginx, Caddy, HAProxy) is still a valid option but is no longer required.
- The Bearer token is visible in server logs if your proxy logs full request
  headers.  Ensure proxy log sanitisation is in place.
