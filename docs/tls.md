# TLS / HTTPS

Policy-engine has native TLS support using [rustls](https://github.com/rustls/rustls)
(no OpenSSL dependency).  When TLS is enabled the daemon serves HTTPS on the
configured port; the WebSocket event stream (`/ws/events`) and all other
endpoints are served over the same TLS connection — no separate port or proxy
is needed.

TLS is **opt-in**.  If neither `tls_cert` nor `tls_key` is configured the
daemon falls back to plain HTTP, preserving backward compatibility.

---

## Configuration

TLS is configured through the config file at `/etc/policy-engine/config.toml`
and/or CLI flags.  **CLI flags override the config file.**

### Config file (recommended for production)

```toml
[server]
host     = "0.0.0.0"        # optional — defaults to 127.0.0.1
port     = 8443             # optional — defaults to 8080
tls_cert = "/etc/policy-engine/server.crt"
tls_key  = "/etc/policy-engine/server.key"
```

Both `tls_cert` and `tls_key` must be set together, or neither.  Providing
only one is a startup error.

### CLI flags

```bash
policy-engine \
  --tls-cert /etc/policy-engine/server.crt \
  --tls-key  /etc/policy-engine/server.key \
  --port 8443
```

| Flag | Description |
|---|---|
| `--tls-cert <path>` | PEM certificate file (may include full chain) |
| `--tls-key <path>` | PEM private key (RSA, EC, or PKCS8) |
| `--port <n>` | Override the listen port from config file |
| `--host <addr>` | Override the bind address from config file |

---

## Certificate setup

### Self-signed certificate (development / lab)

A self-signed cert is quick to generate and works with `--tls-insecure` or
when you distribute the CA cert to clients.

```bash
# Generate a CA key and self-signed CA cert.
openssl ecparam -name P-256 -genkey -noout -out /etc/policy-engine/ca.key
openssl req -x509 -new -key /etc/policy-engine/ca.key -sha256 -days 365 \
  -subj "/CN=Policy Engine CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,digitalSignature" \
  -out /etc/policy-engine/ca.crt

# Generate the server key and a CSR.
openssl ecparam -name P-256 -genkey -noout -out /etc/policy-engine/server.key
openssl req -new -key /etc/policy-engine/server.key \
  -subj "/CN=$(hostname)" -out /tmp/server.csr

# Sign the server cert with the CA.
# Adjust subjectAltName to match the hostname or IP clients will connect to.
printf "[ext]\nsubjectAltName=DNS:$(hostname),IP:127.0.0.1\n" \
  > /tmp/server.ext
openssl x509 -req -in /tmp/server.csr \
  -CA /etc/policy-engine/ca.crt -CAkey /etc/policy-engine/ca.key \
  -CAcreateserial -days 365 -sha256 \
  -extfile /tmp/server.ext -extensions ext \
  -out /etc/policy-engine/server.crt

# Tighten permissions.
chmod 600 /etc/policy-engine/server.key /etc/policy-engine/ca.key
chmod 644 /etc/policy-engine/server.crt /etc/policy-engine/ca.crt
rm -f /tmp/server.csr /tmp/server.ext
```

Distribute `/etc/policy-engine/ca.crt` to any host that needs to verify the
server's certificate.

### CA-signed certificate (production)

If you have an internal CA or use Let's Encrypt / ACME, obtain a certificate
for the hostname clients will use and place the certificate chain and private
key at the paths configured in `[server]`.

The `tls_cert` file may contain the full chain (leaf + intermediates).  The
`tls_key` file must contain only the matching private key.

---

## Connecting with policy-client

```bash
# Trust a specific CA cert (recommended with self-signed certs).
policy-client \
  --server https://policy-engine.example.com:8443/graphql \
  --tls-ca-cert /path/to/ca.crt \
  status

# Skip certificate verification (development only — insecure).
policy-client \
  --server https://127.0.0.1:8443/graphql \
  --tls-insecure \
  status
```

| Flag | Description |
|---|---|
| `--tls-ca-cert <path>` | PEM CA certificate to trust (for self-signed server certs) |
| `--tls-insecure` | Skip TLS certificate verification — **dev only** |

These flags are global and apply to all subcommands.

---

## Connecting with curl

```bash
# Trust CA cert explicitly.
curl --cacert /path/to/ca.crt \
  https://policy-engine.example.com:8443/health

# Skip verification (development only).
curl -k https://127.0.0.1:8443/health

# GraphQL query with CA cert.
curl --cacert /path/to/ca.crt \
  -X POST https://policy-engine.example.com:8443/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ status { version } }"}'
```

---

## Web UI

The React web UI is served from the same HTTPS port as the API.  When the
browser loads the UI over HTTPS it automatically uses `wss://` for the
WebSocket event stream — no configuration is needed.

Open the UI at `https://<host>:<port>/` and accept or install the CA cert in
your browser if using a self-signed certificate.

---

## Authentication + TLS

TLS and Bearer token authentication are independent features that complement
each other.  In production, enable both:

1. Configure TLS as above.
2. Set `POLICY_ENGINE_API_TOKEN` — see [docs/authentication.md](authentication.md).

TLS protects the token from interception; the token prevents unauthorised
clients from reaching the API even if they trust the server's certificate.

---

## Security notes

- TLS termination is handled natively by the daemon — no reverse proxy is
  required, though using one (nginx, Caddy) is still valid and supported.
- The daemon requires TLS 1.2 or 1.3; older protocol versions are not
  negotiated.
- Certificate files are read at startup.  To rotate certificates, update the
  files and restart the service (`systemctl restart policy-engine`).
- Private key files should be owned by the `policy-engine` service user and
  mode `0600`.
