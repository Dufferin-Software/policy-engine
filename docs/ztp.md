# Zero-Touch Provisioning (ZTP) for policy-node-agent

This document describes how to enrol fleets of nodes into a `policy-controller`.
ZTP is the only supported enrollment path: agents present a short-lived
bootstrap token at first connect, and the controller auto-approves and
returns the per-node mTLS credentials in the same response.

For the deeper security model see [enrollment-crypto.md](enrollment-crypto.md).

## TL;DR

```
# On the controller host: mint an operator API token (printed once).
policy-controller-mint-token --name ztp --role operator

# On the operator's workstation: authenticate the client with that token.
export POLICY_CONTROLLER_TOKEN=<token from the controller host>
policy-controller-client enroll-token create \
    --controller-url https://controller.example.com:7777 \
    --ttl 1h \
    --max-uses 50 \
    --label edge-fleet \
    --bundle-only > bundle.b64

# On each target host (already managed by your config-mgmt):
ansible -i fleet.ini -m copy \
    -a "src=bundle.b64 dest=/etc/policy-node-agent/bootstrap.bundle mode=0600" all
ansible -i fleet.ini -m apt -a "name=policy-node-agent state=present" all
```

That's it. Each host reads the bundle on first boot, presents the token, the
controller auto-approves, the agent persists its own per-node mTLS credentials,
deletes the consumed bundle, and joins the management stream. The token
expires automatically; nothing to clean up.

## What is in a bundle

A bootstrap bundle is a base64url-no-pad blob (typically ~200 bytes) carrying:

| Field             | Purpose                                                         |
|-------------------|-----------------------------------------------------------------|
| `enrollment_url`  | gRPC URL of the enrollment endpoint (TLS, no client cert yet).  |
| `controller_url`  | gRPC URL of the management endpoint (mTLS, used after enroll).  |
| `ca_fp_sha256`    | SHA-256 over the controller CA cert DER (32 bytes, hex).         |
| `token_id`        | UUID, opaque, used for lookup and revocation.                   |
| `token_b64`       | 32-byte random secret, base64url-encoded.                       |
| `expires_at`      | Unix seconds; controller is authoritative.                      |

The bundle is **not** a long-lived shared secret. It is a one-shot grant that
is scoped (TTL, max-uses, optional CIDR), revocable, and consumed at first
use. The same bundle file is distributed to every host in a rollout batch —
distribution effort is identical to pushing any fleet-wide config file.

## Operator workflow

### 0. Authenticate the client

Operators run `policy-controller-client` remotely against the controller's
HTTP API; the token itself is minted on the controller host. These are two
different machines:

**On the controller host** — `policy-controller-mint-token` opens the
controller's SQLite DB directly, so it must run where that file lives (the
controller host, as the service user or root). Mint a token with the
`enrollment:write` permission and hand the plaintext to the operator over a
secure channel:

```
# On the controller host:
policy-controller-mint-token --name ztp --role operator
# prints the plaintext token on stdout — copy it now, it cannot be retrieved later
```

**On the operator workstation** — `policy-controller-client` talks only to the
controller's REST + GraphQL surface over the network. On any controller with
the `api_tokens` migration applied it must present that token: pass it with
`--token <tok>` or set `POLICY_CONTROLLER_TOKEN` in the environment. Without it
the enroll-token calls below are rejected before they reach the controller.

```
# On the operator workstation:
export POLICY_CONTROLLER_TOKEN=<token from the controller host>
```

The token's roles gate which enroll-token operations are allowed:

| Operation                  | Required permission  | Built-in roles that grant it       |
|----------------------------|----------------------|------------------------------------|
| `enroll-token create`      | `enrollment:write`   | `admin`, `operator`, `security-admin` |
| `enroll-token list`        | `enrollment:read`    | any read role (`viewer`, `auditor`, …) |
| `enroll-token revoke`      | `enrollment:delete`  | `admin`, `operator`, `security-admin` |

The token is tenant-scoped, and the tenant it binds to (`--tenant-id` on
`mint-token`, default `1`/`default`) is the tenant every node enrolled via the
resulting bundle is re-bound to (see "Multi-tenant enrollment" below).

### 1. Mint an enrollment token

```
policy-controller-client enroll-token create \
    --controller-url https://controller.example.com:7777 \
    --enrollment-url https://controller.example.com:7776 \
    --ttl 1h \
    --max-uses 50 \
    --label edge-fleet \
    --cidr 10.0.0.0/8
```

- `--enrollment-url` is optional; defaults to `controller-url` with `:7777`
  replaced by `:7776`.
- `--ttl` accepts plain seconds or `s/m/h/d` suffix (e.g. `1h`, `30m`, `7d`).
- `--max-uses` caps the number of distinct enrollments. Pick a number ≥ the
  rollout batch size but as small as feasible.
- `--cidr` restricts which source addresses may redeem the token (optional).
- `--label` sets a fleet label on every node enrolled via this token.

Add `--bundle-only` if you want only the base64 blob on stdout (suitable for
`> bundle.b64`). Without it the command prints the metadata too. The bundle
is shown **exactly once**.

### 2. Distribute the bundle

Use whatever your fleet already runs — Ansible, Puppet, Salt, cloud-init,
manual scp. The required outcome: `/etc/policy-node-agent/bootstrap.bundle`
exists on each target host with mode 0600, before the systemd unit starts.

Alternatives the agent also accepts:
- `POLICY_BOOTSTRAP_BUNDLE=/path/to/bundle.b64` environment variable on the
  systemd unit.
- `--bootstrap-bundle /path/to/bundle.b64` CLI flag.

### 3. Install the package

`apt install policy-node-agent` (or restart the service if already installed).
The agent's startup sequence is now:

1. If `/var/lib/policy-node-agent/controller-client.{key,crt}` exist → already
   enrolled; load and proceed.
2. Otherwise, if a bootstrap bundle is present → enrol.
3. Otherwise → hard fail with instructions to mint a bundle.

On enrollment the agent:

- Parses the bundle and uses its `controller_url`/`enrollment_url` (overriding
  the values in `config.toml` if any).
- Opens TLS to the enrollment endpoint with a rustls verifier that pins the
  CA fingerprint from the bundle. No pre-distributed CA cert.
- Includes the token in `EnrollmentRequest.bootstrap_token`.
- Receives the auto-approved mTLS credentials in the *same* response.
- Persists `controller-client.{key,crt}` and `controller-ca.crt` under
  `/var/lib/policy-node-agent/` (the systemd unit's StateDirectory; the agent
  cannot write to `/etc/` under `ProtectSystem=strict`).
- **Deletes the bundle file** — consumed-secret hygiene.

### 4. Token lifecycle

```
policy-controller-client enroll-token list
policy-controller-client enroll-token revoke <token-id>
```

Revoke any token you suspect is leaked. Tokens expire automatically; there is
no cleanup required.

## Security properties

| Property                                          | Outcome                                                                                                                                                                          |
|---------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| MITM on the enrollment TLS leg                    | Blocked: the agent verifies the controller's CA cert by SHA-256 fingerprint pin. An attacker without the controller's actual CA cert cannot complete the handshake.              |
| Bundle stolen from disk before first use          | Attacker may enrol up to `uses_remaining` nodes before TTL/revocation. Use short TTL + small `--max-uses` + optional `--cidr`. Treat bundles like SSH private keys in operator tooling. |
| Cloned disk image containing a fresh bundle       | Bundle redeems once (or until exhausted). Hardware binding is out of scope for the bundle mechanism; see "Future work" in `enrollment-crypto.md`.                                |
| Compromised controller at token-issuance time     | Attacker-issued tokens are still useless against legitimate agents: the bundle pins the legitimate CA fingerprint, and the attacker doesn't have the matching server key.        |
| Lost bundle (operator workstation, CI logs, etc.) | Same as "stolen". Revoke immediately via `enroll-token revoke`.                                                                                                                  |

A node whose token is invalid or expired (e.g. operator typo, stale bundle)
still creates a `Pending` enrollment record on the controller for manual
investigation, but is not auto-approved. The operator can `approveEnrollment`
or `rejectEnrollment` via the GraphQL API in that case.

## Configuration reference

In `/etc/policy-node-agent/config.toml`:

```toml
# Optional — the bundle carries these. Set them only if you want a fallback
# in case the bundle URL fields are wrong.
# controller_url = "https://controller.example.com:7777"
# enrollment_url = "https://controller.example.com:7776"

# Where to look for a ZTP bundle on startup. Default shown.
bootstrap_bundle_path = "/etc/policy-node-agent/bootstrap.bundle"
```

The agent CLI also accepts `--bootstrap-bundle <path>` (or
`POLICY_BOOTSTRAP_BUNDLE=<path>` in the env) for one-off enrollments without
editing config files.

## Verification

A new node should reach Active status within a few seconds of `apt install`:

```
policy-controller-client nodes list --status active
policy-controller-client audit list --limit 20
```

The audit log records `enrollment_token_created`, `enrollment_token_redeemed`,
`enrollment_approved`, and `enrollment_token_rejected` events alongside the
operator action that triggered each.

## Multi-tenant enrollment

Enrollment tokens are tenant-scoped:

- The `enrollment_tokens` row carries a `tenant_id` (slug), inherited from
  the principal that minted the token. `enrollmentTokens` and
  `createEnrollmentToken` always operate within the caller's tenant —
  there is no cross-tenant view.
- New nodes are born in the controller's `default` tenant during the
  `Pending` submission step (`submit_enrollment`), then **re-bound** to
  the token's tenant the moment the token is redeemed. The subsequent
  cert-issue, status flip, and auto-approve audit row all land in the
  correct tenant.
- The redeem path returns `TokenRedeemOutcome::Redeemed { fleet_label,
  tenant_id }`; the controller's `submit_enrollment_with_token` calls
  `ControllerStore::update_node_tenant` before `approve_enrollment`.

To bootstrap a non-default tenant before minting its first token, run
the new `policy-controller-bootstrap-tenant` bin (creates the
`tenants` row and seeds the per-tenant built-in role set so
`createApiToken --tenant-id <new>` has somewhere to bind roles).
