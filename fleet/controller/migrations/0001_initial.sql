-- policy-controller schema
-- Managed by sqlx migrate!()

CREATE TABLE IF NOT EXISTS nodes (
    id                TEXT PRIMARY KEY,
    label             TEXT,
    -- Hex-encoded DER SPKI public key bytes
    public_key_der    TEXT NOT NULL,
    dmi_uuid          TEXT,
    status            TEXT NOT NULL CHECK (status IN ('pending', 'active', 'decommissioned')),
    -- Hex-encoded DER serial number of the issued mTLS client cert
    cert_serial       TEXT,
    -- Unix timestamp
    cert_expiry       INTEGER,
    last_seen         INTEGER,
    enrolled_at       INTEGER,
    decommissioned_at INTEGER,
    -- Timestamp of the most recent successful RenewClientCert; NULL until first renewal.
    last_renewed_at   INTEGER,
    -- UUID of the pending enrollment request
    enrollment_id     TEXT,
    tpm_backed        INTEGER NOT NULL DEFAULT 0,
    agent_version     TEXT,
    -- OS hostname reported by agent (display only)
    hostname          TEXT,
    -- OS pretty name, e.g. "Debian GNU/Linux 13 (trixie)"
    os_pretty_name    TEXT,
    -- Kernel version, e.g. "6.12.74+deb13+1-amd64"
    kernel_version    TEXT,
    -- DMI sys_vendor from /sys/class/dmi/id/sys_vendor (e.g. "Dell Inc.")
    dmi_sys_vendor    TEXT,
    -- DMI product_name from /sys/class/dmi/id/product_name (e.g. "PowerEdge R340")
    dmi_product_name  TEXT,
    -- Multi-tenancy support
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    -- Operator-configured stop behavior ("clear-state" or "preserve-state").
    -- NULL means controller has not set a preference (node uses its local default).
    stop_behavior     TEXT,
    -- Operator-configured metrics scrape/forward interval in seconds.
    -- NULL means the controller has not set a preference (agent uses its local default).
    metrics_interval_secs INTEGER,
    -- JSON-encoded Capabilities (features/engine_version/sources) reported in
    -- the most recent AgentHello. Used by alert-rule write-time validation to
    -- reject rules referencing sources no node in the fleet advertises.
    -- Defaults to '{}' so pre-step-6 rows decode as "no capabilities known".
    capabilities      TEXT NOT NULL DEFAULT '{}',
    -- Node-global Suricata inspect mode ('disabled' / 'ips' / 'ids').
    -- Agent-authoritative: written when a SetInspectMode generation commits
    -- AND overwritten by every StateSnapshot; never re-pushed on reconnect
    -- (same model as uRPF/FIB).
    inspect_mode      TEXT NOT NULL DEFAULT 'disabled'
);

CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_nodes_enrollment_id ON nodes(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_nodes_tenant ON nodes(tenant_id);

-- Per-node, per-interface, per-direction rules.
CREATE TABLE IF NOT EXISTS rules (
    id              TEXT PRIMARY KEY, -- This is a u64, unique per tenant.
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    node_id         TEXT NOT NULL REFERENCES nodes(id),
    interface_name  TEXT NOT NULL,
    direction       TEXT NOT NULL CHECK (direction IN ('ingress', 'egress')),
    src_cidr        TEXT,
    dst_cidr        TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT NOT NULL DEFAULT 'any',
    sni_pattern     TEXT,
    quic_version    TEXT,
    src_mac         TEXT,
    dst_mac         TEXT,
    -- JSON array: [{"action":"drop","priority":0}]
    actions_json    TEXT NOT NULL DEFAULT '[]',
    -- Unix timestamp
    created_at      INTEGER NOT NULL,
    created_by      TEXT,
    -- Rule TTL: drop the rule after this many seconds have elapsed since created_at
    expires_after_secs INTEGER,
    -- JSON weekly schedule (when NULL the rule is always active)
    schedule_json      TEXT
);

CREATE INDEX IF NOT EXISTS idx_rules_node ON rules(node_id);
CREATE INDEX IF NOT EXISTS idx_rules_node_iface ON rules(node_id, interface_name, direction);
CREATE INDEX IF NOT EXISTS idx_rules_tenant ON rules(tenant_id);

-- Network interfaces discovered from each node's agent
CREATE TABLE IF NOT EXISTS node_interfaces (
    node_id         TEXT NOT NULL REFERENCES nodes(id),
    interface_name  TEXT NOT NULL,
    -- Linux interface index (matches `ifindex` on flow events). 0 if agent didn't report.
    ifindex         INTEGER NOT NULL DEFAULT 0,
    mac_address     TEXT,
    link_state      TEXT NOT NULL DEFAULT 'unknown',
    -- JSON array of {address, prefix_len, family}
    addresses_json  TEXT NOT NULL DEFAULT '[]',
    -- Operator-assigned tag (e.g. "WAN", "LAN")
    tag             TEXT,
    -- Unix timestamp
    last_reported   INTEGER NOT NULL,
    -- BPF program attachment state (reported by agent)
    xdp_attached    INTEGER NOT NULL DEFAULT 0,
    tc_attached     INTEGER NOT NULL DEFAULT 0,
    -- Agent-reported XDP FIB forwarding enabled on this interface (ingress only)
    fib_forwarding  INTEGER NOT NULL DEFAULT 0,
    -- uRPF mode on this interface (ingress only): 0 = off, 1 = loose, 2 = strict
    urpf_mode       INTEGER NOT NULL DEFAULT 0,
    -- Agent-reported per-interface Suricata inspection flag (0/1). Only
    -- effective while the node's inspect_mode is 'ips' or 'ids'.
    inspect_enabled INTEGER NOT NULL DEFAULT 0,
    -- Operator-configured default action for unmatched packets (NULL = engine default PASS)
    ingress_default_action TEXT,
    egress_default_action  TEXT,
    PRIMARY KEY (node_id, interface_name)
);

CREATE INDEX IF NOT EXISTS idx_node_interfaces_node ON node_interfaces(node_id);

-- Named fleet-managed Suricata rulesets. Each ruleset materialises on
-- assigned nodes as one file: /etc/suricata/rules/policy-engine/fleet-<name>.rules
-- (files without the "fleet-" prefix are node-local and never touched by the
-- controller). Content is capped at 4 MiB and canonicalised to end with '\n';
-- sha256 is over the exact content bytes — the drift-detection contract with
-- the engine's byte-verbatim write_rules/list_custom_rules_meta.
CREATE TABLE IF NOT EXISTS suricata_rulesets (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    name        TEXT NOT NULL,
    content     TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    rule_count  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (tenant_id, name)
);

-- Which rulesets are assigned to which nodes (desired state).
CREATE TABLE IF NOT EXISTS node_suricata_rulesets (
    node_id     TEXT NOT NULL REFERENCES nodes(id),
    ruleset_id  TEXT NOT NULL REFERENCES suricata_rulesets(id),
    PRIMARY KEY (node_id, ruleset_id)
);

CREATE INDEX IF NOT EXISTS idx_node_suricata_rulesets_ruleset
    ON node_suricata_rulesets(ruleset_id);

-- Agent-reported Suricata rule files (ALL files in the rules dir, fleet- and
-- local), refreshed from every StateSnapshot. Drives in-sync badges and the
-- drift reconcile without re-querying agents.
CREATE TABLE IF NOT EXISTS node_suricata_rule_files (
    node_id     TEXT NOT NULL REFERENCES nodes(id),
    filename    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    rule_count  INTEGER NOT NULL,
    PRIMARY KEY (node_id, filename)
);

CREATE TABLE IF NOT EXISTS revoked_certs (
    -- Hex-encoded DER serial
    serial     TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);

-- PEM certificates stored separately to avoid bloating the nodes table
CREATE TABLE IF NOT EXISTS node_certs (
    node_id  TEXT PRIMARY KEY REFERENCES nodes(id),
    cert_pem TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    operator TEXT,
    action   TEXT NOT NULL,
    node_id  TEXT,
    detail   TEXT,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_node ON audit_log(node_id);

-- ZTP bootstrap tokens. An operator mints a token via the GraphQL API, the
-- token (alongside the controller URL and CA fingerprint) is embedded in a
-- bootstrap bundle distributed to nodes. On enrollment, a valid token causes
-- the controller to auto-approve the node without operator intervention.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    -- UUID, also embedded in the bundle for token lookup.
    token_id       TEXT PRIMARY KEY,
    -- SHA-256 of the random token secret. Stored hashed so a database leak
    -- does not yield usable tokens.
    token_hash     BLOB NOT NULL,
    -- Unix timestamp.
    created_at     INTEGER NOT NULL,
    -- Operator that minted the token (NULL when minted via unauthenticated path,
    -- not currently used but reserved for future server-issued tokens).
    created_by     TEXT,
    -- Unix timestamp at which the token expires.
    expires_at     INTEGER NOT NULL,
    -- Remaining uses. Atomically decremented on each successful redemption.
    uses_remaining INTEGER NOT NULL,
    -- Optional CIDR restriction (textual, e.g. "10.0.0.0/8"). NULL = no restriction.
    cidr_scope     TEXT,
    -- Optional fleet label applied to nodes enrolled through this token.
    fleet_label    TEXT,
    -- Set to a timestamp when revoked; revoked tokens are never accepted.
    revoked_at     INTEGER,
    -- Tenant the token belongs to (matches nodes.tenant_id / audit_log.tenant_id
    -- TEXT slug convention, NOT the numeric tenants.id). The GraphQL list and
    -- mint resolvers filter on this so tenant A can't see or revoke tenant B's
    -- bundles. Redemption-time propagation of this tenant into the new node
    -- row is a separate follow-up (today nodes always land in `default`).
    tenant_id      TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_expires ON enrollment_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_tenant  ON enrollment_tokens(tenant_id);

-- API bearer tokens used by Grafana, controller-web sessions, and other
-- REST/GraphQL consumers to authenticate against the controller. See
-- docs/event-pipeline.md open question 1 and docs/login-flow.md. Same
-- hash-at-rest pattern as enrollment_tokens above.
CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY,
    -- Operator-facing label, e.g. "grafana-prod" for static tokens.
    -- Session tokens auto-generate a name like "session:<username>:<ts>".
    -- Unique so accidentally minting "grafana" twice fails fast.
    name         TEXT NOT NULL UNIQUE,
    -- SHA-256 of the random plaintext. Plaintext is shown once at creation
    -- and never persisted.
    token_hash   BLOB NOT NULL,
    -- 'static'  = minted by mint-token bin / GraphQL, long-lived, named.
    -- 'session' = minted by /api/v1/login, short-lived, revoked on logout.
    -- The distinction exists so the operator-token-list UI can filter
    -- noisy session rows and so a future "kill all sessions for operator X"
    -- action can target them precisely.
    kind         TEXT NOT NULL DEFAULT 'static' CHECK (kind IN ('static', 'session')),
    created_at   INTEGER NOT NULL,
    -- Originator. For static tokens minted by the bootstrap bin this is
    -- "mint-token-bin"; for static tokens minted via GraphQL it's
    -- "operator:<username>"; for session tokens it's "login:<username>".
    -- NULL only for legacy rows predating the field.
    created_by   TEXT,
    -- Numeric FK to the issuing operator. NULL for static tokens minted by
    -- the CLI bootstrap (no operator context) or by automation that does
    -- not authenticate as an operator. Session tokens always set this so
    -- that disabling an operator effectively downgrades their active
    -- sessions to zero permissions (see rbac::Principal::resolve).
    operator_id  INTEGER REFERENCES operators(id),
    -- Tenant the token operates within. INTEGER FK to tenants(id); 1 is
    -- the seeded 'default' tenant. Single tenant per token; a user with
    -- access to multiple tenants gets multiple tokens (one per tenant).
    tenant_id    INTEGER NOT NULL DEFAULT 1 REFERENCES tenants(id),
    -- Unix timestamp. NULL = no expiry; operator must revoke explicitly.
    -- Session tokens always set this (default 12h, see operators::SESSION_TTL_S).
    expires_at   INTEGER,
    -- Revoked tokens are never accepted. Logout sets this on the caller's
    -- token; static-token revocation goes through the GraphQL mutation.
    revoked_at   INTEGER,
    -- Updated on each successful auth, throttled in the middleware so we
    -- don't write on every request.
    last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_operator ON api_tokens(operator_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant ON api_tokens(tenant_id);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_kind ON api_tokens(kind);

-- Operator accounts for controller-web. Minimal username + password-hash
-- table; argon2id hashes are produced by the controller and never leave
-- the DB. See docs/login-flow.md for the full flow.
--
-- Bootstrap: `policy-controller-add-operator --username alice` opens the
-- DB directly (same trust model as the mint-token bin — fs access to the
-- DB is already total).
--
-- The login endpoint verifies the password against this table and mints a
-- session-kind api_token; subsequent requests authenticate against that
-- token, not against this table.
CREATE TABLE IF NOT EXISTS operators (
    id             INTEGER PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    -- Full argon2id PHC string (`$argon2id$v=19$m=…$t=…$p=…$<salt>$<hash>`).
    -- Verify with `argon2::PasswordHash::new(&hash)` — params are embedded,
    -- so cost can be tuned over time without a migration.
    password_hash  TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    last_login_at  INTEGER,
    -- Disabled accounts can't log in but old sessions stay valid until
    -- they expire (caller can revoke via GraphQL if needed). NULL = active.
    disabled_at    INTEGER
);

-- ── Event pipeline (docs/event-pipeline.md, build order step 1) ──────────────

CREATE TABLE IF NOT EXISTS tenants (
    id          INTEGER PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    -- Per-tenant event retention. 7 days default.
    retention_s INTEGER NOT NULL DEFAULT 604800,
    created_at  INTEGER NOT NULL
);

-- Bootstrap the singleton tenant. All existing rows in `nodes`, `rules`,
-- `audit_log` carry tenant_id = 'default' (TEXT slug) — this row reifies
-- that string into a numeric ID for tenant-scoped tables.
-- Policy match events are deliberately NOT persisted: they live in a
-- bounded in-memory buffer on the controller (see event_pipeline::store).
INSERT OR IGNORE INTO tenants (slug, name, retention_s, created_at)
VALUES ('default', 'Default Tenant', 604800, strftime('%s', 'now'));

-- Suricata IPS/IDS alerts forwarded from nodes. Separate from `events`
-- (which is BPF-event-shaped): alerts carry signature/category/severity.
-- `raw_json` preserves the full engine SuricataAlert for the UI.
CREATE TABLE IF NOT EXISTS suricata_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    node_id      TEXT NOT NULL,
    -- Alert timestamp string as reported by Suricata (EVE `timestamp`).
    timestamp    TEXT NOT NULL,
    -- Controller receive time (ns since epoch) for stable ordering when two
    -- alerts share an EVE timestamp string.
    received_ns  INTEGER NOT NULL,
    src_ip       TEXT,
    src_port     INTEGER,
    dst_ip       TEXT,
    dst_port     INTEGER,
    proto        TEXT,
    action       TEXT,
    signature_id INTEGER,
    signature    TEXT,
    category     TEXT,
    severity     INTEGER,
    raw_json     TEXT NOT NULL,
    -- Acknowledge time (ns since epoch); NULL = unacknowledged. The UI's
    -- "clear" acknowledges alerts rather than deleting them — deletion is
    -- the retention sweep's job.
    acked_at     INTEGER
);

CREATE INDEX IF NOT EXISTS suricata_alerts_tenant_ts
    ON suricata_alerts(tenant_id, received_ns DESC);
CREATE INDEX IF NOT EXISTS suricata_alerts_node_ts
    ON suricata_alerts(node_id, received_ns DESC);
CREATE INDEX IF NOT EXISTS suricata_alerts_sid
    ON suricata_alerts(tenant_id, signature_id);

-- ----------------------------------------------------------------------
-- Alert pipeline tables (event-pipeline.md step 4).
--
-- Schema is created up-front rather than as a separate migration: the
-- controller's DB is still considered destroyable until 1.0 (see
-- docs/event-pipeline.md "Schema").
-- ----------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS alert_rules (
    id                  INTEGER PRIMARY KEY,
    tenant_id           INTEGER NOT NULL REFERENCES tenants(id),
    name                TEXT NOT NULL,
    enabled             INTEGER NOT NULL DEFAULT 1,
    -- MatchSpec serialised as JSON; compiled at load time by the matcher.
    match_json          TEXT NOT NULL,
    -- JSON array of event field names used for group keying
    -- (e.g. ["rule_id","src_ip"]).
    group_by            TEXT NOT NULL,
    -- NULL = per-event mode (every match fires). Non-NULL pair switches
    -- on the threshold/window mode added in step 5.
    threshold_count     INTEGER,
    threshold_window_s  INTEGER,
    group_wait_s        INTEGER NOT NULL DEFAULT 30,
    group_interval_s    INTEGER NOT NULL DEFAULT 300,
    repeat_interval_s   INTEGER NOT NULL DEFAULT 14400,
    resolve_after_s     INTEGER NOT NULL DEFAULT 1500,
    -- Free-form label carried to receivers (info | warning | critical).
    -- Matcher does not interpret it; see open question 4.
    severity            TEXT NOT NULL,
    -- JSON array of receivers.id values.
    receiver_ids        TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    UNIQUE(tenant_id, name)
);

CREATE TABLE IF NOT EXISTS receivers (
    id          INTEGER PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    name        TEXT NOT NULL,
    -- One of webhook | email | alertmanager (matched by providers/*).
    kind        TEXT NOT NULL,
    -- Provider-specific config. Secret fields are encrypted at rest;
    -- see docs/event-pipeline.md "Secret storage".
    config_json TEXT NOT NULL,
    UNIQUE(tenant_id, name)
);

CREATE TABLE IF NOT EXISTS silences (
    id           INTEGER PRIMARY KEY,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id),
    -- Subset of MatchSpec applied to outbound notifications only.
    matcher_json TEXT NOT NULL,
    starts_at    INTEGER NOT NULL,
    ends_at      INTEGER NOT NULL,
    created_by   TEXT,
    comment      TEXT
);
CREATE INDEX IF NOT EXISTS silences_tenant_active
    ON silences(tenant_id, ends_at);

CREATE TABLE IF NOT EXISTS alert_history (
    id               INTEGER PRIMARY KEY,
    -- No FK on tenant_id: this table grows quickly and the constraint
    -- check buys nothing (tenants are append-only and soft-deleted).
    tenant_id        INTEGER NOT NULL,
    rule_id          INTEGER NOT NULL REFERENCES alert_rules(id),
    -- Stringified group key built from alert_rules.group_by; opaque to
    -- the DB but useful for filtering history.
    group_key        TEXT NOT NULL,
    fired_at         INTEGER NOT NULL,
    resolved_at      INTEGER,
    event_count      INTEGER NOT NULL,
    -- Up to 5 event IDs (JSON array) so the UI can link back to source
    -- rows without storing the full payload.
    sample_event_ids TEXT NOT NULL,
    -- 1 if a silence suppressed the notification at fire time.
    silenced         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alert_history_tenant_fired
    ON alert_history(tenant_id, fired_at DESC);

-- ── RBAC (docs/rbac.md) ──────────────────────────────────────────────────
--
-- Roles are per-tenant. Built-in roles are seeded by `INSERT OR IGNORE`
-- below for tenant_id = 1 ('default'); per-tenant seeding for additional
-- tenants happens in rbac::bootstrap_tenant when a tenant is created.
--
-- Permissions use a 'resource:verb' vocabulary (see rbac::Permission).
-- The wildcard '*:*' is reserved for the built-in `admin` role.
--
-- Effective permissions for a request are the intersection of the token's
-- roles with the issuing operator's roles (when operator_id is set), so
-- disabling an operator drops their active sessions to zero permissions
-- on the next request without explicit revocation.
CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    -- Stable identifier: 'admin', 'operator', 'viewer', 'security-admin',
    -- 'auditor', 'service' for built-ins; operator-chosen for custom roles
    -- (custom roles are schema-supported but gated off in v1).
    name        TEXT NOT NULL,
    description TEXT,
    -- 1 = cannot be renamed or deleted; bindings to it remain editable.
    built_in    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    UNIQUE(tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    -- Examples: 'node:read', 'rule:*', 'event:read-payload', '*:*'.
    -- Verbs are matched literally; the wildcard token is '*'. See
    -- rbac::Permission::matches for the matching rules.
    permission TEXT NOT NULL,
    PRIMARY KEY (role_id, permission)
);

-- An operator can hold multiple roles; effective permissions are the union.
CREATE TABLE IF NOT EXISTS operator_roles (
    operator_id INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    role_id     INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at  INTEGER NOT NULL,
    granted_by  INTEGER REFERENCES operators(id),
    PRIMARY KEY (operator_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_operator_roles_operator ON operator_roles(operator_id);

-- Tokens carry their own role set. For session tokens this is normally a
-- copy of the operator's roles at login time; the intersection rule in
-- the resolver path enforces "can't exceed current operator roles" without
-- requiring re-login when roles are revoked.
--
-- For static tokens (Grafana, CI), this is the *only* source of
-- permissions — there is no operator linkage to intersect against.
CREATE TABLE IF NOT EXISTS api_token_roles (
    token_id INTEGER NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
    role_id  INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_api_token_roles_token ON api_token_roles(token_id);

-- Optional resource-level scoping on a token. Each row narrows the token
-- to a specific node or label; multiple rows union (any-match wins).
-- An empty scope set means the token is unscoped within its roles.
-- Scope enforcement is done inside resolvers (not by the Guard), so the
-- Guard stays purely permission-based and predictable.
CREATE TABLE IF NOT EXISTS api_token_scopes (
    token_id    INTEGER NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
    -- 'node_id' matches nodes.id exactly; 'node_label' matches against the
    -- node's `label` column.
    scope_type  TEXT NOT NULL CHECK (scope_type IN ('node_id', 'node_label')),
    scope_value TEXT NOT NULL,
    PRIMARY KEY (token_id, scope_type, scope_value)
);

-- ── Seed built-in roles for the default tenant ───────────────────────────
--
-- Six built-in roles. Explicit IDs so role_permissions inserts below
-- don't need subqueries; INSERT OR IGNORE keeps re-runs harmless. When a
-- new tenant is created at runtime, rbac::bootstrap_tenant mirrors these
-- rows with auto-assigned IDs.
INSERT OR IGNORE INTO roles (id, tenant_id, name, description, built_in, created_at) VALUES
    (1, 1, 'admin',          'Full access to everything in the tenant.',                                1, strftime('%s','now')),
    (2, 1, 'operator',       'Day-to-day fleet operations: nodes, rules, alerts, enrollment.',          1, strftime('%s','now')),
    (3, 1, 'viewer',         'Read-only access to everything except event payloads.',                   1, strftime('%s','now')),
    (4, 1, 'security-admin', 'Operator plus IAM and token management.',                                 1, strftime('%s','now')),
    (5, 1, 'auditor',        'Read-only, including event payloads, for compliance investigations.',     1, strftime('%s','now')),
    (6, 1, 'service',        'Empty starter role for API tokens; grant additional roles explicitly.',   1, strftime('%s','now'));

-- admin: everything.
INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES
    (1, '*:*');

-- operator: write on operational resources, read elsewhere except event payloads.
INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES
    (2, 'node:read'), (2, 'node:write'), (2, 'node:delete'),
    (2, 'rule:read'), (2, 'rule:write'), (2, 'rule:delete'),
    (2, 'interface:read'), (2, 'interface:write'),
    (2, 'enrollment:read'), (2, 'enrollment:write'), (2, 'enrollment:delete'),
    (2, 'alert:read'), (2, 'alert:write'), (2, 'alert:delete'),
    (2, 'event:read'), (2, 'event:delete'),
    (2, 'audit:read'),
    (2, 'token:read'),
    (2, 'tenant:read');

-- viewer: read-only, NO event payloads (only counts/aggregates).
INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES
    (3, 'node:read'),
    (3, 'rule:read'),
    (3, 'interface:read'),
    (3, 'enrollment:read'),
    (3, 'alert:read'),
    (3, 'event:read'),
    (3, 'audit:read'),
    (3, 'token:read'),
    (3, 'tenant:read');

-- security-admin: operator + IAM/token write.
INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES
    (4, 'node:read'), (4, 'node:write'), (4, 'node:delete'),
    (4, 'rule:read'), (4, 'rule:write'), (4, 'rule:delete'),
    (4, 'interface:read'), (4, 'interface:write'),
    (4, 'enrollment:read'), (4, 'enrollment:write'), (4, 'enrollment:delete'),
    (4, 'alert:read'), (4, 'alert:write'), (4, 'alert:delete'),
    (4, 'event:read'), (4, 'event:delete'),
    (4, 'audit:read'),
    (4, 'token:read'), (4, 'token:write'), (4, 'token:delete'),
    (4, 'iam:read'), (4, 'iam:write'), (4, 'iam:delete'),
    (4, 'tenant:read');

-- auditor: full read, INCLUDING event payloads, for compliance work.
INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES
    (5, 'node:read'),
    (5, 'rule:read'),
    (5, 'interface:read'),
    (5, 'enrollment:read'),
    (5, 'alert:read'),
    (5, 'event:read'), (5, 'event:read-payload'),
    (5, 'audit:read'),
    (5, 'token:read'),
    (5, 'iam:read'),
    (5, 'tenant:read');

-- service: intentionally empty. Tokens get this role plus whatever
-- specific grants the operator chose at mint time.
