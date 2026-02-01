# CA Rotation Design

This document describes how to rotate the controller CA without breaking an in-production fleet. It is the long form of the *CA Rotation* paragraph in [enrollment-crypto.md](enrollment-crypto.md) Phase 7.

> **Status:** design only. No code in tree implements this yet. CA rotation is expected to be a once-every-few-years operation, so we want the design pinned down before it is needed under pressure.

---

## Why rotate

The CA is currently valid until 2035-01-01 (set in Phase 0). Reasons we might rotate before then:

- Suspected key compromise (incident-driven, fast).
- Cryptographic-agility move (e.g., to a PQ-hybrid signing scheme), planned.
- Move the CA key into hardware (HSM/TPM), planned.
- Tenant split — one CA becomes two, planned.

The incident-driven case is rare but the design has to cover it; the planned cases dominate normal operation and must not require any fleet-wide downtime.

## Invariants the rotation must preserve

1. **No node is locked out** at any point in the rotation, assuming it can reach the controller at least once during the trust window.
2. **No operator-distributed bundle** ("re-bootstrap every node") is required for the planned case. Incident response is allowed to require it.
3. **mTLS in both directions** keeps working throughout — agents authenticating to controller *and* controller authenticating to agents.
4. **Revocation continues to work** — revoking a cert signed by the outgoing CA must still be enforceable.

## Actors and new state

The controller gains two CA slots:

| Slot | Role | Lifetime |
|---|---|---|
| `ca_current` | Active issuer. Signs all new node certs and the server cert. | Until cutover. |
| `ca_next` | Standby. Distributed to agents during the trust window. Becomes `ca_current` at cutover. | From distribution start to cutover. After cutover the old CA moves to a third *retired* slot until its last-issued cert expires. |
| `ca_retired` | Trust-only. Not used to sign anything, but stays in both server and client trust stores until the last cert it issued has expired. | `node_cert_ttl_days` past cutover. |

On the agent, `controller-ca.crt` becomes a *bundle* of one or two PEM-encoded certs. rustls already accepts multiple roots in a single PEM file, so no parser changes are needed agent-side.

## Phase-by-phase rotation

### CA-1: Generate `ca_next`

Operator runs `policy-controllerctl ca rotate prepare`. The controller:

1. Generates a fresh ECDSA P-384 keypair (same algorithm as `ca_current`; agility moves are a separate change).
2. Self-signs `ca_next.crt` with validity extending past `cutover_at + node_cert_ttl_days + safety_margin`.
3. Persists `ca_next.{key,crt}` alongside `ca.{key,crt}`.
4. Begins announcing `ca_next` to connected agents (see CA-2).

The controller's server cert chain is **not** updated yet — clients still see only `ca_current` on the wire. Only the trust *distribution* starts.

### CA-2: Distribute `ca_next` to agents

A new control message `TrustAnchorUpdate { ca_pem_bundle, generation }` flows over the existing management stream. On receipt the agent:

1. Verifies the message arrived on a session whose peer cert chains to `ca_current` (i.e., the controller is the one we already trust to tell us this). This is intrinsic to mTLS, so it requires no extra check beyond receiving the message on the authenticated stream.
2. Parses every PEM block in `ca_pem_bundle` and confirms each is a valid self-signed cert.
3. Atomically rewrites `controller-ca.crt` to the new bundle (stage → fsync → rename).
4. Replies with `TrustAnchorAck { generation, fingerprints[] }` so the controller can track which agents have absorbed the new trust anchor.

Agents that are offline during distribution catch up when they reconnect; the controller re-sends `TrustAnchorUpdate` after every `AgentHello` until acked.

### CA-3: Wait for distribution to complete

The operator monitors `fleet_nodes_pending_trust_anchor` (count of Active nodes whose latest ack is below `generation`). Cutover is gated on this hitting zero, or on operator override after manual triage of long-offline nodes.

Recommended minimum dwell time before cutover: 14 days. This is to surface any agents that only check in via a slow schedule (overnight maintenance windows, etc.).

### CA-4: Cutover

`policy-controllerctl ca rotate cutover` flips two atomic state changes in a single transaction:

1. `ca_current ↔ ca_next` swap. The outgoing CA's key+cert move into the `ca_retired` slot. The retired key is kept *only* so revocation entries created under it can be matched by serial — it is never used to sign new material. (Optional hardening: zeroize and discard the retired *key* immediately, keeping only the retired *cert* for trust-store purposes. Serial-based revocation does not require the private key.)
2. New server cert is issued from the now-current CA and swapped into the live `ResolvesServerCert` (`security/server_cert.rs::ReloadableServerCert::replace`) for both the enrollment and management listeners. No listener restart is required. Existing mTLS connections are not torn down — they continue under the previous handshake. The next handshake (reconnect, renewal, or scheduled controller restart) uses the new chain.

Outside of CA rotation the same resolver is kept fresh by a background task that re-issues each server cert at 2/3 of its lifetime (`security/server_cert.rs::spawn_renewal`). Operators should not expect the controller's server cert to ride along with `node_cert_ttl_secs` until the next process restart — it is renewed in-process on the same cadence the agent uses for its client cert.

From this moment all new `issue_node_cert` and `RenewClientCert` calls sign under the new CA.

### CA-5: Drain

For the next `node_cert_ttl_days` (default 90d), both CAs remain trust anchors on agents (because step CA-2 distributed both) and on the controller's `ClientCertVerifier` (which loads both `ca_current` and `ca_retired`). The renewal loop from Phase 7 naturally migrates every node onto a cert signed by the new CA before its old cert expires.

The drain ends when:
- The controller observes that no Active node still has a cert signed by `ca_retired`, **and**
- The retired CA cert is past its `not_after`.

At that point the controller removes `ca_retired` from its trust set and emits a `TrustAnchorUpdate` with only the new CA, prompting agents to drop the retired anchor from their bundle.

### CA-6: New bootstrap bundles

Any ZTP bundle minted between CA-1 and CA-4 pins both fingerprints (the `ServerCertVerifier` already accepts a match against any pinned hash in the chain — extending it to a *set* of pinned hashes is a small change). Bundles minted after CA-4 pin only the new CA.

## Failure handling

| Failure | Effect | Recovery |
|---|---|---|
| Agent never acks `TrustAnchorUpdate` (offline) | Cannot complete CA-3 until it reconnects. | Operator triages the node and either waits, manually pushes the new CA via config-management, or decommissions the node. |
| Agent acks but cert renewal RPC under the new CA fails during CA-5 | Agent's old cert still valid; will retry. | Renewal loop's existing retry/backoff handles it. |
| Controller crash mid-cutover (CA-4) | State change is a single SQLite transaction over the `controller_state` row that names the active CA slot, so it is atomic. | Restart resumes whichever side of the transaction committed. |
| Compromise of `ca_current` mid-drain | Cannot wait for the natural drain. | Operator runs `ca rotate emergency`, which immediately moves the compromised CA out of the active trust set, revokes every cert it signed, and forces all nodes to re-enroll using a freshly minted bundle. This is the only path that requires operator-driven re-bootstrap. |

## Out of scope

- **HSM-backed CA keys.** Orthogonal change — the rotation flow above works whether keys are in files or in an HSM, as long as the controller can produce signatures.
- **Cross-signing the new CA with the old.** Considered and rejected: it shortens the trust window but complicates the X.509 chain handling on the agent. Distribution-then-cutover is simpler and the only thing it costs is the dwell time in CA-3.
- **Per-tenant CAs.** A future enhancement layered on top of this design.
