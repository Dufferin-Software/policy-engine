# Config Confirm & Rollback

Every config mutation pushed from the controller to a node is gated by a
confirmation handshake. The handshake exists to close one specific failure
mode: an operator installs a rule (or attach/detach or FIB change) that
causes the node to lose its controller path. Without a handshake the node
would sit in the broken state forever; with it, the node rolls the change
back automatically and the controller is notified.

This doc covers the wire protocol, the agent- and controller-side state
machines, operator-visible behaviour, and testing notes.

## Scope

Gated operations:

- `createRule`, `deleteRule`, `createRulesMultiNode` (via `DeltaConfigPush`)
- `attachProgram`, `detachProgram`
- `setFibForwarding`
- `setUrpf`

### Agent-side auto-revert coverage

Two distinct guarantees hang off "gated":

1. **Controller-side gating** — the controller reserves a generation, awaits the
   agent's `ConfigConfirm`, and abandons the change if it does not arrive. This
   applies to *all* gated operations above.
2. **Agent-side auto-revert** — the agent captures an inverse op, applies the
   change, and arms a watchdog that rolls the change back locally and emits
   `ConfigConfirm{REVERTED}` if the controller's `CommitAck` is not received in
   time (see `pending_change.rs`). This is what protects against a change that
   severs the agent's *own* control channel.

   **Deadline coordination.** The agent's watchdog deadline is *not* the same as
   the controller's `confirm_deadline_ms`; it is that value plus
   `REVERT_GRACE_MS` (`watchdog_deadline_ms()`). The controller commits as soon
   as `APPLIED` arrives — any time up to its own deadline — and only then sends
   `CommitAck`, which still has to travel back. If the agent used the same
   deadline, a `CommitAck` for a genuinely-committed change could land *after*
   the watchdog already reverted, leaving the controller (committed) and node
   (reverted) in disagreement until the next StateSnapshot reconciles them. The
   grace gives a successful `CommitAck` time to return; if the controller
   instead abandoned the change (dead channel) no `CommitAck` ever comes and the
   watchdog still fires, just `REVERT_GRACE_MS` later.

   Agent-side auto-revert is wired for **all** gated operations:

   | Operation | Inverse captured before apply |
   |---|---|
   | `DeltaConfigPush` | re-add deleted rules / delete added rules; restore prior default actions |
   | `setUrpf` | restore prior uRPF mode (fallback `off`) |
   | `setFibForwarding` | restore prior enable state |
   | `attachProgram` | detach (only if not already attached before the push) |
   | `detachProgram` | re-attach with the prior mode (only if it was attached) |

   `setUrpf` and `attachProgram` matter most: enabling uRPF or attaching a
   default-drop program filters ingress on the interface and can cut the agent
   off from the controller. The uRPF/FIB inverses fall back to the
   connectivity-restoring direction (`off` / disabled) when the prior value
   can't be read.

   The inverse is always registered *before* the agent sends
   `ConfigConfirm{APPLIED}`, so the controller's `CommitAck` (sent only in
   response to APPLIED) can never race ahead of the watchdog being armed —
   including for `attachProgram`, whose apply runs in a background task because
   BPF first-load can take 10–25 s.

Non-gated operations (sent without a `generation_id`):

- Reconciliation pushes issued on reconnect (`build_full_restore_push` — the
  controller is restating already-committed desired state and does not want
  to block on confirmation).
- `pushConfig` operator-initiated full restore (same rationale).

## Wire protocol

Added in protocol version 2:

- `ControllerMessage.config / attach / detach / set_fib` each carry two new
  fields: `generation_id` (ULID) and `confirm_deadline_ms`. An empty
  `generation_id` means "legacy push, not gated".
- `AgentMessage.config_confirm` (`ConfigConfirm`) — agent → controller.
  `{generation_id, outcome, error_message}` where outcome is one of
  `APPLIED`, `REJECTED`, `REVERTED`.
- `ControllerMessage.commit_ack` (`ConfigCommitAck`) — controller → agent.
  `{generation_id, committed, reason}`.

The `PROTOCOL_VERSION` constant in `policy-controller-proto` was bumped to
`2`; older agents report a mismatch at `AgentHello` time and are disconnected.

## Controller state machine

`PendingRegistry` (in `policy-controller/src/pending.rs`) tracks one
in-flight generation per node. It is purely in-memory; nothing is persisted
to SQLite until the agent confirms APPLIED.

1. **Begin.** A mutation calls `try_begin(op, deadline_ms)`. If the node
   already has an in-flight generation the call returns `BeginError::Blocked`
   and the mutation fails with `BLOCKED_PENDING_CONFIRM: …`. Otherwise a new
   `generation_id` is reserved and a `oneshot::Receiver<ConfirmOutcome>` is
   returned.
2. **Push.** The pending op is serialised into the corresponding
   `ControllerMessage` (stamped with `generation_id` and `confirm_deadline_ms`)
   and sent down the node's session.
3. **Await.** The mutation awaits the oneshot receiver. It resolves when the
   registry is told the generation finished.
4. **Confirm.** On `ConfigConfirm` from the agent:
   - `APPLIED` → controller commits the op to SQLite, sends
     `ConfigCommitAck{committed=true}`, and notifies the waiter with
     `ConfirmOutcome::Applied`.
   - `REJECTED` → the waiter is notified with
     `ConfirmOutcome::Rejected(error_message)`; nothing is committed.
   - `REVERTED` → the agent has already rolled back; the waiter is notified
     with `ConfirmOutcome::Reverted(error_message)`.
5. **Expiry.** A watchdog task (`run_watchdog`, tick every 500 ms) reaps any
   generation whose `deadline` has passed and notifies with
   `ConfirmOutcome::Abandoned`. On expiry the node is offline or has stopped
   responding; the operator sees the mutation fail and can retry.

The mutation's return value reflects the real outcome: success only on
`Applied`; every other outcome turns into a user-visible error message.
Every resolution writes an `audit_log` row (`config_applied`,
`config_rejected`, `config_reverted`, `config_abandoned`,
`config_commit_failed`).

## Agent state machine

`PendingChangeRegistry` (in `policy-node-agent/src/pending_change.rs`) is the
mirror image. For each gated push:

1. **Capture inverse.** `ConfigApplier::capture_inverse(push)` queries the
   local policy-engine to snapshot the prior JSON of any rule the push will
   delete and records the cached prior default actions. For rules the push
   adds, the inverse is simply "delete by ID". A full-restore push is not
   reversibly captured (the agent has no way to reconstruct the pre-restore
   world; reconciliation pushes are also not gated, so this case is rare).
2. **Apply.** The push is applied as usual. On failure the agent sends
   `ConfigConfirm{REJECTED, error_message}` and does not register anything
   locally.
3. **Register.** On success the agent registers the `generation_id` →
   `inverse_ops` in the registry and spawns a per-generation watchdog timer
   based on `confirm_deadline_ms` (clamped to 500 ms–60 s).
4. **Confirm APPLIED.** The agent sends `ConfigConfirm{APPLIED}` and waits.
5. **Commit ack.** On `ConfigCommitAck`:
   - `committed=true` → the entry is removed and the watchdog is cancelled.
   - `committed=false` → the inverse ops are applied and
     `ConfigConfirm{REVERTED}` is sent.
6. **Watchdog.** If the timer fires first (CommitAck never arrived — the most
   likely signal of a connectivity break), the inverse ops are applied and
   `ConfigConfirm{REVERTED}` is sent on reconnect. This is the critical
   recovery path: the node self-heals even when the controller can no longer
   reach it.

## Why targeted inverse delta (not full restore)

An earlier sketch wiped all rules and re-applied the prior set as a single
"full restore". We rejected it because the wipe-and-rebuild sequence leaves
a short window during which *previously-blocked* traffic would be allowed.
Targeted inverse — re-adding exactly the rules that were deleted and
deleting exactly the rules that were added — keeps every other rule in place
throughout, so no policy is ever briefly more permissive than before.

## Operator experience

- Mutations block while the agent confirms, typically well under a second.
  The returned `OperationResult.success` reflects the actual outcome.
- If a node is already mid-confirm, a second mutation against it fails fast
  with `BLOCKED_PENDING_CONFIRM` so the operator can retry when the first
  resolves.
- The UI surfaces in-flight generations:
  - Fleet dashboard: amber "⏳ pending" badge next to the node's status.
  - Node detail header: amber "⏳ pending confirm (<op_kind>)" badge.
  Queries: `pendingGenerations` (all) and `pendingGeneration(nodeId)`.
- Audit log entries trace every outcome; `config_reverted` indicates the
  change was self-rolled-back by the agent watchdog.

## Deadlines

- Controller-side default: `DEFAULT_CONFIRM_DEADLINE_MS = 5_000` ms. Mutations
  can override per-call if needed.
- Agent-side watchdog: same `confirm_deadline_ms` the controller stamped,
  clamped to `[500, 60_000]` ms. The agent deliberately does not trust
  arbitrarily long or zero values.
- If both timers fire around the same instant the protocol still converges:
  the controller reaps as Abandoned and emits no CommitAck; the agent
  watchdog reverts and sends REVERTED; the receiver has already resolved so
  the REVERTED message is logged and dropped.

## Tests

- Controller-side: `policy-controller/src/pending.rs` (unit tests for
  begin/commit/reap) and the `#[Object]` mutation tests in
  `policy-controller/src/graphql/schema.rs` (an in-test fake agent auto-
  confirms APPLIED and drives the happy path).
- Agent-side: `policy-node-agent/src/pending_change.rs` (watchdog fires a
  REVERTED confirm on timeout; commit removes the entry).
- Integration: `netsim/tests/multi_node/test_config_rollback.py` installs a
  rule that black-holes controller-bound traffic and verifies the node rolls
  it back when the handshake cannot complete, then reconnects to the
  controller cleanly.
