"""Shared plumbing for the policy-engine deploy scripts.

Imported by `e2e-deploy.py` (whole-fleet redeploy, controller included) and
`node-deploy.py` (nodes only). Everything here is about *how* to talk to a
machine and what to do on a node; the two scripts differ only in what they
orchestrate around that.

Not a CLI itself.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ── feature -> engine package ────────────────────────────────────────────────
ENGINE_PKG = {
    "vanilla": "policy-engine",
    "ips": "policy-engine-ips",
    "ipfix": "policy-engine-ipfix",
    "ips-ipfix": "policy-engine-ips-ipfix",
}

# Node packages, by the short name the CLIs accept. "engine" is resolved from
# the chosen --feature, the rest are fixed.
NODE_PKGS = {
    "engine": None,
    "client": "policy-engine-client",
    "web": "policy-engine-web",
    "agent": "policy-node-agent",
}

CONTROLLER_PKGS = [
    "policy-controller",
    "policy-controller-client",
    "policy-controller-web",
]

# Where debs (and, when enrolling, the bundle) are staged on each node.
NODE_STAGE = "/tmp/pe-deploy"

# Tag on the /etc/hosts line we manage, so a rerun replaces its own entry
# instead of stacking duplicates. Deliberately unchanged from when this lived
# in e2e-deploy.py: it has to match what earlier runs wrote, or their lines
# would be orphaned rather than replaced.
HOSTS_MARKER = "# policy-engine-e2e"

# Remote cleanup + install script, run on each node via `ssh <t> sudo bash -s`.
# Everything it needs is staged in NODE_STAGE first. The four positional args
# are all optional-by-emptiness so the same script serves an in-place package
# upgrade and a full wipe-and-re-enrol.
NODE_SCRIPT = r"""
set -euo pipefail
STAGE=%(stage)s
CONTROLLER_IP="${1:-}"
CONTROLLER_NAME="${2:-}"
WIPE_STATE="${3:-}"
WIPE_IDENTITY="${4:-}"

# The controller's mgmt server cert validates the bundle URL host against its
# SANs. When that host is a DNS name the node has to resolve it, so pin it in
# /etc/hosts (idempotent, marker-tagged). Skipped when the caller passes an
# empty name — either the bundle URL is already an IP whose iPAddress SAN the
# cert carries, or the operator manages DNS themselves.
if [ -n "$CONTROLLER_NAME" ] && [ -n "$CONTROLLER_IP" ]; then
    echo "  pinning /etc/hosts: $CONTROLLER_IP $CONTROLLER_NAME"
    sed -i '/%(marker)s$/d' /etc/hosts
    echo "$CONTROLLER_IP $CONTROLLER_NAME %(marker)s" >> /etc/hosts
fi

echo "  stopping services"
systemctl stop policy-node-agent.service 2>/dev/null || true
systemctl stop policy-engine.service 2>/dev/null || true

if [ -n "$WIPE_STATE" ]; then
    echo "  wiping engine state + BPF pins"
    rm -f  /var/lib/policy-engine/state.json
    rm -rf /sys/fs/bpf/policy_engine
    rm -rf /run/policy_engine /run/policy-engine
    rm -f  /var/run/policy_engine/.bpf_version 2>/dev/null || true
else
    echo "  keeping engine state + BPF maps"
fi

if [ -n "$WIPE_IDENTITY" ]; then
    # The agent treats "identity key + client cert on disk" as "already
    # enrolled", so clearing these is what forces it back through ZTP. The node
    # comes back with a NEW id; its old controller entry goes stale.
    echo "  removing agent mTLS credentials (forces re-enrolment)"
    rm -f /var/lib/policy-node-agent/identity.key \
          /var/lib/policy-node-agent/controller-client.crt \
          /var/lib/policy-node-agent/controller-client.key \
          /var/lib/policy-node-agent/controller-ca.crt \
          /var/lib/policy-node-agent/endpoints.json \
          /var/lib/policy-node-agent/renewal-counter
    rm -rf /run/policy-node-agent
    rm -f  /etc/policy-node-agent/bootstrap.bundle
else
    echo "  keeping agent identity (no re-enrolment)"
fi

if [ -f "$STAGE/bootstrap.bundle" ]; then
    echo "  installing bootstrap bundle"
    install -d -m 0755 /etc/policy-node-agent
    install -m 0600 "$STAGE/bootstrap.bundle" /etc/policy-node-agent/bootstrap.bundle
fi

echo "  installing packages"
# Any bundle is already in place above, so whatever order apt settles on, the
# node-agent's postinst restart finds it. --reinstall lets a same-version
# rebuild actually replace the on-disk binaries; a variant switch
# (e.g. policy-engine -> policy-engine-ips) is handled via their Conflicts.
apt-get install -y --reinstall "$STAGE"/*.deb

# Restart only units that exist: a node may legitimately have just the agent
# or just the engine installed. `systemctl cat` fails for an unknown unit,
# while a genuine restart failure still aborts the script.
for unit in policy-engine.service policy-node-agent.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
        echo "  restarting $unit"
        systemctl restart "$unit"
    fi
done

echo "  done"
""" % {"stage": NODE_STAGE, "marker": HOSTS_MARKER}


# ── pretty logging ───────────────────────────────────────────────────────────
_TTY = sys.stdout.isatty()


def _c(code: str) -> str:
    return code if _TTY else ""


RESET = _c("\033[0m")
BLUE = _c("\033[1;34m")
GREEN = _c("\033[1;32m")
YELLOW = _c("\033[1;33m")
RED = _c("\033[1;31m")
DIM = _c("\033[2m")


def log(msg: str) -> None:
    print(f"{BLUE}==>{RESET} {msg}")


def ok(msg: str) -> None:
    print(f"{GREEN} ok{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}warn{RESET} {msg}", file=sys.stderr)


def step(msg: str) -> None:
    print(f"\n{DIM}──{RESET} {msg}")


class DeployError(Exception):
    """Fatal error with an operator-facing message."""


# ── command helpers ──────────────────────────────────────────────────────────
class Runner:
    """Runs (or, under --dry-run, prints) shell commands."""

    def __init__(self, dry_run: bool) -> None:
        self.dry_run = dry_run

    def run(
        self,
        argv: list[str],
        *,
        check: bool = True,
        capture: bool = False,
        stdin_text: str | None = None,
        redact: str | None = None,
    ) -> subprocess.CompletedProcess | None:
        """Execute argv. Returns the CompletedProcess, or None under dry-run.

        `redact` is a substring to mask when echoing (e.g. a token).
        """
        shown = " ".join(shlex.quote(a) for a in argv)
        if redact:
            shown = shown.replace(redact, "***")
        if self.dry_run:
            print(f"{DIM}+ {shown}{RESET}")
            if stdin_text:
                print(f"{DIM}  (stdin: {len(stdin_text)} bytes){RESET}")
            return None
        return subprocess.run(
            argv,
            check=check,
            text=True,
            input=stdin_text,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )


# ── where the controller lives ───────────────────────────────────────────────
class ControllerHost:
    """The machine the controller runs on: this one, or a remote box over ssh.

    Every controller-side action (deb install, config write, mint-token,
    add-operator, policy-controller-client calls) goes through here, so the
    local and remote paths stay identical apart from the ssh wrapper.
    """

    STAGE = "/tmp/pe-deploy-ctrl"

    def __init__(self, runner: Runner, ssh_dest: str | None, ssh_opts: list[str]) -> None:
        self.r = runner
        self.ssh_dest = ssh_dest
        self.ssh_opts = ssh_opts

    @property
    def remote(self) -> bool:
        return self.ssh_dest is not None

    @property
    def label(self) -> str:
        return self.ssh_dest if self.ssh_dest else "this machine"

    def _wrap(self, argv: list[str]) -> list[str]:
        """Local argv, or the same argv re-quoted for a remote shell."""
        if not self.remote:
            return argv
        return [
            "ssh",
            *self.ssh_opts,
            self.ssh_dest,
            " ".join(shlex.quote(a) for a in argv),
        ]

    def run(self, argv: list[str], *, sudo: bool = False, **kw):
        return self.r.run(self._wrap(["sudo", *argv] if sudo else list(argv)), **kw)

    def run_script(self, script: str, *, sudo: bool = False, **kw):
        """Run a bash snippet on the controller host.

        The script travels in argv (not stdin) so callers keep stdin free for
        data — e.g. piping a password into add-operator, or a config body into
        a file. sudo passes that stdin straight through.
        """
        argv = ["bash", "-c", script]
        return self.r.run(self._wrap(["sudo", *argv] if sudo else argv), **kw)

    def probe(self, argv: list[str]) -> subprocess.CompletedProcess:
        """Run a read-only query on the controller host, bypassing the Runner
        (so it still answers under --dry-run). Raises on failure."""
        return subprocess.run(self._wrap(argv), check=True, text=True, capture_output=True)

    def put(self, paths: list[Path]) -> list[str]:
        """Make `paths` available on the controller host, returning the paths
        to use there. Local: the originals. Remote: scp'd into STAGE."""
        if not self.remote:
            return [str(p) for p in paths]
        self.r.run(
            ["ssh", *self.ssh_opts, self.ssh_dest,
             f"rm -rf {self.STAGE} && mkdir -p {self.STAGE}"]
        )
        self.r.run(
            ["scp", *self.ssh_opts, *map(str, paths), f"{self.ssh_dest}:{self.STAGE}/"]
        )
        return [f"{self.STAGE}/{p.name}" for p in paths]

    def now_utc(self) -> datetime:
        """The controller's clock, as an aware UTC datetime.

        Used as the enrolment-freshness baseline. Locally our clock *is* the
        controller's; remotely it may be skewed, so ask the far end.
        """
        if not self.remote or self.r.dry_run:
            return datetime.now(timezone.utc)
        proc = self.run(["date", "-u", "+%s"], capture=True, check=False)
        try:
            return datetime.fromtimestamp(int((proc.stdout or "").strip()), timezone.utc)
        except (ValueError, AttributeError):
            warn(f"could not read {self.ssh_dest}'s clock; using local time as baseline")
            return datetime.now(timezone.utc)


# ── deb resolution ───────────────────────────────────────────────────────────
def resolve_deb(deb_dir: Path, pkg: str) -> Path:
    """Newest matching <pkg>_<ver>_<arch>.deb, excluding -dbgsym packages."""
    matches = [
        p
        for p in deb_dir.glob(f"{pkg}_*.deb")
        if "-dbgsym_" not in p.name
    ]
    if not matches:
        raise DeployError(
            f"package '{pkg}' not found in {deb_dir} (build it with 'make deb'?)"
        )
    return max(matches, key=lambda p: p.stat().st_mtime)


def resolve_node_debs(deb_dir: Path, feature: str, which: list[str]) -> list[Path]:
    """Resolve the chosen node packages, `which` being keys of NODE_PKGS."""
    pkgs = [ENGINE_PKG[feature] if w == "engine" else NODE_PKGS[w] for w in which]
    return [resolve_deb(deb_dir, p) for p in pkgs]


# ── node deployment ──────────────────────────────────────────────────────────
@dataclass
class NodePlan:
    """Everything the node-side of a deploy needs, independent of which script
    is driving it."""

    debs: list[Path]
    ssh_opts: list[str] = field(default_factory=list)
    # Bundle to install as /etc/policy-node-agent/bootstrap.bundle. None means
    # don't touch the node's enrolment material at all (an in-place upgrade).
    bundle_path: Path | None = None
    wipe_state: bool = False
    wipe_identity: bool = False
    # (ip, name) to pin in the node's /etc/hosts, or None to leave it alone.
    hosts_pin: tuple[str, str] | None = None
    # Free-text suffix for the per-node log lines, e.g. "feature: ips".
    what: str = ""

    def remote_args(self) -> list[str]:
        ip, name = self.hosts_pin or ("", "")
        return [ip, name, "1" if self.wipe_state else "", "1" if self.wipe_identity else ""]


def _run_step(
    r: Runner,
    emit,
    label: str,
    argv: list[str],
    stdin_text: str | None = None,
) -> None:
    """Run one command for a node, routing its log lines through `emit`.

    Raises CalledProcessError on failure (after emitting the captured output).
    """
    emit("")
    emit(f"{DIM}──{RESET} {label}")
    try:
        proc = r.run(argv, capture=True, check=True, stdin_text=stdin_text)
    except subprocess.CalledProcessError as e:
        emit(f"{RED} !! failed (exit {e.returncode}){RESET}")
        for stream in (e.stdout, e.stderr):
            for ln in (stream or "").rstrip("\n").splitlines():
                emit(f"    {ln}")
        raise
    if proc is not None and (proc.stdout or "").strip():
        for ln in proc.stdout.rstrip("\n").splitlines():
            emit(f"    {ln}")


def deploy_node(r: Runner, plan: NodePlan, target: str, emit) -> None:
    """Stage, clean, and install on a single node. `emit(line)` sinks output."""
    opts = plan.ssh_opts
    remote_cmd = "sudo bash -s " + " ".join(shlex.quote(a) for a in plan.remote_args())
    what = f" ({plan.what})" if plan.what else ""

    _run_step(
        r, emit, f"Node {target}: staging files",
        ["ssh", *opts, target, f"rm -rf {NODE_STAGE} && mkdir -p {NODE_STAGE}"],
    )
    payload = [str(d) for d in plan.debs]
    if plan.bundle_path is not None:
        payload.append(str(plan.bundle_path))
    _run_step(
        r, emit, f"Node {target}: copying packages" + (" + bundle" if plan.bundle_path else ""),
        ["scp", *opts, *payload, f"{target}:{NODE_STAGE}/"],
    )
    if plan.bundle_path is not None:
        # The local bundle is a mkstemp name; the remote script looks for a
        # fixed filename, so rename it once it's across.
        _run_step(
            r, emit, f"Node {target}: staging bundle",
            ["ssh", *opts, target,
             f"mv {NODE_STAGE}/{plan.bundle_path.name} {NODE_STAGE}/bootstrap.bundle"],
        )
    _run_step(
        r, emit, f"Node {target}: cleanup + install{what}",
        ["ssh", *opts, target, remote_cmd],
        stdin_text=NODE_SCRIPT,
    )
    if not r.dry_run:
        emit(f"{GREEN} ok{RESET} node {target} done")


def _run_one_node(r: Runner, plan: NodePlan, target: str) -> tuple[str, bool, list[str]]:
    """Worker for parallel deploys: buffers all output, returns it for the
    caller to print as one contiguous block."""
    lines: list[str] = []
    success = True
    try:
        deploy_node(r, plan, target, lines.append)
    except subprocess.CalledProcessError:
        lines.append(f"{RED}warn{RESET} deployment to {target} FAILED")
        success = False
    return target, success, lines


def deploy_nodes(r: Runner, plan: NodePlan, targets: list[str], jobs: int) -> list[str]:
    """Deploy to every target; returns the ones that failed.

    Under --dry-run or a single node, runs sequentially with live inline output
    (which also keeps dry-run command order sane). Otherwise fans out across
    threads — ssh is I/O-bound — and prints each node's buffered log as one
    block when it finishes.
    """
    failed: list[str] = []
    jobs = jobs if jobs > 0 else len(targets)
    if r.dry_run or jobs == 1 or len(targets) == 1:
        for target in targets:
            try:
                deploy_node(r, plan, target, print)
            except subprocess.CalledProcessError:
                warn(f"deployment to {target} FAILED")
                failed.append(target)
        return failed

    step(f"Deploying {len(targets)} nodes ({jobs} in parallel)")
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(_run_one_node, r, plan, t): t for t in targets}
        for fut in as_completed(futures):
            target, success, lines = fut.result()
            for ln in lines:
                print(ln)
            if not success:
                failed.append(target)
    return failed


# ── controller API helpers ───────────────────────────────────────────────────
def mint_token(host: ControllerHost, prefix: str = "deploy") -> str:
    """Mint an operator API token on the controller (needs sudo there)."""
    step("Controller: minting operator API token")
    token_name = f"{prefix}-{int(time.time())}"
    proc = host.run(
        ["policy-controller-mint-token", "--name", token_name, "--role", "operator"],
        sudo=True,
        capture=True,
    )
    if host.r.dry_run:
        return "DRY_RUN_TOKEN"
    token = (proc.stdout or "").strip()
    if not token:
        raise DeployError("mint-token returned an empty token")
    ok(f"minted token '{token_name}'")
    return token


def create_bundle(
    host: ControllerHost,
    api: str,
    token: str,
    mgmt_url: str,
    bundle_path: Path,
    *,
    ttl: str = "1h",
    max_uses: int = 50,
    label: str | None = None,
) -> None:
    """Mint a ZTP enrollment bundle and write it to `bundle_path` locally.

    The client runs on the controller host; its stdout (the bundle) comes back
    to us over ssh, ready to scp on to each node.
    """
    step(f"Controller: creating enrollment bundle (mgmt url: {mgmt_url})")
    argv = [
        "policy-controller-client",
        "--url", api,
        "--token", token,
        "enroll-token", "create",
        "--controller-url", mgmt_url,
        "--ttl", ttl,
        "--max-uses", str(max_uses),
    ]
    if label:
        argv += ["--label", label]
    argv.append("--bundle-only")
    proc = host.run(argv, capture=True, redact=token)
    if host.r.dry_run:
        return
    bundle = (proc.stdout or "").strip()
    if not bundle:
        raise DeployError("bundle creation produced no output")
    bundle_path.write_text(bundle + "\n")
    ok(f"bundle written ({len(bundle)} bytes)")


def _parse_last_seen(value: str | None) -> datetime | None:
    """Parse an RFC3339 lastSeen string into an aware UTC datetime, or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _fresh_nodes(nodes: list[dict], since: datetime) -> list[dict]:
    """Active nodes whose lastSeen is at or after `since` — i.e. they have
    genuinely checked in during this run, not left over from a previous one."""
    fresh = []
    for n in nodes:
        seen = _parse_last_seen(n.get("lastSeen"))
        if seen is not None and seen >= since:
            fresh.append(n)
    return fresh


def _node_label(n: dict) -> str:
    return n.get("hostname") or n.get("id", "?")[:12]


def verify_checkin(
    host: ControllerHost,
    api: str,
    token: str,
    since: datetime,
    expected: int,
    timeout: int,
) -> None:
    """Poll until `expected` nodes have checked in since `since`, then show the
    node table."""
    base = ["policy-controller-client", "--url", api, "--token", token]
    step(f"Verifying check-in (since {since.isoformat(timespec='seconds')})")
    if host.r.dry_run:
        host.run([*base, "nodes", "list", "--status", "active"], redact=token)
        return

    deadline = time.monotonic() + timeout
    nodes: list[dict] = []
    fresh: list[dict] = []
    while time.monotonic() < deadline:
        proc = host.run(
            [*base, "--json", "nodes", "list", "--status", "active"],
            capture=True,
            check=False,
            redact=token,
        )
        try:
            parsed = json.loads((proc.stdout or "").strip() or "[]")
            nodes = parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, AttributeError):
            nodes = []
        fresh = _fresh_nodes(nodes, since)
        if len(fresh) >= expected:
            break
        time.sleep(2)

    if len(fresh) >= expected:
        ok(f"{len(fresh)} node(s) checked in since start")
    else:
        warn(f"only {len(fresh)}/{expected} node(s) checked in within {timeout}s")
        # Point at the active-but-stale nodes (old last-seen, or "never").
        fresh_ids = {id(n) for n in fresh}
        for n in [n for n in nodes if id(n) not in fresh_ids]:
            warn(f"  stale/not-yet-connected: {_node_label(n)} "
                 f"(lastSeen={n.get('lastSeen') or 'never'})")
    # Show the human-readable table regardless.
    host.run([*base, "nodes", "list", "--status", "active"], check=False, redact=token)
