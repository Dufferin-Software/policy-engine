#!/usr/bin/env python3
"""End-to-end redeploy of policy-engine onto a fleet.

Does the tedious loop by hand so you don't have to:

  Controller (this machine, "dev node"):
    stop controller -> wipe DB -> install controller + web + client debs ->
    wait for it to come up -> mint an operator API token -> mint a ZTP
    enrollment bundle.

  Each target node (over ssh):
    stop agent + engine -> remove engine state + BPF pins + agent mTLS creds
    -> copy the bundle to /etc/policy-node-agent/bootstrap.bundle -> install
    the engine (feature variant) + client + web + node-agent debs -> the
    agent re-enrols against the fresh controller on restart.

Packages are taken as-is from a directory of prebuilt .deb files (default ../
relative to the repo). Build them yourself first with `make deb` /
`make deb FEATURES=...` when you want fresh binaries.

Usage:
    scripts/e2e-deploy.py --feature ips node-a node-b root@10.0.0.5

Run with --help for all options.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ── feature -> engine package ────────────────────────────────────────────────
ENGINE_PKG = {
    "vanilla": "policy-engine",
    "ips": "policy-engine-ips",
    "ipfix": "policy-engine-ipfix",
    "ips-ipfix": "policy-engine-ips-ipfix",
}

CONTROLLER_PKGS = [
    "policy-controller",
    "policy-controller-client",
    "policy-controller-web",
]

# Node packages besides the engine variant (added in resolve order below).
NODE_EXTRA_PKGS = [
    "policy-engine-client",
    "policy-engine-web",
    "policy-node-agent",
]

# Remote cleanup + install script, run on each node via `ssh <t> sudo bash -s`.
# The bundle and all debs are dropped in /tmp/pe-e2e first.
REMOTE_SCRIPT = r"""
set -euo pipefail
STAGE=/tmp/pe-e2e
CONTROLLER_IP="${1:-}"
CONTROLLER_NAME="${2:-}"
WIPE_STATE="${3:-}"

# The controller's mgmt/enrollment server cert has a fixed DNS SAN
# (policy-controller). mTLS validates the URL host against that SAN, so the
# bundle must reach the controller by that NAME, not an IP. Pin it in
# /etc/hosts (idempotent, marker-tagged) so name resolution points at the
# controller. Skipped when the caller passes an empty name (--no-hosts).
if [ -n "$CONTROLLER_NAME" ] && [ -n "$CONTROLLER_IP" ]; then
    echo "  pinning /etc/hosts: $CONTROLLER_IP $CONTROLLER_NAME"
    sed -i '/# policy-engine-e2e$/d' /etc/hosts
    echo "$CONTROLLER_IP $CONTROLLER_NAME # policy-engine-e2e" >> /etc/hosts
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
    echo "  keeping engine state + BPF maps (pass --wipe-state to clear)"
fi

echo "  removing agent mTLS credentials (forces re-enrolment)"
rm -f /var/lib/policy-node-agent/identity.key \
      /var/lib/policy-node-agent/controller-client.crt \
      /var/lib/policy-node-agent/controller-client.key \
      /var/lib/policy-node-agent/controller-ca.crt \
      /var/lib/policy-node-agent/endpoints.json \
      /var/lib/policy-node-agent/renewal-counter
rm -rf /run/policy-node-agent
rm -f  /etc/policy-node-agent/bootstrap.bundle

echo "  installing bootstrap bundle"
install -d -m 0755 /etc/policy-node-agent
install -m 0600 "$STAGE/bootstrap.bundle" /etc/policy-node-agent/bootstrap.bundle

echo "  installing packages"
# The bundle is already in place above, so whatever order apt settles on,
# the node-agent's postinst restart finds it. --reinstall lets a same-version
# rebuild actually replace the on-disk binaries; a variant switch
# (e.g. policy-engine -> policy-engine-ips) is handled via their Conflicts.
apt-get install -y --reinstall "$STAGE"/*.deb

echo "  restarting engine + agent"
systemctl restart policy-engine.service
systemctl restart policy-node-agent.service

echo "  done"
"""


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
                print(f"{DIM}  (stdin: <remote-script>){RESET}")
            return None
        return subprocess.run(
            argv,
            check=check,
            text=True,
            input=stdin_text,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )


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


# ── controller-host autodetection ────────────────────────────────────────────
def autodetect_host() -> str:
    """Primary outbound IPv4 address of this machine."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.split()
        if "src" in out:
            return out[out.index("src") + 1]
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["hostname", "-I"], check=True, text=True, capture_output=True
        ).stdout.split()
        if out:
            return out[0]
    except Exception:
        pass
    raise DeployError(
        "could not autodetect controller host; pass --controller-host <addr>"
    )


def wait_for_controller(api: str, dry_run: bool, timeout: int = 60) -> None:
    if dry_run:
        print(f"{DIM}+ wait for {api}/health{RESET}")
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for path in ("/health", "/"):
            try:
                with urllib.request.urlopen(api + path, timeout=2):
                    ok("controller is up")
                    return
            except urllib.error.HTTPError:
                # Any HTTP response means the server is listening.
                ok("controller is up")
                return
            except Exception:
                pass
        time.sleep(1)
    raise DeployError(
        "controller did not come up within "
        f"{timeout}s (check: journalctl -u policy-controller)"
    )


# ── phases ───────────────────────────────────────────────────────────────────
def controller_phase(args: argparse.Namespace, r: Runner, ctrl_debs: list[Path]) -> None:
    if not args.skip_controller:
        step("Controller: stop + wipe DB + install")
        r.run(["sudo", "systemctl", "stop", "policy-controller.service"], check=False)
        r.run(
            [
                "sudo", "rm", "-f",
                "/var/lib/policy-controller/controller.db",
                "/var/lib/policy-controller/controller.db-wal",
                "/var/lib/policy-controller/controller.db-shm",
            ]
        )
        if args.wipe_ca:
            warn("wiping controller CA (ca.key/ca.crt)")
            r.run(
                [
                    "sudo", "rm", "-f",
                    "/var/lib/policy-controller/ca.key",
                    "/var/lib/policy-controller/ca.crt",
                ]
            )
        r.run(["sudo", "apt-get", "install", "-y", "--reinstall", *map(str, ctrl_debs)])
        r.run(["sudo", "systemctl", "restart", "policy-controller.service"])
    else:
        step("Controller: skipped (reusing running controller)")

    step(f"Controller: waiting for HTTP API at {args.controller_api}")
    wait_for_controller(args.controller_api, r.dry_run)


def mint_token(args: argparse.Namespace, r: Runner) -> str:
    step("Controller: minting operator API token")
    token_name = f"e2e-{int(time.time())}"
    argv = ["sudo", "policy-controller-mint-token", "--name", token_name, "--role", "operator"]
    proc = r.run(argv, capture=True)
    if r.dry_run:
        return "DRY_RUN_TOKEN"
    token = (proc.stdout or "").strip()
    if not token:
        raise DeployError("mint-token returned an empty token")
    ok(f"minted token '{token_name}'")
    return token


def add_operator(args: argparse.Namespace, r: Runner) -> None:
    """Create a controller-web operator account (argon2id-hashed password)."""
    if args.no_operator:
        return
    step(f"Controller: creating operator '{args.operator_user}' (role admin)")
    if r.dry_run:
        r.run(
            [
                "sudo", "policy-controller-add-operator",
                "--username", args.operator_user,
                "--password-file", "<tmp>",
                "--role", "admin",
            ]
        )
        return
    # add-operator has no --password flag; it reads a file (or prompts a TTY).
    fd, pw_path = tempfile.mkstemp(prefix="pe-e2e-pw.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(args.operator_password + "\n")
        os.chmod(pw_path, 0o600)
        proc = r.run(
            [
                "sudo", "policy-controller-add-operator",
                "--username", args.operator_user,
                "--password-file", pw_path,
                "--role", "admin",
            ],
            check=False,
            capture=True,
        )
    finally:
        Path(pw_path).unlink(missing_ok=True)
    if proc is not None and proc.returncode != 0:
        warn(
            f"could not create operator '{args.operator_user}' "
            "(already exists?) — continuing"
        )
        if proc.stderr:
            warn(proc.stderr.strip())
    else:
        ok(f"operator '{args.operator_user}' created (password: {args.operator_password})")


def create_bundle(
    args: argparse.Namespace, r: Runner, token: str, bundle_path: Path
) -> None:
    mgmt_url = f"https://{args.controller_name}:7777"
    step(f"Controller: creating enrollment bundle (mgmt url: {mgmt_url})")
    argv = [
        "policy-controller-client",
        "--url", args.controller_api,
        "--token", token,
        "enroll-token", "create",
        "--controller-url", mgmt_url,
        "--ttl", args.ttl,
        "--max-uses", str(args.max_uses),
        "--label", args.label,
        "--bundle-only",
    ]
    proc = r.run(argv, capture=True, redact=token)
    if r.dry_run:
        return
    bundle = (proc.stdout or "").strip()
    if not bundle:
        raise DeployError("bundle creation produced no output")
    bundle_path.write_text(bundle + "\n")
    ok(f"bundle written ({len(bundle)} bytes)")


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


def deploy_node(
    args: argparse.Namespace,
    r: Runner,
    target: str,
    node_debs: list[Path],
    bundle_path: Path,
    emit,
) -> None:
    """Stage, clean, and install on a single node. `emit(line)` sinks output."""
    ssh_opts = shlex.split(args.ssh_opts)
    staged = bundle_path.name
    # Pass controller IP + name + wipe-flag as positional args to the remote
    # script. An empty name disables the hosts edit (--no-hosts); an empty
    # wipe-flag preserves engine state + BPF maps (the default).
    hosts_name = "" if args.no_hosts else args.controller_name
    wipe_state = "1" if args.wipe_state else ""
    remote_cmd = (
        f"sudo bash -s {shlex.quote(args.controller_host)} "
        f"{shlex.quote(hosts_name)} {shlex.quote(wipe_state)}"
    )

    _run_step(
        r, emit, f"Node {target}: staging files",
        ["ssh", *ssh_opts, target, "rm -rf /tmp/pe-e2e && mkdir -p /tmp/pe-e2e"],
    )
    _run_step(
        r, emit, f"Node {target}: copying packages + bundle",
        ["scp", *ssh_opts, *map(str, node_debs), str(bundle_path), f"{target}:/tmp/pe-e2e/"],
    )
    _run_step(
        r, emit, f"Node {target}: staging bundle",
        ["ssh", *ssh_opts, target, f"mv /tmp/pe-e2e/{staged} /tmp/pe-e2e/bootstrap.bundle"],
    )
    _run_step(
        r, emit, f"Node {target}: cleanup + install (feature: {args.feature})",
        ["ssh", *ssh_opts, target, remote_cmd],
        stdin_text=REMOTE_SCRIPT,
    )
    if not r.dry_run:
        emit(f"{GREEN} ok{RESET} node {target} redeployed")


def run_one_node(
    args: argparse.Namespace,
    r: Runner,
    target: str,
    node_debs: list[Path],
    bundle_path: Path,
) -> tuple[str, bool, list[str]]:
    """Worker for parallel deploys: buffers all output, returns it for the
    caller to print as one contiguous block."""
    lines: list[str] = []
    success = True
    try:
        deploy_node(args, r, target, node_debs, bundle_path, lines.append)
    except subprocess.CalledProcessError:
        lines.append(f"{RED}warn{RESET} deployment to {target} FAILED")
        success = False
    return target, success, lines


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


def verify_enrolment(
    args: argparse.Namespace, r: Runner, token: str, since: datetime
) -> None:
    """Poll until every deployed node has checked in since `since`, then show
    the node table."""
    if args.no_verify:
        return
    base = ["policy-controller-client", "--url", args.controller_api, "--token", token]
    step(f"Verifying enrolment (checked in since {since.isoformat(timespec='seconds')})")
    if r.dry_run:
        r.run([*base, "nodes", "list", "--status", "active"], redact=token)
        return

    expected = len(args.nodes)
    deadline = time.monotonic() + args.verify_timeout
    nodes: list[dict] = []
    fresh: list[dict] = []
    while time.monotonic() < deadline:
        proc = r.run(
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
        warn(
            f"only {len(fresh)}/{expected} node(s) checked in within "
            f"{args.verify_timeout}s"
        )
        # Point at the active-but-stale nodes (old last-seen, or "never").
        fresh_ids = {id(n) for n in fresh}
        stale = [n for n in nodes if id(n) not in fresh_ids]
        for n in stale:
            warn(f"  stale/not-yet-connected: {_node_label(n)} "
                 f"(lastSeen={n.get('lastSeen') or 'never'})")
    # Show the human-readable table regardless.
    r.run([*base, "nodes", "list", "--status", "active"], check=False, redact=token)


# ── argument parsing ─────────────────────────────────────────────────────────
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="e2e-deploy.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--feature",
        choices=sorted(ENGINE_PKG),
        default="vanilla",
        help="engine variant (default: vanilla)",
    )
    p.add_argument(
        "--deb-dir",
        type=Path,
        default=None,
        help="directory holding the prebuilt .deb files (default: the repo's parent)",
    )
    p.add_argument(
        "--controller-host",
        default=None,
        help="IP the NODES route to for this controller. Pinned in each node's "
        "/etc/hosts as <controller-name>. Default: this machine's primary IP.",
    )
    p.add_argument(
        "--controller-name",
        default="policy-controller",
        help="DNS name embedded in the bundle URLs; must match the controller's "
        "server-cert SAN (default: policy-controller)",
    )
    p.add_argument(
        "--no-hosts",
        action="store_true",
        help="don't touch /etc/hosts on the nodes (you manage DNS for "
        "--controller-name yourself)",
    )
    p.add_argument(
        "--controller-api",
        default="http://127.0.0.1:8443",
        help="base URL of the local controller HTTP API (default: %(default)s)",
    )
    p.add_argument("--ttl", default="1h", help="enrollment-token TTL (default: %(default)s)")
    p.add_argument(
        "--max-uses", type=int, default=50, help="max bundle redemptions (default: %(default)s)"
    )
    p.add_argument("--label", default="e2e", help="fleet label (default: %(default)s)")
    p.add_argument(
        "--ssh-opts",
        default="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        help="extra options passed to ssh/scp",
    )
    p.add_argument(
        "--skip-controller",
        action="store_true",
        help="don't reinstall/wipe the controller; just mint a fresh token + bundle",
    )
    p.add_argument(
        "--wipe-ca",
        action="store_true",
        help="also delete the controller CA (ca.key/ca.crt) when wiping",
    )
    p.add_argument(
        "--wipe-state",
        action="store_true",
        help="wipe engine state (state.json) + BPF pins on the target nodes. "
        "Default: preserve them (rules/attachments restore from state.json).",
    )
    p.add_argument(
        "--operator-user",
        default=os.environ.get("USER") or getpass.getuser(),
        help="controller-web operator account to create (default: $USER)",
    )
    p.add_argument(
        "--operator-password",
        default="password",
        help="password for the operator account (default: 'password')",
    )
    p.add_argument(
        "--no-operator",
        action="store_true",
        help="don't create a controller-web operator account",
    )
    p.add_argument(
        "--no-verify",
        action="store_true",
        help="don't poll for node enrolment after deploying",
    )
    p.add_argument(
        "--verify-timeout",
        type=int,
        default=60,
        help="seconds to wait for nodes to reach Active (default: %(default)s)",
    )
    p.add_argument(
        "--keep-bundle",
        action="store_true",
        help="leave the generated bundle file on disk and print its path",
    )
    p.add_argument(
        "-j", "--jobs",
        type=int,
        default=0,
        help="max nodes to deploy in parallel (0 = all at once; 1 = sequential). "
        "Default: 0",
    )
    p.add_argument(
        "--dry-run", action="store_true", help="print every command instead of running it"
    )
    p.add_argument("nodes", nargs="+", help="ssh destinations of the nodes to (re)deploy")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    r = Runner(args.dry_run)
    # Baseline for the enrolment check: a node counts as freshly enrolled only
    # if its lastSeen is at or after this instant. The controller runs on this
    # same host, so its clock and ours agree (no skew to compensate for).
    started = datetime.now(timezone.utc)

    repo_root = Path(__file__).resolve().parent.parent
    deb_dir = (args.deb_dir or repo_root.parent).resolve()
    if not deb_dir.is_dir():
        raise DeployError(f"deb dir not found: {deb_dir}")

    engine_pkg = ENGINE_PKG[args.feature]

    step(f"Resolving packages in {deb_dir} (feature: {args.feature})")
    ctrl_debs = [resolve_deb(deb_dir, pkg) for pkg in CONTROLLER_PKGS]
    node_debs = [resolve_deb(deb_dir, pkg) for pkg in [engine_pkg, *NODE_EXTRA_PKGS]]
    for d in [*ctrl_debs, *node_debs]:
        print(f"   {d.name}")

    if not args.controller_host:
        args.controller_host = autodetect_host()
        warn(
            f"autodetected controller host: {args.controller_host} "
            "(override with --controller-host)"
        )

    fd, bundle_name = tempfile.mkstemp(prefix="pe-e2e-bundle.", suffix=".b64", dir="/tmp")
    os.close(fd)
    bundle_path = Path(bundle_name)

    failed: list[str] = []
    token = "<tok>"
    try:
        controller_phase(args, r, ctrl_debs)
        token = mint_token(args, r)
        add_operator(args, r)
        create_bundle(args, r, token, bundle_path)

        # Under --dry-run or a single node, run sequentially with live inline
        # output. Otherwise fan out across threads (SSH is I/O-bound) and print
        # each node's buffered log as one block when it finishes.
        jobs = args.jobs if args.jobs > 0 else len(args.nodes)
        if r.dry_run or jobs == 1 or len(args.nodes) == 1:
            # Sequential: emit live inline (also keeps dry-run command order sane).
            for target in args.nodes:
                try:
                    deploy_node(args, r, target, node_debs, bundle_path, print)
                except subprocess.CalledProcessError:
                    warn(f"deployment to {target} FAILED")
                    failed.append(target)
        else:
            step(f"Deploying {len(args.nodes)} nodes ({jobs} in parallel)")
            with ThreadPoolExecutor(max_workers=jobs) as pool:
                futures = {
                    pool.submit(run_one_node, args, r, t, node_debs, bundle_path): t
                    for t in args.nodes
                }
                for fut in as_completed(futures):
                    target, success, lines = fut.result()
                    for ln in lines:
                        print(ln)
                    if not success:
                        failed.append(target)

        verify_enrolment(args, r, token, started)
    finally:
        if args.keep_bundle:
            if bundle_path.exists() and bundle_path.stat().st_size:
                log(f"bundle kept at {bundle_path}")
        else:
            bundle_path.unlink(missing_ok=True)

    # ── summary ──────────────────────────────────────────────────────────────
    step("Summary")
    print(f"  feature:        {args.feature} ({engine_pkg})")
    print(f"  controller ui:  {args.controller_api}")
    print(f"  bundle mgmt url:https://{args.controller_name}:7777  (embedded for nodes)")
    if not args.no_hosts:
        print(f"  node hosts pin: {args.controller_host} {args.controller_name}")
    print(f"  engine state:   {'WIPED' if args.wipe_state else 'preserved'}")
    print(f"  nodes:          {' '.join(args.nodes)}")
    if not args.no_operator:
        print(f"  operator login: {args.operator_user} / {args.operator_password}")
    print(f"  api token:      {token}")
    print(
        f"{DIM}  rerun a client command with:\n"
        f"    export POLICY_CONTROLLER_TOKEN={token}\n"
        f"    policy-controller-client --url {args.controller_api} nodes list --status active{RESET}"
    )
    if failed:
        print(f"{RED}  failed:         {' '.join(failed)}{RESET}")
        return 1

    ok(f"all {len(args.nodes)} node(s) redeployed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except DeployError as exc:
        print(f"{RED}error{RESET} {exc}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"{RED}error{RESET} command failed: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
