#!/usr/bin/env python3
"""End-to-end redeploy of policy-engine onto a fleet.

Does the tedious loop by hand so you don't have to:

  Controller (this machine by default, or --controller-ssh <dest>):
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
    # controller on this dev machine
    scripts/e2e-deploy.py --feature ips node-a node-b root@10.0.0.5

    # controller on a separate box (debs are shipped there over ssh)
    scripts/e2e-deploy.py --controller-ssh root@10.0.0.2 --by-ip node-a node-b

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
import urllib.parse
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

# Only used in DNS/hosts mode; --by-ip deliberately has no name default. Must
# match the controller's own `default_server_san()` so an unconfigured
# controller's cert validates against the name we pin in the nodes' /etc/hosts.
DEFAULT_CONTROLLER_NAME = "policy-controller"

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

# The controller's mgmt server cert validates the bundle URL host against its
# SANs. In name mode the cert's DNS SAN is a name (e.g. policy-controller), so
# nodes must reach the controller by that NAME: pin it in /etc/hosts
# (idempotent, marker-tagged). Skipped when the caller passes an empty name
# (--no-hosts / --by-ip, where the bundle URL is the controller IP and the
# cert carries a matching iPAddress SAN, so no name resolution is needed).
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

    STAGE = "/tmp/pe-e2e-ctrl"

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


# ── controller-host autodetection ────────────────────────────────────────────
def autodetect_host(host: ControllerHost) -> str:
    """Primary outbound IPv4 address of the controller machine — the address
    the nodes will be pointed at."""
    if host.remote and host.r.dry_run:
        return "<controller-ip>"
    for argv in (["ip", "-4", "route", "get", "1.1.1.1"], ["hostname", "-I"]):
        try:
            proc = host.probe(argv)
        except Exception:
            continue
        out = proc.stdout.split()
        if argv[0] == "ip" and "src" in out:
            return out[out.index("src") + 1]
        if argv[0] == "hostname" and out:
            return out[0]
    raise DeployError(
        "could not autodetect controller host; pass --controller-host <addr>"
    )


# Probes the controller's HTTP listener from the controller host itself, so
# this works regardless of what a firewall lets through to the dev machine.
# A bound socket is the same readiness signal the local urllib check uses.
_PROBE_SCRIPT = r"""
for _ in $(seq 1 %(timeout)d); do
    if (exec 3<>/dev/tcp/%(host)s/%(port)d) 2>/dev/null; then exit 0; fi
    sleep 1
done
exit 1
"""


def wait_for_controller(api: str, host: ControllerHost, timeout: int = 60) -> None:
    if host.r.dry_run:
        print(f"{DIM}+ wait for {api}/health on {host.label}{RESET}")
        return

    if host.remote:
        parsed = urllib.parse.urlsplit(api)
        script = _PROBE_SCRIPT % {
            "timeout": timeout,
            "host": parsed.hostname or "127.0.0.1",
            "port": parsed.port or 8443,
        }
        proc = host.run_script(script, check=False, capture=True)
        if proc.returncode == 0:
            ok("controller is up")
            return
    else:
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
        f"{timeout}s (check: journalctl -u policy-controller on {host.label})"
    )


# ── phases ───────────────────────────────────────────────────────────────────
def bundle_host(args: argparse.Namespace) -> str:
    """Host embedded in the bundle's controller/enrollment URLs. In --by-ip
    mode that's the controller's IP (now a cert SAN); otherwise the DNS name
    that nodes resolve via /etc/hosts."""
    return args.controller_host if args.by_ip else args.controller_name


def controller_sans(args: argparse.Namespace) -> list[str]:
    """Server-cert SANs for the controller, primary entry first.

    The primary is special twice over: it becomes the cert CN, and the
    controller uses `server_san` as the host of the enrollment URLs its web UI
    pre-fills — so it must be whatever the nodes actually dial.

      --by-ip:  the IP leads (a legal primary SAN — it's encoded as an
                iPAddress GeneralName), and a name only appears if one was
                asked for explicitly.
      otherwise: the DNS name leads, with the IP carried as an extra SAN so a
                node that connects by address still validates.
    """
    sans = (
        [args.controller_host, args.controller_name]
        if args.by_ip
        else [args.controller_name, args.controller_host]
    )
    out: list[str] = []
    for s in sans:
        if s and s not in out:
            out.append(s)
    return out


# ControllerConfig is a flat table (no `[section]`s), so dropping the two SAN
# keys and appending replacements is a safe edit that leaves any other operator
# settings — web_root, node_cert_ttl_secs, bind addresses — untouched. Only
# single-line `extra_server_sans = [...]` is recognised, which is all this
# script ever writes.
_WRITE_CONFIG_SCRIPT = r"""
set -eu
CFG=/etc/policy-controller/config.toml
install -d -m 0755 /etc/policy-controller
[ -f "$CFG" ] || : > "$CFG"
sed -i -E '/^[[:space:]]*(server_san|extra_server_sans)[[:space:]]*=/d;
           /^# server SANs managed by scripts\/e2e-deploy\.py/d' "$CFG"
cat >> "$CFG"
"""


def write_controller_config(args: argparse.Namespace, host: ControllerHost) -> None:
    """Point the controller's server cert at the SANs the nodes will dial.

    Runs on every deploy: the certs are re-issued from this config at each
    startup, and without it the controller keeps its built-in default
    (`policy-controller`) while the bundle sends nodes to some other name —
    which fails the mTLS leg with "certificate not valid for name ...".

    Must land after the deb install and before the restart so the freshly
    issued cert picks the SANs up.
    """
    sans = controller_sans(args)
    extra = ", ".join(f'"{s}"' for s in sans[1:])
    block = (
        "# server SANs managed by scripts/e2e-deploy.py — regenerated each run.\n"
        f'server_san = "{sans[0]}"\n'
        f"extra_server_sans = [{extra}]\n"
    )
    step(f"Controller: setting server-cert SANs in config.toml ({', '.join(sans)})")
    host.run_script(_WRITE_CONFIG_SCRIPT, sudo=True, stdin_text=block, capture=True)
    ok(f"server cert SANs: {', '.join(sans)}")


# Marker logged by the controller at startup, listing the SANs it actually
# issued its gRPC server certs with. Added by commit e6299ee (2026-07-21)
# alongside configurable SANs; controllers built before that hardcode
# DnsName("policy-controller") and silently ignore server_san, so its absence
# is the tell-tale for a stale binary.
_SAN_LOG_MARKER = "Server certificate SANs:"


def verify_cert_sans(args: argparse.Namespace, host: ControllerHost) -> None:
    """Check the controller issued its server certs with the SANs we asked for.

    Config alone doesn't prove it: a controller older than e6299ee parses
    server_san happily and then issues certs for "policy-controller" anyway,
    which fails every node's management mTLS leg with a hostname-verification
    error that says nothing about the real cause.
    """
    want = controller_sans(args)[0]
    proc = host.run(
        ["journalctl", "-u", "policy-controller.service", "-n", "200", "--no-pager"],
        sudo=True,
        capture=True,
        check=False,
    )
    if proc is None or proc.returncode != 0:
        warn("could not read the controller journal — skipping server-SAN check")
        return
    lines = [ln for ln in (proc.stdout or "").splitlines() if _SAN_LOG_MARKER in ln]
    if not lines:
        warn(
            "the controller never logged its server-cert SANs — this build "
            "predates configurable SANs (commit e6299ee, 2026-07-21) and will "
            'issue certs for "policy-controller" no matter what config.toml '
            f"says, so nodes dialling {want} will fail mTLS hostname "
            "verification. Rebuild the debs with 'make deb' and rerun."
        )
        return
    issued = lines[-1].split(_SAN_LOG_MARKER, 1)[1].strip()
    if want in [s.strip() for s in issued.split(",")]:
        ok(f"controller issued server certs for: {issued}")
    else:
        warn(
            f"controller issued server certs for [{issued}] but the nodes will "
            f"dial {want} — their mTLS leg will fail hostname verification"
        )


def controller_phase(
    args: argparse.Namespace, host: ControllerHost, ctrl_debs: list[Path]
) -> None:
    if not args.skip_controller:
        step(f"Controller ({host.label}): stop + wipe DB + install")
        host.run(["systemctl", "stop", "policy-controller.service"], sudo=True, check=False)
        host.run(
            [
                "rm", "-f",
                "/var/lib/policy-controller/controller.db",
                "/var/lib/policy-controller/controller.db-wal",
                "/var/lib/policy-controller/controller.db-shm",
            ],
            sudo=True,
        )
        if args.wipe_ca:
            warn("wiping controller CA (ca.key/ca.crt)")
            host.run(
                [
                    "rm", "-f",
                    "/var/lib/policy-controller/ca.key",
                    "/var/lib/policy-controller/ca.crt",
                ],
                sudo=True,
            )
        # Ship the debs over first when the controller is remote; local installs
        # read them straight out of the deb dir.
        staged = host.put(ctrl_debs)
        host.run(["apt-get", "install", "-y", "--reinstall", *staged], sudo=True)
        # Config must land after the install (which may drop a default config)
        # and before the restart so the reissued server cert carries our SANs.
        write_controller_config(args, host)
        host.run(["systemctl", "restart", "policy-controller.service"], sudo=True)
    else:
        step("Controller: skipped (reusing running controller)")
        warn(
            "--skip-controller: not rewriting config.toml or reissuing the "
            "server cert — the running controller must already carry "
            f"{controller_sans(args)[0]} as a server-cert SAN, or the nodes' "
            "mTLS leg will fail hostname verification"
        )

    step(f"Controller: waiting for HTTP API at {args.controller_api} (on {host.label})")
    wait_for_controller(args.controller_api, host)
    # Only meaningful against a controller we just restarted; under
    # --skip-controller the journal may predate the current config.
    if not args.skip_controller and not host.r.dry_run:
        verify_cert_sans(args, host)


def mint_token(args: argparse.Namespace, host: ControllerHost) -> str:
    step("Controller: minting operator API token")
    token_name = f"e2e-{int(time.time())}"
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


# add-operator has no --password flag: it reads a file (or prompts a TTY). The
# password arrives on stdin and never touches an argv, so it stays out of the
# process table on either host; the 0600 temp file is removed either way.
_ADD_OPERATOR_SCRIPT = r"""
set -u
umask 077
pw=$(mktemp /tmp/pe-e2e-pw.XXXXXX)
trap 'rm -f "$pw"' EXIT
cat > "$pw"
sudo policy-controller-add-operator --username %(user)s --password-file "$pw" --role admin
"""


def add_operator(args: argparse.Namespace, host: ControllerHost) -> None:
    """Create a controller-web operator account (argon2id-hashed password)."""
    if args.no_operator:
        return
    step(f"Controller: creating operator '{args.operator_user}' (role admin)")
    script = _ADD_OPERATOR_SCRIPT % {"user": shlex.quote(args.operator_user)}
    proc = host.run_script(
        script,
        stdin_text=args.operator_password + "\n",
        check=False,
        capture=True,
    )
    if host.r.dry_run:
        return
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
    args: argparse.Namespace, host: ControllerHost, token: str, bundle_path: Path
) -> None:
    mgmt_url = f"https://{bundle_host(args)}:7777"
    step(f"Controller: creating enrollment bundle (mgmt url: {mgmt_url})")
    # Runs on the controller host; its stdout (the bundle) comes back to us and
    # is written locally, ready to scp on to each node.
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
    proc = host.run(argv, capture=True, redact=token)
    if host.r.dry_run:
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
    args: argparse.Namespace, host: ControllerHost, token: str, since: datetime
) -> None:
    """Poll until every deployed node has checked in since `since`, then show
    the node table."""
    if args.no_verify:
        return
    base = ["policy-controller-client", "--url", args.controller_api, "--token", token]
    step(f"Verifying enrolment (checked in since {since.isoformat(timespec='seconds')})")
    if host.r.dry_run:
        host.run([*base, "nodes", "list", "--status", "active"], redact=token)
        return

    expected = len(args.nodes)
    deadline = time.monotonic() + args.verify_timeout
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
    host.run([*base, "nodes", "list", "--status", "active"], check=False, redact=token)


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
        "--controller-ssh",
        default=None,
        metavar="DEST",
        help="ssh destination of the machine to install the controller on "
        "(e.g. root@10.0.0.2). The controller debs are copied there and every "
        "controller-side command runs over ssh. Default: this machine.",
    )
    p.add_argument(
        "--controller-host",
        default=None,
        help="IP the NODES route to for this controller. Pinned in each node's "
        "/etc/hosts as <controller-name>. Default: the controller machine's "
        "primary IP (autodetected locally, or over ssh with --controller-ssh).",
    )
    p.add_argument(
        "--controller-name",
        default=None,
        help="DNS name embedded in the bundle URLs; must match the controller's "
        f"server-cert SAN (default: {DEFAULT_CONTROLLER_NAME}). Under --by-ip "
        "there is no default at all — the controller is addressed purely by IP "
        "— and passing one only adds it as an extra cert SAN.",
    )
    p.add_argument(
        "--no-hosts",
        action="store_true",
        help="don't touch /etc/hosts on the nodes (you manage DNS for "
        "--controller-name yourself)",
    )
    p.add_argument(
        "--by-ip",
        action="store_true",
        help="connect nodes straight to the controller's IP (no DNS/hosts at "
        "all). Writes /etc/policy-controller/config.toml with the controller IP "
        "as server_san so the server cert covers it and the web UI's own bundle "
        "URLs use it too, embeds the IP in the bundle URLs, and skips the "
        "/etc/hosts pin. Requires reinstalling the controller (not compatible "
        "with --skip-controller).",
    )
    p.add_argument(
        "--controller-api",
        default="http://127.0.0.1:8443",
        help="base URL of the controller HTTP API, as seen FROM the controller "
        "machine (default: %(default)s)",
    )
    p.add_argument("--ttl", default="1h", help="enrollment-token TTL (default: %(default)s)")
    p.add_argument(
        "--max-uses", type=int, default=50, help="max bundle redemptions (default: %(default)s)"
    )
    p.add_argument("--label", default="e2e", help="fleet label (default: %(default)s)")
    p.add_argument(
        "--ssh-opts",
        default="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        help="extra options passed to ssh/scp (nodes and --controller-ssh alike)",
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
    # In --by-ip mode the bundle URL is the controller IP, so there is no name
    # to pin: the /etc/hosts edit is pointless and would just add a bogus entry.
    # A name is only carried if one was asked for explicitly (as an extra SAN).
    if args.by_ip:
        args.no_hosts = True
    elif not args.controller_name:
        args.controller_name = DEFAULT_CONTROLLER_NAME
    r = Runner(args.dry_run)
    host = ControllerHost(r, args.controller_ssh, shlex.split(args.ssh_opts))
    # Baseline for the enrolment check: a node counts as freshly enrolled only
    # if its lastSeen is at or after this instant — read off the controller's
    # own clock, which is ours when it runs here and may be skewed when it
    # doesn't.
    started = host.now_utc()

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
        args.controller_host = autodetect_host(host)
        warn(
            f"autodetected controller host: {args.controller_host} "
            f"(on {host.label}; override with --controller-host)"
        )

    fd, bundle_name = tempfile.mkstemp(prefix="pe-e2e-bundle.", suffix=".b64", dir="/tmp")
    os.close(fd)
    bundle_path = Path(bundle_name)

    failed: list[str] = []
    token = "<tok>"
    try:
        controller_phase(args, host, ctrl_debs)
        token = mint_token(args, host)
        add_operator(args, host)
        create_bundle(args, host, token, bundle_path)

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

        verify_enrolment(args, host, token, started)
    finally:
        if args.keep_bundle:
            if bundle_path.exists() and bundle_path.stat().st_size:
                log(f"bundle kept at {bundle_path}")
        else:
            bundle_path.unlink(missing_ok=True)

    # ── summary ──────────────────────────────────────────────────────────────
    step("Summary")
    print(f"  feature:        {args.feature} ({engine_pkg})")
    print(f"  controller on:  {host.label}")
    # The API URL is controller-local; from here you reach it on its real address.
    ui_url = args.controller_api
    if host.remote:
        parsed = urllib.parse.urlsplit(args.controller_api)
        ui_url = f"{parsed.scheme}://{args.controller_host}:{parsed.port or 8443}"
    print(f"  controller ui:  {ui_url}")
    print(f"  bundle mgmt url:https://{bundle_host(args)}:7777  (embedded for nodes)")
    if args.by_ip:
        print(f"  node reach:     direct to {args.controller_host} (cert IP SAN, no hosts pin)")
    elif not args.no_hosts:
        print(f"  node hosts pin: {args.controller_host} {args.controller_name}")
    print(f"  engine state:   {'WIPED' if args.wipe_state else 'preserved'}")
    print(f"  nodes:          {' '.join(args.nodes)}")
    if not args.no_operator:
        print(f"  operator login: {args.operator_user} / {args.operator_password}")
    print(f"  api token:      {token}")
    if host.remote:
        # An exported var doesn't cross ssh, so pass the token inline instead.
        hint = (
            f"    ssh {args.controller_ssh} 'policy-controller-client "
            f"--url {args.controller_api} --token {token} "
            "nodes list --status active'"
        )
    else:
        hint = (
            f"    export POLICY_CONTROLLER_TOKEN={token}\n"
            f"    policy-controller-client --url {args.controller_api} "
            "nodes list --status active"
        )
    print(f"{DIM}  rerun a client command with:\n{hint}{RESET}")
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
