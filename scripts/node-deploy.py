#!/usr/bin/env python3
"""Deploy policy-engine packages to one or more nodes. No controller involved.

Two modes:

  --mode upgrade (default)
    Install the debs and restart. The agent keeps its identity, so the node
    stays the same node in the controller; the engine keeps state.json and its
    BPF pins, so rules and attachments come back after the restart. Needs no
    controller access whatsoever — just ssh to the nodes.

  --mode reinstall
    Wipe the agent's mTLS credentials, drop a fresh ZTP bootstrap bundle, and
    let it enrol from scratch. Use for a brand-new node, or one that has to
    move to a different controller. The node comes back with a NEW id — its old
    controller entry goes stale — so this is not the way to pick up a new
    build. Engine state survives unless you pass --wipe-state.

The bundle for a reinstall either gets minted for you (needs to reach a
controller, locally or via --controller-ssh) or is supplied with --bundle.

Packages are taken as-is from a directory of prebuilt .deb files (default ../
relative to the repo). Build them first with `make deb` / `make deb FEATURES=...`.

Usage:
    # roll a new build onto three existing nodes, keeping their enrolment
    scripts/node-deploy.py --feature ips peter@flobot peter@fws-2277

    # just the agent, nothing else
    scripts/node-deploy.py --pkg agent peter@flobot

    # enrol a brand-new node into an existing fleet
    scripts/node-deploy.py --mode reinstall --controller-ssh peter@noisey \
        --controller-url https://noisey:7777 --pin-hosts 10.0.0.2 \
        --feature ips peter@newnode

    # enrol with a bundle someone handed you (no controller access at all)
    scripts/node-deploy.py --mode reinstall --bundle ./bootstrap.b64 peter@newnode

Run with --help for all options. To stand up a whole fleet including the
controller, use e2e-deploy.py.
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
import tempfile
import urllib.parse
from pathlib import Path

from pe_deploy import (
    DIM,
    ENGINE_PKG,
    NODE_PKGS,
    RED,
    RESET,
    ControllerHost,
    DeployError,
    NodePlan,
    Runner,
    create_bundle,
    deploy_nodes,
    log,
    mint_token,
    ok,
    resolve_node_debs,
    step,
    verify_checkin,
    warn,
)

TOKEN_ENV = "POLICY_CONTROLLER_TOKEN"


# ── option plumbing ──────────────────────────────────────────────────────────
def url_hostname(url: str) -> str:
    """Host part of a controller URL, without port."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname:
        raise DeployError(f"could not parse a hostname out of --controller-url {url!r}")
    return parsed.hostname


def hosts_pin(args: argparse.Namespace) -> tuple[str, str] | None:
    """The (ip, name) pair to pin in each node's /etc/hosts, if any.

    Only meaningful when the controller URL carries a DNS name: an IP-addressed
    URL needs no resolution (and the controller's cert must carry a matching
    iPAddress SAN for it to work at all).
    """
    if not args.pin_hosts:
        return None
    if not args.controller_url:
        raise DeployError("--pin-hosts needs --controller-url to know what name to pin")
    name = url_hostname(args.controller_url)
    if name.replace(".", "").isdigit() or ":" in name:
        raise DeployError(
            f"--controller-url host {name!r} is an address, not a name — "
            "nothing to pin; drop --pin-hosts"
        )
    return (args.pin_hosts, name)


def resolve_token(args: argparse.Namespace, host: ControllerHost) -> str | None:
    """The API token for minting and/or verification, or None if we have no
    way to talk to the controller."""
    token = args.token or os.environ.get(TOKEN_ENV)
    if token:
        return token
    if args.no_mint:
        return None
    # Falls back to minting one on the controller, which needs sudo there.
    return mint_token(host, prefix="node")


def obtain_bundle(
    args: argparse.Namespace, host: ControllerHost, token: str | None, bundle_path: Path
) -> Path:
    """Return the path of the bundle to ship, minting one if needed."""
    if args.bundle:
        src = args.bundle.expanduser().resolve()
        if not src.is_file():
            raise DeployError(f"bundle not found: {src}")
        ok(f"using bundle {src}")
        return src
    if not args.controller_url:
        raise DeployError(
            "--mode reinstall needs a bundle: pass --bundle <file>, or "
            "--controller-url <mgmt url> so one can be minted for you"
        )
    if not token:
        raise DeployError(
            "no API token to mint a bundle with: pass --token, set "
            f"${TOKEN_ENV}, or drop --no-mint"
        )
    create_bundle(
        host,
        args.controller_api,
        token,
        args.controller_url,
        bundle_path,
        ttl=args.ttl,
        max_uses=args.max_uses,
        label=args.label,
    )
    return bundle_path


def check_args(args: argparse.Namespace) -> None:
    """Reject combinations that can't mean what they look like."""
    if args.mode == "upgrade":
        # Enrolment material is inert without a credential wipe: the agent
        # treats existing creds as "already enrolled" and never reads a bundle.
        for flag, value in (("--bundle", args.bundle), ("--controller-url", args.controller_url)):
            if value:
                raise DeployError(
                    f"{flag} does nothing in --mode upgrade (the agent keeps its "
                    "identity and never re-reads a bundle) — did you mean "
                    "--mode reinstall?"
                )
    if args.mode == "reinstall" and not args.bundle and not args.controller_url:
        # Fail before resolving packages or minting anything.
        raise DeployError(
            "--mode reinstall needs a bundle: pass --bundle <file>, or "
            "--controller-url <mgmt url> so one can be minted for you"
        )
    if args.pkg and "agent" not in args.pkg and args.mode == "reinstall":
        warn(
            "--mode reinstall without the 'agent' package: credentials will be "
            "wiped and a bundle staged, but the installed agent build won't change"
        )


# ── argument parsing ─────────────────────────────────────────────────────────
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="node-deploy.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--mode",
        choices=("upgrade", "reinstall"),
        default="upgrade",
        help="upgrade: install debs, keep enrolment + state (default). "
        "reinstall: also wipe agent credentials and re-enrol from a bundle.",
    )
    p.add_argument(
        "--feature",
        choices=sorted(ENGINE_PKG),
        default="vanilla",
        help="engine variant (default: %(default)s)",
    )
    p.add_argument(
        "--pkg",
        action="append",
        choices=sorted(NODE_PKGS),
        metavar="{engine,client,web,agent}",
        help="package to install; repeatable. Default: all four.",
    )
    p.add_argument(
        "--deb-dir",
        type=Path,
        default=None,
        help="directory holding the prebuilt .deb files (default: the repo's parent)",
    )
    p.add_argument(
        "--wipe-state",
        action="store_true",
        help="wipe engine state (state.json) + BPF pins. Default: preserve them, "
        "so rules and attachments restore after the restart.",
    )

    g = p.add_argument_group("enrolment (--mode reinstall)")
    g.add_argument(
        "--controller-url",
        default=None,
        help="management URL embedded in the bundle, e.g. https://controller:7777. "
        "Its host must match a SAN on the controller's server cert, and must "
        "resolve on the nodes (see --pin-hosts).",
    )
    g.add_argument(
        "--pin-hosts",
        metavar="IP",
        default=None,
        help="pin the --controller-url hostname to this IP in each node's "
        "/etc/hosts, for fleets without DNS for it",
    )
    g.add_argument(
        "--bundle",
        type=Path,
        default=None,
        help="use this existing bootstrap bundle instead of minting one "
        "(needs no controller access)",
    )
    g.add_argument(
        "--controller-ssh",
        default=None,
        metavar="DEST",
        help="ssh destination of the controller, for minting the bundle and "
        "checking the nodes came back. Default: run the client on this machine.",
    )
    g.add_argument(
        "--controller-api",
        default="http://127.0.0.1:8443",
        help="controller HTTP API, as seen from wherever the client runs "
        "(default: %(default)s)",
    )
    g.add_argument(
        "--token",
        default=None,
        help=f"controller API token. Default: ${TOKEN_ENV}, else mint a fresh "
        "one on the controller (needs sudo there).",
    )
    g.add_argument(
        "--no-mint",
        action="store_true",
        help="never mint an API token; use only --token/env if present",
    )
    g.add_argument("--ttl", default="1h", help="enrollment-token TTL (default: %(default)s)")
    g.add_argument(
        "--max-uses", type=int, default=10, help="max bundle redemptions (default: %(default)s)"
    )
    g.add_argument("--label", default=None, help="fleet label applied to enrolling nodes")
    g.add_argument(
        "--keep-bundle",
        action="store_true",
        help="leave the minted bundle on disk and print its path",
    )

    p.add_argument(
        "--ssh-opts",
        default="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        help="extra options passed to ssh/scp",
    )
    p.add_argument(
        "--no-verify",
        action="store_true",
        help="don't poll the controller for the nodes checking back in",
    )
    p.add_argument(
        "--verify-timeout",
        type=int,
        default=60,
        help="seconds to wait for nodes to check in (default: %(default)s)",
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
    p.add_argument("nodes", nargs="+", help="ssh destinations of the nodes to deploy to")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    check_args(args)
    enrolling = args.mode == "reinstall"
    r = Runner(args.dry_run)
    host = ControllerHost(r, args.controller_ssh, shlex.split(args.ssh_opts))
    pin = hosts_pin(args)

    repo_root = Path(__file__).resolve().parent.parent
    deb_dir = (args.deb_dir or repo_root.parent).resolve()
    if not deb_dir.is_dir():
        raise DeployError(f"deb dir not found: {deb_dir}")

    which = args.pkg or list(NODE_PKGS)
    step(f"Resolving packages in {deb_dir} (feature: {args.feature})")
    node_debs = resolve_node_debs(deb_dir, args.feature, which)
    for d in node_debs:
        print(f"   {d.name}")

    # Only talk to the controller when there's a reason to: minting a bundle,
    # or verifying the nodes came back. An upgrade with neither needs nothing.
    token: str | None = None
    if enrolling and not args.bundle:
        token = resolve_token(args, host)
    elif not args.no_verify:
        token = args.token or os.environ.get(TOKEN_ENV)

    # Baseline for the check-in poll, off the controller's own clock.
    started = host.now_utc()

    fd, tmp_name = tempfile.mkstemp(prefix="pe-node-bundle.", suffix=".b64", dir="/tmp")
    os.close(fd)
    minted_path = Path(tmp_name)
    bundle_path: Path | None = None

    try:
        if enrolling:
            bundle_path = obtain_bundle(args, host, token, minted_path)

        plan = NodePlan(
            debs=node_debs,
            ssh_opts=shlex.split(args.ssh_opts),
            bundle_path=bundle_path,
            wipe_state=args.wipe_state,
            wipe_identity=enrolling,
            hosts_pin=pin,
            what=f"{args.mode}, feature: {args.feature}",
        )
        failed = deploy_nodes(r, plan, args.nodes, args.jobs)

        if args.no_verify:
            pass
        elif token:
            verify_checkin(
                host, args.controller_api, token, started,
                len(args.nodes), args.verify_timeout,
            )
        elif args.controller_ssh or args.no_mint:
            # They pointed us at a controller but we ended up without a token.
            warn(
                "no API token, so not verifying the nodes checked in — pass "
                f"--token or set ${TOKEN_ENV}"
            )
        else:
            # No controller access was configured; nothing surprising here.
            print(
                f"{DIM}  not verifying check-in (no controller access configured); "
                f"on each node: systemctl status policy-node-agent{RESET}"
            )
    finally:
        if args.keep_bundle and minted_path.exists() and minted_path.stat().st_size:
            log(f"bundle kept at {minted_path}")
        else:
            minted_path.unlink(missing_ok=True)

    # ── summary ──────────────────────────────────────────────────────────────
    step("Summary")
    print(f"  mode:           {args.mode}")
    print(f"  feature:        {args.feature} ({ENGINE_PKG[args.feature]})")
    print(f"  packages:       {' '.join(which)}")
    print(f"  engine state:   {'WIPED' if args.wipe_state else 'preserved'}")
    print(f"  agent identity: {'WIPED (re-enrolled)' if enrolling else 'preserved'}")
    if enrolling and args.controller_url:
        print(f"  bundle mgmt url:{args.controller_url}")
    if pin:
        print(f"  node hosts pin: {pin[0]} {pin[1]}")
    print(f"  nodes:          {' '.join(args.nodes)}")
    if failed:
        print(f"{RED}  failed:         {' '.join(failed)}{RESET}")
        return 1

    ok(f"all {len(args.nodes)} node(s) deployed")
    if enrolling:
        print(f"{DIM}  the agents re-enrol on restart; give them a few seconds{RESET}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except DeployError as exc:
        print(f"{RED}error{RESET} {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
