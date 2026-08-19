# Integration tests

End-to-end tests for policy-engine and the fleet controller, run against
Debian VMs on a [netsim](https://github.com/Dufferin-Software/netsim)
topology. Each suite is a directory holding its own topology YAML, its
fixtures, and its tests.

```
python/
  conftest.py             loads netsim.testkit, adds the scale-test options
  run_all.sh              every suite in sequence, with a summary
  policy_engine_client/   Python clients for the engine and controller APIs
  tests/<suite>/
    <suite>.yaml          the topology, including which .debs each node gets
    conftest.py           the suite's fixtures
    test_*.py
```

netsim supplies the topology, VM lifecycle, SSH access, netplan configuration
and package installation as pytest fixtures. `python/conftest.py` opts in with
a single line — `pytest_plugins = ["netsim.testkit.plugin"]` — and everything
else in the suites is policy-engine's own.

## Setup

Install the build dependencies for `libvirt-python`, then the project:

```bash
sudo apt install libvirt-dev pkg-config
poetry install
```

Configure the libvirt user session once, using the script from a netsim
checkout:

```bash
git clone git@github.com:Dufferin-Software/netsim.git
netsim/setup-user-mode.sh
```

libvirt must not be running the AppArmor security driver — it blocks QEMU from
reading images under `~/.netsim`. Set `security_driver = "none"` in
`/etc/libvirt/qemu.conf` and restart `libvirtd`.

## Running

Build the packages first; the suites install them into the VMs.

```bash
make deb                                  # from the repo root; .debs land in ../
poetry run pytest python/tests/policy_sanity/ --package-dir ..
```

`--package-dir` points at the directory holding the `.deb` files. Each
topology also names a default, so it can be omitted when the packages are
where `dpkg-buildpackage` left them.

Suites that exercise a build feature need the matching package. `--feature`
selects which set a node installs where the topology declares several:

```bash
poetry run pytest python/tests/ips_ids/ --feature ips --package-dir ..
```

Everything, with a summary table and per-suite logs in `pytest-logs/`:

```bash
python/run_all.sh
SKIP="scale_test" python/run_all.sh
```

Two options are useful when something breaks: `--pause-on-failure` keeps the
topology up and prints the `ssh` command for each node, and `-m 'not slow'`
skips the tests that wait on scheduler intervals.

## Working on netsim at the same time

netsim is pinned to a tag. To test against a local checkout instead:

```bash
poetry run pip install -e ../netsim
```

Re-run `poetry install` to go back to the pinned version.
