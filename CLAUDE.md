# Project Structure.

See README.md and the docs directory for full project overview.

# Post changes.

If any bpf files are touched, always run:

```make verify-bpf lint-bpf fmt```.

# BPF Changes.

For any bpf changes please consider the impact to performance and memory usage.

# Rust Changes.

For any significant rust change, please consider adding additional unit tests. Tests
must always use the mock system adaptor so that nothing on the system itself is
touched. For any rust api changes we should check that the ```npm run codegen```
phase works. Also we should ideally update the Python clients in
`python/policy_engine_client/`.

# Integration testing

Lives in `python/`: the suites in `python/tests/<suite>/` and the Python clients they
drive in `python/policy_engine_client/`. Each suite boots real VMs via
[netsim](https://github.com/pdmorrow/netsim), which is a dependency and supplies
the topology/SSH/package fixtures — see `python/README.md` and
`docs/TESTING_WITH_NETSIM.md`.

Run one with `make test-integration SUITE=policy_sanity`, all of them with
`make test-integration`. Lint with `make lint-python`.
