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
phase works. Also we should ideally update the netsim policy client code.

# Integration testing

This done via the netsim repository in the parent directory.
