BPF_DIR := src/bpf
# Exclude vendored/generated headers (bpf_helpers.h, vmlinux_subset.h) from linting.
BPF_FILES := $(shell find $(BPF_DIR) -type f \( -name '*.c' -o -name '*.h' \) \
               ! -name 'bpf_helpers.h' ! -name 'vmlinux_subset.h' 2>/dev/null)

# Prefer the real bpftool binary under /usr/lib/linux-tools/ (installed by
# linux-tools-azure or linux-tools-generic) over /usr/sbin/bpftool, which is
# only a wrapper that requires the exact running-kernel package to be present.
BPFTOOL      ?= $(or $(shell find /usr/lib/linux-tools/ /usr/lib/linux-tools-*/ -name bpftool -type f 2>/dev/null | head -1),/usr/sbin/bpftool)
CLANG        ?= clang
CLANG_FORMAT ?= clang-format
# Map uname -m to the __TARGET_ARCH_* name expected by BPF headers.
BPF_ARCH := $(shell uname -m | sed 's/aarch64/arm64/')

BPF_VERIFY_CFLAGS := \
	-g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	-I src/bpf/include \
	-Wno-compare-distinct-pointer-types \
	-mllvm -unroll-threshold=500000

BPF_VERIFY_TMP := /tmp/pe_bpf_verify
BPF_VERIFY_PIN := /sys/fs/bpf/pe_verify

# ---------------------------------------------------------------------------
# Debian package build
#
# Usage:
#   make deb                        # base package (no optional features)
#   make deb FEATURES=features      # with rust features enabled support
#
# Translates FEATURES into DEB_BUILD_PROFILES and passes them to
# dpkg-buildpackage.  The -P flag alone does not export DEB_BUILD_PROFILES
# into debian/rules' environment, so we export it explicitly.
# ---------------------------------------------------------------------------

FEATURES ?=
comma := ,

# Convert "foo" → "pkg.policy-engine.foo"
_DEB_PROFILES = $(foreach f,$(subst $(comma), ,$(FEATURES)),pkg.policy-engine.$(f))

.PHONY: deb

# Each build gets a unique Debian version (<base>+git<utc-timestamp>.<sha>)
# via a temporary changelog entry (restored afterwards, even on failure).
# With a constant version, `apt install ./pkg.deb` over an equal installed
# version is a silent no-op — stale binaries survive what looks like an
# upgrade.  The monotonic timestamp makes every rebuild an apt upgrade.
deb:
	@set -e; \
	cp debian/changelog debian/changelog.deb-orig; \
	trap 'mv debian/changelog.deb-orig debian/changelog' EXIT; \
	base="$$(dpkg-parsechangelog -SVersion)"; \
	maint="$$(dpkg-parsechangelog -SMaintainer)"; \
	sha="$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"; \
	ver="$$base+git$$(date -u +%Y%m%d%H%M%S).$$sha"; \
	{ printf 'policy-engine (%s) unstable; urgency=medium\n\n  * Development build from git %s.\n\n -- %s  %s\n\n' \
		"$$ver" "$$sha" "$$maint" "$$(date -R)"; \
	  cat debian/changelog.deb-orig; } > debian/changelog; \
	$(if $(_DEB_PROFILES),DEB_BUILD_PROFILES="$(_DEB_PROFILES)" )dpkg-buildpackage --no-sign -uc -us -b

.PHONY: verify-bpf lint lint-rust lint-bpf lint-python fmt fmt-python coverage \
	lint-web build-web ci test-integration

# Load BPF programs into the kernel to confirm the verifier accepts them.
# Compiles from source with clang (matching libbpf_cargo flags), then uses
# bpftool prog loadall to run the kernel verifier without attaching to any
# interface.  Requires sudo (CAP_BPF only; CAP_NET_ADMIN is not needed).
#
# Both the base build and the -DSURICATA_IPS build are verified: the IPS
# variant adds code to the main programs (INSPECT action, ingress cloning)
# and has its own verifier cost, so verifying only the base build can miss
# an IPS-only rejection (e.g. the 1M processed-insn limit).
#
# Usage: make verify-bpf
verify-bpf:
	@mkdir -p $(BPF_VERIFY_TMP)
	@echo "Compiling XDP BPF program..."
	$(CLANG) $(BPF_VERIFY_CFLAGS) -c src/bpf/xdp/xdp_policy.bpf.c -o $(BPF_VERIFY_TMP)/xdp_policy.bpf.o
	@echo "Compiling TC BPF program..."
	$(CLANG) $(BPF_VERIFY_CFLAGS) -c src/bpf/tc/tc_policy.bpf.c  -o $(BPF_VERIFY_TMP)/tc_policy.bpf.o
	@echo "Compiling XDP BPF program (SURICATA_IPS)..."
	$(CLANG) $(BPF_VERIFY_CFLAGS) -DSURICATA_IPS -c src/bpf/xdp/xdp_policy.bpf.c -o $(BPF_VERIFY_TMP)/xdp_policy_ips.bpf.o
	@echo "Compiling TC BPF program (SURICATA_IPS)..."
	$(CLANG) $(BPF_VERIFY_CFLAGS) -DSURICATA_IPS -c src/bpf/tc/tc_policy.bpf.c  -o $(BPF_VERIFY_TMP)/tc_policy_ips.bpf.o
	@echo "Running programs through kernel BPF verifier (requires sudo)..."
	@sudo rm -rf $(BPF_VERIFY_PIN)
	@sudo mkdir -p $(BPF_VERIFY_PIN)
	sudo $(BPFTOOL) prog loadall $(BPF_VERIFY_TMP)/xdp_policy.bpf.o $(BPF_VERIFY_PIN)/xdp
	sudo $(BPFTOOL) prog loadall $(BPF_VERIFY_TMP)/tc_policy.bpf.o  $(BPF_VERIFY_PIN)/tc
	sudo $(BPFTOOL) prog loadall $(BPF_VERIFY_TMP)/xdp_policy_ips.bpf.o $(BPF_VERIFY_PIN)/xdp_ips
	sudo $(BPFTOOL) prog loadall $(BPF_VERIFY_TMP)/tc_policy_ips.bpf.o  $(BPF_VERIFY_PIN)/tc_ips
	@sudo rm -rf $(BPF_VERIFY_PIN)
	@rm -rf $(BPF_VERIFY_TMP)
	@echo "BPF verifier: all programs accepted (base + SURICATA_IPS)."

# Run all linters
lint: lint-rust lint-bpf lint-python

# Rust linting: formatting check + clippy
lint-rust:
	@command -v cargo >/dev/null || { echo "cargo not found in PATH"; exit 1; }
	@echo "Running cargo fmt..."
	cargo fmt --all
	@echo "Running cargo clippy..."
	cargo clippy --all-targets --all-features -- -D warnings

# BPF C linting: clang-format check + cppcheck (if available)
lint-bpf:
	@if [ -z "$(BPF_FILES)" ]; then \
		echo "No BPF C files found in $(BPF_DIR), skipping BPF lint."; \
	else \
		if command -v $(CLANG_FORMAT) >/dev/null; then \
			echo "Checking clang-format for BPF files..."; \
			$(CLANG_FORMAT) -style=file -n $(BPF_FILES) || true; \
		else \
			echo "clang-format not found; skipping format check for BPF files"; \
		fi; \
	fi

# Python linting: ruff + mypy over python/ (the integration tests and clients)
lint-python:
	@command -v poetry >/dev/null || { echo "poetry not found in PATH"; exit 1; }
	@echo "Running ruff..."
	poetry run ruff check python/
	poetry run ruff format --check python/
	@echo "Running mypy..."
	poetry run mypy

# Format the Python sources in-place
fmt-python:
	poetry run ruff format python/
	poetry run ruff check --fix python/

# Integration tests. Needs libvirt (see python/README.md) and the .debs built
# by `make deb`, which land in the parent directory.
#
#   make test-integration                        every suite
#   make test-integration SUITE=policy_sanity    just one
test-integration:
	@if [ -n "$(SUITE)" ]; then \
		poetry run pytest python/tests/$(SUITE)/ --package-dir ..; \
	else \
		python/run_all.sh; \
	fi

# Format both Rust and BPF sources in-place
fmt:
	@command -v cargo >/dev/null || { echo "cargo not found in PATH"; exit 1; }
	@echo "Running cargo fmt..."
	cargo fmt
	@if [ -z "$(BPF_FILES)" ]; then \
		echo "No BPF C files found in $(BPF_DIR), skipping BPF formatting."; \
	else \
		if command -v $(CLANG_FORMAT) >/dev/null; then \
			echo "Formatting BPF files with clang-format..."; \
			$(CLANG_FORMAT) -i $(BPF_FILES); \
		else \
			echo "clang-format not found; skipping formatting of BPF files"; \
		fi; \
	fi

# Generate HTML code coverage report using cargo-llvm-cov.
# The llvm-tools rustup component is declared in rust-toolchain.toml and
# installed automatically.  cargo-llvm-cov is installed here if missing.
# Output: coverage/html/index.html
coverage:
	@command -v cargo-llvm-cov >/dev/null || cargo install cargo-llvm-cov --locked
	cargo llvm-cov --release --workspace --all-features --html --output-dir coverage/

# Run the same steps as the GitHub Actions rust CI job.
# Requires: clang, libbpf-dev, bpftool (sudo), cargo, cargo-llvm-cov, debhelper.
ci:
	@echo "=== deb build+test (default) ==="
	dpkg-buildpackage -us -uc -b
	@echo "=== deb build+test (suricata) ==="
	DEB_BUILD_PROFILES="pkg.policy-engine.suricata" dpkg-buildpackage -us -uc -b
	@echo "=== deb build+test (ipfix) ==="
	DEB_BUILD_PROFILES="pkg.policy-engine.ipfix" dpkg-buildpackage -us -uc -b
	@echo "=== deb build+test (suricata+ipfix) ==="
	DEB_BUILD_PROFILES="pkg.policy-engine.suricata pkg.policy-engine.ipfix" dpkg-buildpackage -us -uc -b
	@echo "=== cargo fmt check ==="
	cargo fmt --all -- --check
	@echo "=== clippy ==="
	cargo clippy --all-targets --all-features -- -D warnings
	@echo "=== lint-bpf ==="
	$(MAKE) lint-bpf
	@echo "=== verify-bpf ==="
	$(MAKE) verify-bpf
	@echo "=== coverage ==="
	$(MAKE) coverage
	@echo "=== CI complete ==="

lint-web:
	cd web && npm run lint

build-web: schema-export
	cd web && npm run codegen && npm run build

schema-export:
	@echo running schema export
	cargo run --release --bin schema_export --all-features > ${CWD}web/schema.graphql
