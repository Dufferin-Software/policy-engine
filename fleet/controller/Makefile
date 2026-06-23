# Build helpers for the controller fleet web app (fleet/controller/web).
#
# The controller exposes its own GraphQL schema, distinct from the engine's.
# `schema-export` regenerates the checked-in SDL snapshot the web app builds
# against, using the controller's print-schema bin.

.PHONY: schema-export build-web lint-web

schema-export:
	@echo running controller schema export
	cargo run --release --bin policy-controller-print-schema --all-features > web/schema.graphql

build-web: schema-export
	cd web && npm run build

lint-web:
	cd web && npm run lint
