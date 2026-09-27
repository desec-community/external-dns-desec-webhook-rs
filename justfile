# Default recipe: list available commands
default:
    @just --list

# Format all code (Rust + Nix + Markdown)
fmt:
    treefmt

# Check formatting (Rust + Nix + Markdown)
fmt-check:
    treefmt --fail-on-change --no-cache

# Run clippy lints
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Run all tests
test:
    cargo test --all-features

# Run the tests that talk to the real API. Needs DESEC_TOKEN from a test account with
# perm_create_domain and perm_delete_domain. Override the parent zone for scratch
# domains with DESEC_TEST_PARENT (default dedyn.io).
#
# These are #[ignore]d so `just test` and CI skip them; --ignored is what opts in. The
# thread cap is lower than desec-rs's: a full four-endpoint reconcile cycle spends more
# of the 300/day per-domain write budget than a library test does.
live-test *args='':
    cargo test --test live -- --ignored --nocapture --test-threads 2 {{ args }}

# Build release
build:
    cargo build --release --all-features

# Generate documentation
doc *args='':
    cargo doc --no-deps --all-features {{ args }}

# Build the OCI image (a script that streams a tarball on stdout)
image:
    nix build .#image

# Build the OCI image and load it into the local docker daemon
image-load: image
    ./result | docker load

readme_args := "--project-root crates/external-dns-desec-webhook --input src/lib.rs --template ../../README.tpl"

# Regenerate README.md from README.tpl and the crate docs
readme:
    cargo readme {{ readme_args }} | mdformat - > README.md

# Check README.md is in sync with README.tpl and the crate docs
readme-check:
    cargo readme {{ readme_args }} | mdformat - | diff - README.md

# Preview the release notes CI will attach to a tag. Defaults to the newest tag; pass
# --unreleased to see what tagging HEAD would produce, or a range like v0.1.2..v0.1.3.
changelog *args='--latest':
    git cliff {{ args }} --output -

# Assert the release tag names the version cargo would publish
check-version version:
    @pkgid="$(cargo pkgid -p external-dns-desec-webhook)"; crate="v${pkgid##*#}"; \
    if [ "$crate" != "{{ version }}" ]; then \
        echo "tag {{ version }} does not match crate version $crate" >&2; exit 1; \
    fi

# Run CI checks locally
ci: fmt-check lint test doc readme-check build
    @echo "All CI checks passed!"

# Clean build artifacts
clean:
    cargo clean
