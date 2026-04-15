# Build targets for sfae CLI

BUNDLE_ID ?= com.sfae.cli

# macOS release binary, code-signed for stable keychain access.
# The login keychain ties item ACLs to the binary's code signing identity.
# Without signing, every rebuild changes the identity and triggers password prompts.
#
# Set CODESIGN_IDENTITY to your signing identity:
#   make build CODESIGN_IDENTITY="Apple Development: you@example.com"
# List available identities:
#   security find-identity -v -p codesigning
.PHONY: build
build:
ifndef CODESIGN_IDENTITY
	$(error CODESIGN_IDENTITY is not set. Run: security find-identity -v -p codesigning)
endif
	cargo build --bin sfae --release
	codesign -s "$(CODESIGN_IDENTITY)" --identifier "$(BUNDLE_ID)" --force target/release/sfae
	@echo "Binary: target/release/sfae (signed as $(BUNDLE_ID))"

# Static Linux binary for client mode (no glibc dependency)
# Uses musl libc + --no-default-features (excludes native-keychain/OS keychain)
.PHONY: build-client
build-client:
	docker run --rm --platform linux/amd64 -v $(CURDIR):/app -w /app rust:1.92-alpine sh -c \
		"cargo build --release --bin sfae --no-default-features"
	@echo "Binary: target/release/sfae"
