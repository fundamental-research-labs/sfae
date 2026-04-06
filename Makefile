# Build targets for sfae CLI

# Static Linux binary for client mode (no glibc dependency)
# Uses musl libc + --no-default-features (excludes keyring/OS keychain)
.PHONY: build-client
build-client:
	docker run --rm --platform linux/amd64 -v $(CURDIR):/app -w /app rust:1.92-alpine sh -c \
		"cargo build --release --bin sfae --no-default-features"
	@echo "Binary: target/release/sfae"
