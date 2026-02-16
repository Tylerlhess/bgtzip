#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/Tylerlhess/bgtzip.git"
BRANCH="master"
INSTALL_DIR="${BGTZIP_INSTALL_DIR:-$(mktemp -d)}"
CLEANUP=true

info()  { printf '\033[1;34m==> %s\033[0m\n' "$*"; }
warn()  { printf '\033[1;33m==> %s\033[0m\n' "$*"; }
err()   { printf '\033[1;31m==> %s\033[0m\n' "$*" >&2; }
ok()    { printf '\033[1;32m==> %s\033[0m\n' "$*"; }

cleanup() {
    if [ "$CLEANUP" = true ] && [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
    fi
}
trap cleanup EXIT

# ------------------------------------------------------------------
# 1. Check for git
# ------------------------------------------------------------------
if ! command -v git &>/dev/null; then
    err "git is required but not installed."
    err "Install it with your package manager (e.g. apt install git, yum install git)."
    exit 1
fi

# ------------------------------------------------------------------
# 2. Check for Rust / Cargo — offer to install if missing
# ------------------------------------------------------------------
install_rust() {
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # Source the environment so cargo is available in this session
    if [ -f "$HOME/.cargo/env" ]; then
        . "$HOME/.cargo/env"
    fi
}

if command -v cargo &>/dev/null; then
    CARGO_VER=$(cargo --version)
    ok "Found $CARGO_VER"
else
    warn "Rust/Cargo is not installed."
    printf '\n'
    read -rp "Install Rust now? [Y/n] " answer
    case "${answer:-Y}" in
        [Yy]|[Yy][Ee][Ss]|"")
            install_rust
            if ! command -v cargo &>/dev/null; then
                err "Cargo still not found after install. Try opening a new shell and re-running."
                exit 1
            fi
            ok "Found $(cargo --version)"
            ;;
        *)
            err "Rust is required to build bgtzip. Aborting."
            exit 1
            ;;
    esac
fi

# ------------------------------------------------------------------
# 3. Clone and build
# ------------------------------------------------------------------
info "Cloning bgtzip into $INSTALL_DIR ..."
git clone --depth 1 --branch "$BRANCH" "$REPO" "$INSTALL_DIR/bgtzip"

info "Building and installing bgtzip (this may take a minute)..."
cargo install --path "$INSTALL_DIR/bgtzip"

# ------------------------------------------------------------------
# 4. Verify
# ------------------------------------------------------------------
if command -v bgtzip &>/dev/null; then
    ok "bgtzip installed successfully!"
    printf '\n'
    bgtzip --help
    printf '\n'
    ok "Run:  bgtzip analyze <logfile>"
    ok "      bgtzip anomalies <logfile> --top-n 10"
else
    CARGO_BIN="${CARGO_HOME:-$HOME/.cargo}/bin"
    warn "bgtzip was built but is not on your PATH."
    warn "Add this to your shell profile:"
    printf '\n    export PATH="%s:$PATH"\n\n' "$CARGO_BIN"
    warn "Then run:  bgtzip analyze <logfile>"
fi
