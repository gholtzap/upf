#!/bin/bash

set -e

echo "====================================="
echo "UPF Setup Script"
echo "====================================="

echo ""
echo "Step 1: Checking Rust installation..."
if ! command -v rustc &> /dev/null; then
    echo "Error: Rust is not installed."
    echo "Please install Rust from https://rustup.rs/"
    echo "Run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo "Rust version: $(rustc --version)"
echo "Cargo version: $(cargo --version)"

echo ""
echo "Step 2: Checking configuration file..."
if [ ! -f "config.yaml" ]; then
    echo "Warning: config.yaml not found. Creating default configuration..."
    cat > config.yaml << 'EOF'
n4_address: "127.0.0.1:8805"
n3_address: "127.0.0.1:2152"
n6_address: "127.0.0.1:9000"
n6_interface: "eth0"
upf_node_id: "upf1.example.com"
log_level: "info"
EOF
    echo "Created config.yaml with default values"
else
    echo "config.yaml found"
fi

echo ""
echo "Step 3: Building UPF..."
cargo build --release

echo ""
echo "====================================="
echo "Setup Complete!"
echo "====================================="
echo ""
echo "The UPF has been built successfully."
echo "Binary location: target/release/upf"
echo ""
echo "To run the UPF:"
echo "  ./target/release/upf"
echo ""
echo "To run with a custom config file:"
echo "  ./target/release/upf --config path/to/config.yaml"
echo ""
echo "To set log level via environment variable:"
echo "  RUST_LOG=debug ./target/release/upf"
echo ""
