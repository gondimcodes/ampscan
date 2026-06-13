# AmpScan - Installation & Compilation Guide

This guide walks you through installing the required dependencies and compiling AmpScan from source.

## Prerequisites

### 1. Install Rust and Cargo
AmpScan is written in Rust. If you do not have Rust installed on your machine, you can install it via `rustup` by running the following command:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Follow the on-screen prompts and ensure your shell is updated (you may need to run `source $HOME/.cargo/env` or restart your terminal).

### 2. System Dependencies
On Linux platforms, you will typically need `build-essential` and system SQLite libraries.
For Debian/Ubuntu-based systems:
```bash
sudo apt update
sudo apt install build-essential libsqlite3-dev
```

## Compilation

1. Clone your project repository or navigate to the source directory:
```bash
git clone https://github.com/gondimcodes/ampscan
cd ampscan
```

2. Compile the project in release mode for maximum performance:
```bash
cargo build --release
```

3. The compiled binary will be located at `target/release/ampscan`. You can move it to your PATH if desired:
```bash
sudo cp target/release/ampscan /usr/local/bin/
```
