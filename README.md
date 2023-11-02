
bitcoin-scriptexec
==================

A work-in-progress Bitcoin Script execution utility.

**DISCLAIMER: DO NOT EVER, EVER, TRY TO USE THIS CRATE FOR CONSENSUS PURPOSES !!**


# Status

This project is a work-in-progress mostly attempting to facilitate BitVM development.
It does not yet fully implement all opcodes, but as a library already gives you pretty
good insight into the internals of the execution in a step-wise manner.


# Usage

## CLI

You can simply use `cargo run` or build/intall the binary as follows:

```
# to build in debug mode
$ cargo build --locked
# to build in release (optimized) mode
$ cargo build --locked --release
# to install in ~/.cargo/bin
$ cargo install --locked --path .
```

### Usage

The CLI currently takes only a single argument: the path to the ASM script file:

```
# using the binary
$ btcexec <script.bs>
# using cargo run
$ cargo run -- <script.bs>
```

## WASM

There are wasm bindings provided. For API documentation, see the `src/wasm.rs`a file.

To build the WASM bindings, [install wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
and then run the following script:

```
./build-wasm.sh
```
