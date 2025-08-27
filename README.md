# remu64

Pure Rust x86-64 emulator with Unicorn Engine-like API.

**Disclaimer**: This was hacked together in a weekend with Claude and is ~~probably~~ full of bugs.

As of this writing, Unicorn is based on an older version of QEMU that doesn't implement many of the
AVX instructions required for common things like memcpy on modern Windows. It's also annoying to link to
from rust. I decided to see how far Claude would take me in making a hackable emulator, and it turns out...
quite far.

I took the liberty of implementing things in a modular way, so it's trivial to swap out the memory
backing with read-only implementations with copy-on-write layer on top (used in the minidump loader)
or stick entirely to an owned memory backing like Unicorn. Hooks are implemented via traits in a very
rust friendly way.

It currently only supports x86-64 via the iced_x64 disassembler.

<img width="982" height="511" alt="Instruction tracing" src="https://github.com/user-attachments/assets/8344fcf7-9069-4792-8757-68c49f924f38" />

## Crates

- [remu64](remu64): Core emulation engine (CPU, memory, hooks)
- [rdex](rex): Minidump loader and utilities to exectue functions

## Usage

See examples for usage:

- [remu64/examples](remu64/examples)
- [rdex/examples](rdex/examples)

Notably: [string_encryption_fun.rs](rdex/examples/string_encryption_fun.rs) which demonstrates executing
[Dumpulator's](https://github.com/mrexodia/dumpulator?tab=readme-ov-file#calling-a-function) example minidump
to call a decryption function and read the string from memory:

```
cargo run --release --example string_encryption_fun
Using TEB address 0x24e000 from thread 2476
decrypted: 'this is an encrypted string'
```
