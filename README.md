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

<img width="1165" height="745" alt="Instruction tracing" src="https://github.com/user-attachments/assets/bf0be54d-c112-46e7-8c68-8464ce8e7f32" />

## Crates

- [remu64](remu64): Core emulation engine (CPU, memory, hooks)
- [rdex](rex): Minidump loader and utilities to exectue functions

## Usage

### Simple Code Execution

```rust
use remu64::memory::MemoryTrait
use remu64::{Engine, EngineMode, Permission, Register};

let mut engine = Engine::new(EngineMode::Mode64);
engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();

// mov rax, 0x1337; mov rbx, 0x42; add rax, rbx
let code = [0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, 
            0x48, 0xC7, 0xC3, 0x42, 0x00, 0x00, 0x00, 
            0x48, 0x01, 0xD8];

engine.memory.write(0x1000, &code).unwrap();
engine.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0).unwrap();

assert_eq!(engine.reg_read(Register::RAX), 0x1337 + 0x42);
```

### Hooks Example

```rust
use remu64::hooks::HookManager;
use remu64::memory::MemoryTrait
use remu64::{Engine, EngineMode, Permission, Register};

struct MyHooks;

impl<M: MemoryTrait> HookManager<M> for MyHooks {
    fn on_code(&mut self, engine: &mut Engine<M>, address: u64, _size: usize) -> remu64::Result<()> {
        println!("Executing at {:#x}, RAX = {:#x}", address, engine.reg_read(Register::RAX));
        Ok(())
    }
}

let mut engine = Engine::new(EngineMode::Mode64);
let mut hooks = MyHooks;

// mov rax, 0x1337; mov rbx, 0x42; add rax, rbx
let code = [0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, 
            0x48, 0xC7, 0xC3, 0x42, 0x00, 0x00, 0x00, 
            0x48, 0x01, 0xD8];

engine.memory.map(0x1000, 0x1000, Permission::ALL).unwrap();
engine.memory.write(0x1000, &code).unwrap();

engine.emu_start_with_hooks(0x1000, 0x1000 + code.len() as u64, 0, 0, &mut hooks).unwrap();
```

See examples for more advanced usage:

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
