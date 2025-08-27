# DumpExec - Minidump Function Execution Framework

A Rust framework for loading Windows minidumps and executing functions with x64 Windows fastcall calling convention using the amd64-emu crate.

## Features

- **Efficient Minidump Loading**: Memory-mapped minidump parsing using `memmap2` for zero-copy access
- **Memory Management**: Page fault handling with automatic memory mapping from minidump data
- **x64 Windows Fastcall**: Proper implementation of Windows x64 calling convention
- **Function Execution**: Execute functions by address with optional arguments
- **Instruction Tracing**: Full disassembly and register state for each executed instruction
- **Memory Inspection**: Read/write memory and registers during execution

## Usage

### Command Line

```bash
# Load minidump and list modules
./target/debug/dump_exec dump.dmp

# Execute function at specific address
./target/debug/dump_exec dump.dmp 0x140001000

# Execute function with arguments
./target/debug/dump_exec dump.dmp 0x140001000 42 ptr:0x7ff000000 3.14

# Execute with instruction tracing enabled
./target/debug/dump_exec --trace dump.dmp 0x140001000
```

### Programmatic API

```rust
use dump_exec::{DumpExec, ArgumentType};

// Load minidump
let loader = DumpExec::load_minidump("crash.dmp")?;

// Create executor
let mut executor = DumpExec::create_executor(loader)?;

// Enable instruction tracing (optional)
executor.enable_tracing(true);

// Prepare arguments (fastcall convention)
let args = vec![
    ArgumentType::Integer(42),           // RCX
    ArgumentType::Pointer(0x7ff000000),  // RDX  
    ArgumentType::Float(3.14),           // XMM2
    ArgumentType::Integer(100),          // Stack
];

// Execute function
executor.execute_function(0x140001000, args)?;

// Get return value
let result = executor.get_return_value()?;
println!("Return value: 0x{:x}", result);
```

## Architecture

### Core Components

1. **MinidumpLoader** (`src/minidump_loader.rs`)
   - Memory-mapped minidump parsing for efficient access
   - Extracts module information
   - Provides zero-copy memory region access

2. **MemoryManager** (`src/memory_manager.rs`) 
   - Handles page fault exceptions
   - Maps memory on-demand from minidump
   - Manages executable/readable/writable permissions

3. **FastcallSetup** (`src/fastcall.rs`)
   - Implements x64 Windows calling convention
   - Maps arguments to registers (RCX, RDX, R8, R9) and stack
   - Handles shadow space allocation

4. **FunctionExecutor** (`src/executor.rs`)
   - Coordinates execution using amd64-emu
   - Manages CPU state and memory mapping
   - Provides execution context

5. **InstructionTracer** (`src/tracer.rs`)
   - Disassembles instructions using iced-x86
   - Logs register states for each instruction
   - Tracks function calls and returns

### x64 Windows Fastcall Convention

The framework correctly implements the Microsoft x64 calling convention:

- **Integer/Pointer args**: RCX, RDX, R8, R9, then stack (right-to-left)
- **Float args**: XMM0, XMM1, XMM2, XMM3, then stack
- **Shadow space**: 32 bytes allocated on stack for register parameters
- **Return value**: RAX register
- **Stack alignment**: 16-byte boundary maintained

### Memory Management

- **Page-based**: 4KB page granularity with automatic fault handling
- **Lazy loading**: Memory mapped from minidump on first access
- **Permission tracking**: Separate read/write/execute permissions per page

## Argument Types

### Integer Arguments
```rust
ArgumentType::Integer(42)
```

### Pointer Arguments  
```rust
ArgumentType::Pointer(0x7ff000000)
```

### Float Arguments
```rust
ArgumentType::Float(3.14159)
```

### Command Line Format
- Integers: `42`
- Pointers: `ptr:0x7ff000000` or `ptr:123456` 
- Floats: `3.14` (any number with decimal point)

## Instruction Tracing

When enabled with `--trace` flag or `executor.enable_tracing(true)`, the framework provides:

- **Full Disassembly**: Each instruction decoded and displayed in Intel syntax
- **Register State**: Key registers (RAX, RCX, RDX, RSP, etc.) shown for each instruction
- **Dynamic Register Display**: Additional registers shown when used by instructions
- **Instruction Counter**: Sequential numbering of executed instructions
- **Execution Summary**: Total instruction count at completion

Example trace output:
```
[000001] 0x0000000140001000: push rbp                       | RAX=0000000000000000 RCX=000000000000002a RDX=00007ff000000000
[000002] 0x0000000140001001: mov rbp, rsp                   | RAX=0000000000000000 RCX=000000000000002a RDX=00007ff000000000
                                                           | RSP=00007ffeffffff70 RBP=00007ffeffffff78
[000003] 0x0000000140001004: sub rsp, 20h                   | RAX=0000000000000000 RCX=000000000000002a RDX=00007ff000000000
                                                           | RSP=00007ffeffffff70 RBP=00007ffeffffff70
```

## Dependencies

- **amd64-emu**: x86-64 CPU emulation engine
- **minidump**: Windows minidump parsing
- **memmap2**: Memory-mapped file I/O for efficient minidump access
- **iced-x86**: Fast and correct x86/x64 disassembler
- **anyhow**: Error handling
- **thiserror**: Custom error types

## Building

```bash
cargo build --release
```

## Safety Considerations

This framework is designed for **defensive security analysis only**:

- Analyze crash dumps and malware samples
- Reverse engineer function behavior  
- Extract runtime information from dumps
- Develop detection signatures

**Do not use for**:
- Creating offensive tools
- Developing malware
- Bypassing security controls

## Limitations

- Windows x64 minidumps only
- Limited to functions using standard calling convention
- No support for complex C++ features (vtables, exceptions)
- Maximum 100,000 instruction execution limit

## License

This project is provided for educational and defensive security research purposes.