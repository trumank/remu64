use remu64::hooks::HookManager;
use remu64::memory::{MemoryTrait, Permission};
use remu64::{Engine, EngineMode, Register};

#[derive(Clone)]
struct InterruptTracker {
    interrupts: Vec<(u64, u64)>,         // (interrupt_number, address)
    syscalls: Vec<(u64, u64, u64, u64)>, // (syscall_num, rdi, rsi, rdx)
}

impl InterruptTracker {
    fn new() -> Self {
        Self {
            interrupts: Vec::new(),
            syscalls: Vec::new(),
        }
    }
}

impl<M: MemoryTrait> HookManager<M> for InterruptTracker {
    fn on_interrupt(
        &mut self,
        engine: &mut Engine<M>,
        intno: u64,
        _size: usize,
    ) -> remu64::error::Result<()> {
        let address = engine.reg_read(Register::RIP);

        // Track the interrupt
        self.interrupts.push((intno, address));

        // For SYSCALL (interrupt 0x80), also track the syscall parameters
        if intno == 0x80 {
            let syscall_num = engine.reg_read(Register::RAX);
            let arg1 = engine.reg_read(Register::RDI);
            let arg2 = engine.reg_read(Register::RSI);
            let arg3 = engine.reg_read(Register::RDX);
            self.syscalls.push((syscall_num, arg1, arg2, arg3));
        }

        Ok(())
    }
}

#[test]
fn test_int_instruction() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // INT 0x80 - Linux system call interrupt
    let code = vec![
        0xcd, 0x80, // int 0x80
        0x90, // nop
    ];

    let base = 0x1000;
    engine
        .memory
        .map(
            base,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();
    engine.memory.write(base, &code).unwrap();

    let mut tracker = InterruptTracker::new();
    engine
        .emu_start_with_hooks(base, base + code.len() as u64, 0, 0, &mut tracker)
        .unwrap();

    // Check that interrupt was triggered
    assert_eq!(tracker.interrupts.len(), 1);
    assert_eq!(tracker.interrupts[0].0, 0x80); // Interrupt number
}

#[test]
fn test_int3_breakpoint() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // INT3 - Breakpoint instruction
    let code = vec![
        0xcc, // int3
        0x90, // nop
    ];

    let base = 0x1000;
    engine
        .memory
        .map(
            base,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();
    engine.memory.write(base, &code).unwrap();

    let mut tracker = InterruptTracker::new();
    engine
        .emu_start_with_hooks(base, base + code.len() as u64, 0, 0, &mut tracker)
        .unwrap();

    // Check that INT3 triggered interrupt 3
    assert_eq!(tracker.interrupts.len(), 1);
    assert_eq!(tracker.interrupts[0].0, 3); // Interrupt 3 for breakpoint
}

// Note: INTO (0xCE) is not valid in 64-bit mode, only in 32-bit mode
// We'll skip these tests for 64-bit mode

#[test]
fn test_syscall() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // SYSCALL - Fast system call
    // Set up a write syscall (1 on Linux)
    let code = vec![
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1 (sys_write)
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1 (stdout)
        0x48, 0xc7, 0xc6, 0x00, 0x20, 0x00, 0x00, // mov rsi, 0x2000 (buffer address)
        0x48, 0xc7, 0xc2, 0x0c, 0x00, 0x00, 0x00, // mov rdx, 12 (length)
        0x0f, 0x05, // syscall
        0x90, // nop
    ];

    let base = 0x1000;
    engine
        .memory
        .map(
            base,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();
    engine.memory.write(base, &code).unwrap();

    let mut tracker = InterruptTracker::new();
    let initial_rip = base;
    engine
        .emu_start_with_hooks(initial_rip, base + code.len() as u64, 0, 0, &mut tracker)
        .unwrap();

    // Check that SYSCALL was triggered
    assert_eq!(tracker.interrupts.len(), 1);
    assert_eq!(tracker.interrupts[0].0, 0x80); // We use 0x80 for syscall tracking

    // Check syscall parameters
    assert_eq!(tracker.syscalls.len(), 1);
    assert_eq!(tracker.syscalls[0].0, 1); // sys_write
    assert_eq!(tracker.syscalls[0].1, 1); // stdout
    assert_eq!(tracker.syscalls[0].2, 0x2000); // buffer
    assert_eq!(tracker.syscalls[0].3, 12); // length

    // Check that RCX contains the return address (next instruction after syscall)
    let rcx = engine.reg_read(Register::RCX);
    // SYSCALL is 2 bytes (0x0f 0x05), so next instruction is at base + all setup code + 2
    let expected_return = base + code.len() as u64 - 1; // Points to the nop after syscall
    assert_eq!(rcx, expected_return);

    // R11 should contain RFLAGS (even if all flags are clear, bit 1 is always set)
}

#[test]
fn test_multiple_interrupts() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Multiple different interrupts in sequence
    let code = vec![
        0xcd, 0x21, // int 0x21 (DOS interrupt)
        0xcd, 0x80, // int 0x80 (Linux syscall)
        0xcc, // int3 (breakpoint)
        0x90, // nop
    ];

    let base = 0x1000;
    engine
        .memory
        .map(
            base,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();
    engine.memory.write(base, &code).unwrap();

    let mut tracker = InterruptTracker::new();
    engine
        .emu_start_with_hooks(base, base + code.len() as u64, 0, 0, &mut tracker)
        .unwrap();

    // Check all interrupts were triggered in order
    assert_eq!(tracker.interrupts.len(), 3);
    assert_eq!(tracker.interrupts[0].0, 0x21);
    assert_eq!(tracker.interrupts[1].0, 0x80);
    assert_eq!(tracker.interrupts[2].0, 3);
}

#[test]
fn test_int_with_parameter() {
    let mut engine = Engine::new(EngineMode::Mode64);

    // Test various interrupt numbers
    let code = vec![
        0xcd, 0x00, // int 0x00 (divide error)
        0xcd, 0x01, // int 0x01 (debug)
        0xcd, 0x0d, // int 0x0d (general protection fault)
        0xcd, 0xff, // int 0xff (max interrupt number)
        0x90, // nop
    ];

    let base = 0x1000;
    engine
        .memory
        .map(
            base,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();
    engine.memory.write(base, &code).unwrap();

    let mut tracker = InterruptTracker::new();
    engine
        .emu_start_with_hooks(base, base + code.len() as u64, 0, 0, &mut tracker)
        .unwrap();

    // Check all interrupts with correct numbers
    assert_eq!(tracker.interrupts.len(), 4);
    assert_eq!(tracker.interrupts[0].0, 0x00);
    assert_eq!(tracker.interrupts[1].0, 0x01);
    assert_eq!(tracker.interrupts[2].0, 0x0d);
    assert_eq!(tracker.interrupts[3].0, 0xff);
}
