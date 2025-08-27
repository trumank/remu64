use crate::engine::ExecutionContext;
use crate::error::Result;
use crate::memory::MemoryTrait;
use crate::{Flags, HookManager, Register};
use iced_x86::Instruction;

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_movsb(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSB: Move Byte from [RSI] to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;
        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Move byte from [RSI] to [RDI]
            let byte = self.read_memory_sized(rsi, 1)? as u8;
            self.write_memory_sized(rdi, byte as u64, 1)?;

            // Update RSI and RDI based on direction flag
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };

            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_stosb(&mut self, inst: &Instruction) -> Result<()> {
        // STOSB: Store AL to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let al_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFF) as u8;
        let mut remaining = count;

        while remaining > 0 {
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Store AL to [RDI]
            self.write_memory_sized(rdi, al_value as u64, 1)?;

            // Update RDI based on direction flag
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };

            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_lodsb(&mut self, inst: &Instruction) -> Result<()> {
        // LODSB: Load byte from [RSI] into AL
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;

        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);

            // Load byte from [RSI] into AL
            let byte = self.read_memory_sized(rsi, 1)? as u8;
            let rax = self.engine.cpu.read_reg(Register::RAX);
            self.engine
                .cpu
                .write_reg(Register::RAX, (rax & !0xFF) | (byte as u64));

            // Update RSI based on direction flag
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };

            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_scasb(&mut self, inst: &Instruction) -> Result<()> {
        // SCASB: Compare AL with [RDI]
        let al_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFF) as u8;

        if inst.has_repne_prefix() {
            // REPNE SCASB: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);
                let byte = self.read_memory_sized(rdi, 1)? as u8;

                // Compare AL with [RDI]
                self.update_flags_arithmetic_iced(
                    al_value as u64,
                    byte as u64,
                    (al_value as i16 - byte as i16) as u64,
                    true,
                    inst,
                )?;

                // Update RDI and RCX
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -1i64 as u64 } else { 1 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RCX, self.engine.cpu.read_reg(Register::RCX) - 1);

                // Stop if equal (ZF set)
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE SCASB: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);
                let byte = self.read_memory_sized(rdi, 1)? as u8;

                // Compare AL with [RDI]
                self.update_flags_arithmetic_iced(
                    al_value as u64,
                    byte as u64,
                    (al_value as i16 - byte as i16) as u64,
                    true,
                    inst,
                )?;

                // Update RDI and RCX
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -1i64 as u64 } else { 1 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RCX, self.engine.cpu.read_reg(Register::RCX) - 1);

                // Stop if not equal (ZF clear)
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single SCASB
            let rdi = self.engine.cpu.read_reg(Register::RDI);
            let byte = self.read_memory_sized(rdi, 1)? as u8;

            // Compare AL with [RDI]
            self.update_flags_arithmetic_iced(
                al_value as u64,
                byte as u64,
                (al_value as i16 - byte as i16) as u64,
                true,
                inst,
            )?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    pub(crate) fn execute_cmpsb(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSB: Compare bytes at [RSI] and [RDI]
        if inst.has_repne_prefix() {
            // REPNE CMPSB: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);
                let byte1 = self.read_memory_sized(rsi, 1)? as u8;
                let byte2 = self.read_memory_sized(rdi, 1)? as u8;

                // Compare bytes
                self.update_flags_arithmetic_iced(
                    byte1 as u64,
                    byte2 as u64,
                    (byte1 as i16 - byte2 as i16) as u64,
                    true,
                    inst,
                )?;

                // Update RSI, RDI and RCX
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -1i64 as u64 } else { 1 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RCX, self.engine.cpu.read_reg(Register::RCX) - 1);

                // Stop if equal (ZF set)
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE CMPSB: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);
                let byte1 = self.read_memory_sized(rsi, 1)? as u8;
                let byte2 = self.read_memory_sized(rdi, 1)? as u8;

                // Compare bytes
                self.update_flags_arithmetic_iced(
                    byte1 as u64,
                    byte2 as u64,
                    (byte1 as i16 - byte2 as i16) as u64,
                    true,
                    inst,
                )?;

                // Update RSI, RDI and RCX
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -1i64 as u64 } else { 1 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RCX, self.engine.cpu.read_reg(Register::RCX) - 1);

                // Stop if not equal (ZF clear)
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single CMPSB
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);
            let byte1 = self.read_memory_sized(rsi, 1)? as u8;
            let byte2 = self.read_memory_sized(rdi, 1)? as u8;

            // Compare bytes
            self.update_flags_arithmetic_iced(
                byte1 as u64,
                byte2 as u64,
                (byte1 as i16 - byte2 as i16) as u64,
                true,
                inst,
            )?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -1i64 as u64 } else { 1 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    pub(crate) fn execute_movsw(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSW: Move Word from [RSI] to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;
        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Move word from [RSI] to [RDI]
            let word = self.read_memory_sized(rsi, 2)? as u16;
            self.write_memory_sized(rdi, word as u64, 2)?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_movsd_string(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSD: Move Doubleword from [RSI] to [RDI] (string operation, not SSE)
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;
        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Move dword from [RSI] to [RDI]
            let dword = self.read_memory_sized(rsi, 4)? as u32;
            self.write_memory_sized(rdi, dword as u64, 4)?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_movsq(&mut self, inst: &Instruction) -> Result<()> {
        // MOVSQ: Move Quadword from [RSI] to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;
        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Move qword from [RSI] to [RDI]
            let qword = self.read_memory_sized(rsi, 8)?;
            self.write_memory_sized(rdi, qword, 8)?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_stosw(&mut self, inst: &Instruction) -> Result<()> {
        // STOSW: Store AX to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let ax_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFF) as u16;
        let mut remaining = count;

        while remaining > 0 {
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Store AX to [RDI]
            self.write_memory_sized(rdi, ax_value as u64, 2)?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_stosd(&mut self, inst: &Instruction) -> Result<()> {
        // STOSD: Store EAX to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let eax_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFFFFFF) as u32;
        let mut remaining = count;

        while remaining > 0 {
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Store EAX to [RDI]
            self.write_memory_sized(rdi, eax_value as u64, 4)?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_stosq(&mut self, inst: &Instruction) -> Result<()> {
        // STOSQ: Store RAX to [RDI]
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let rax_value = self.engine.cpu.read_reg(Register::RAX);
        let mut remaining = count;

        while remaining > 0 {
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Store RAX to [RDI]
            self.write_memory_sized(rdi, rax_value, 8)?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_lodsw(&mut self, inst: &Instruction) -> Result<()> {
        // LODSW: Load word from [RSI] into AX
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;

        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);

            // Load word from [RSI] into AX
            let word = self.read_memory_sized(rsi, 2)? as u16;
            let rax = self.engine.cpu.read_reg(Register::RAX);
            self.engine
                .cpu
                .write_reg(Register::RAX, (rax & !0xFFFF) | (word as u64));

            // Update RSI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_lodsd(&mut self, inst: &Instruction) -> Result<()> {
        // LODSD: Load doubleword from [RSI] into EAX
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;

        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);

            // Load dword from [RSI] into EAX
            let dword = self.read_memory_sized(rsi, 4)? as u32;
            let rax = self.engine.cpu.read_reg(Register::RAX);
            self.engine
                .cpu
                .write_reg(Register::RAX, (rax & !0xFFFFFFFF) | (dword as u64));

            // Update RSI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_lodsq(&mut self, inst: &Instruction) -> Result<()> {
        // LODSQ: Load quadword from [RSI] into RAX
        let count = if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.read_reg(Register::RCX)
        } else {
            1
        };

        let mut remaining = count;

        while remaining > 0 {
            let rsi = self.engine.cpu.read_reg(Register::RSI);

            // Load qword from [RSI] into RAX
            let qword = self.read_memory_sized(rsi, 8)?;
            self.engine.cpu.write_reg(Register::RAX, qword);

            // Update RSI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));

            remaining -= 1;
        }

        if inst.has_rep_prefix() || inst.has_repne_prefix() {
            self.engine.cpu.write_reg(Register::RCX, 0);
        }

        Ok(())
    }

    pub(crate) fn execute_scasw(&mut self, inst: &Instruction) -> Result<()> {
        // SCASW: Scan Word - Compare AX with word at [RDI]
        let ax_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFF) as u16;

        if inst.has_repne_prefix() {
            // REPNE SCASW: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare AX with word at [RDI]
                let word = self.read_memory_sized(rdi, 2)? as u16;

                // Update flags
                self.update_flags_arithmetic_iced(
                    ax_value as u64,
                    word as u64,
                    (ax_value as i32 - word as i32) as u64,
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -2i64 as u64 } else { 2 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE SCASW: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare AX with word at [RDI]
                let word = self.read_memory_sized(rdi, 2)? as u16;

                // Update flags
                self.update_flags_arithmetic_iced(
                    ax_value as u64,
                    word as u64,
                    (ax_value as i32 - word as i32) as u64,
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -2i64 as u64 } else { 2 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single SCASW
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare AX with word at [RDI]
            let word = self.read_memory_sized(rdi, 2)? as u16;

            // Update flags
            self.update_flags_arithmetic_iced(
                ax_value as u64,
                word as u64,
                (ax_value as i32 - word as i32) as u64,
                true,
                inst,
            )?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    pub(crate) fn execute_scasd(&mut self, inst: &Instruction) -> Result<()> {
        // SCASD: Scan Doubleword - Compare EAX with dword at [RDI]
        let eax_value = (self.engine.cpu.read_reg(Register::RAX) & 0xFFFFFFFF) as u32;

        if inst.has_repne_prefix() {
            // REPNE SCASD: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare EAX with dword at [RDI]
                let dword = self.read_memory_sized(rdi, 4)? as u32;

                // Update flags
                self.update_flags_arithmetic_iced(
                    eax_value as u64,
                    dword as u64,
                    (eax_value as i64 - dword as i64) as u64,
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -4i64 as u64 } else { 4 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE SCASD: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare EAX with dword at [RDI]
                let dword = self.read_memory_sized(rdi, 4)? as u32;

                // Update flags
                self.update_flags_arithmetic_iced(
                    eax_value as u64,
                    dword as u64,
                    (eax_value as i64 - dword as i64) as u64,
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -4i64 as u64 } else { 4 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single SCASD
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare EAX with dword at [RDI]
            let dword = self.read_memory_sized(rdi, 4)? as u32;

            // Update flags
            self.update_flags_arithmetic_iced(
                eax_value as u64,
                dword as u64,
                (eax_value as i64 - dword as i64) as u64,
                true,
                inst,
            )?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    pub(crate) fn execute_scasq(&mut self, inst: &Instruction) -> Result<()> {
        // SCASQ: Scan Quadword - Compare RAX with qword at [RDI]
        let rax_value = self.engine.cpu.read_reg(Register::RAX);

        if inst.has_repne_prefix() {
            // REPNE SCASQ: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare RAX with qword at [RDI]
                let qword = self.read_memory_sized(rdi, 8)?;

                // Update flags
                self.update_flags_arithmetic_iced(
                    rax_value,
                    qword,
                    rax_value.wrapping_sub(qword),
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -8i64 as u64 } else { 8 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE SCASQ: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare RAX with qword at [RDI]
                let qword = self.read_memory_sized(rdi, 8)?;

                // Update flags
                self.update_flags_arithmetic_iced(
                    rax_value,
                    qword,
                    rax_value.wrapping_sub(qword),
                    true,
                    inst,
                )?;

                // Update RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -8i64 as u64 } else { 8 };
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single SCASQ
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare RAX with qword at [RDI]
            let qword = self.read_memory_sized(rdi, 8)?;

            // Update flags
            self.update_flags_arithmetic_iced(
                rax_value,
                qword,
                rax_value.wrapping_sub(qword),
                true,
                inst,
            )?;

            // Update RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    pub(crate) fn execute_cmpsw(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSW: Compare words at [RSI] and [RDI]
        if inst.has_repne_prefix() {
            // REPNE CMPSW: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare words
                let word1 = self.read_memory_sized(rsi, 2)? as u16;
                let word2 = self.read_memory_sized(rdi, 2)? as u16;

                // Update flags
                self.update_flags_arithmetic_iced(
                    word1 as u64,
                    word2 as u64,
                    (word1 as i32 - word2 as i32) as u64,
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -2i64 as u64 } else { 2 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE CMPSW: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare words
                let word1 = self.read_memory_sized(rsi, 2)? as u16;
                let word2 = self.read_memory_sized(rdi, 2)? as u16;

                // Update flags
                self.update_flags_arithmetic_iced(
                    word1 as u64,
                    word2 as u64,
                    (word1 as i32 - word2 as i32) as u64,
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -2i64 as u64 } else { 2 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single CMPSW
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare words
            let word1 = self.read_memory_sized(rsi, 2)? as u16;
            let word2 = self.read_memory_sized(rdi, 2)? as u16;

            // Update flags
            self.update_flags_arithmetic_iced(
                word1 as u64,
                word2 as u64,
                (word1 as i32 - word2 as i32) as u64,
                true,
                inst,
            )?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -2i64 as u64 } else { 2 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    pub(crate) fn execute_cmpsd_string(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSD: Compare doublewords at [RSI] and [RDI] (string operation, not SSE)
        if inst.has_repne_prefix() {
            // REPNE CMPSD: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare dwords
                let dword1 = self.read_memory_sized(rsi, 4)? as u32;
                let dword2 = self.read_memory_sized(rdi, 4)? as u32;

                // Update flags
                self.update_flags_arithmetic_iced(
                    dword1 as u64,
                    dword2 as u64,
                    (dword1 as i64 - dword2 as i64) as u64,
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -4i64 as u64 } else { 4 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE CMPSD: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare dwords
                let dword1 = self.read_memory_sized(rsi, 4)? as u32;
                let dword2 = self.read_memory_sized(rdi, 4)? as u32;

                // Update flags
                self.update_flags_arithmetic_iced(
                    dword1 as u64,
                    dword2 as u64,
                    (dword1 as i64 - dword2 as i64) as u64,
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -4i64 as u64 } else { 4 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single CMPSD
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare dwords
            let dword1 = self.read_memory_sized(rsi, 4)? as u32;
            let dword2 = self.read_memory_sized(rdi, 4)? as u32;

            // Update flags
            self.update_flags_arithmetic_iced(
                dword1 as u64,
                dword2 as u64,
                (dword1 as i64 - dword2 as i64) as u64,
                true,
                inst,
            )?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -4i64 as u64 } else { 4 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    pub(crate) fn execute_cmpsq(&mut self, inst: &Instruction) -> Result<()> {
        // CMPSQ: Compare quadwords at [RSI] and [RDI]
        if inst.has_repne_prefix() {
            // REPNE CMPSQ: Repeat while not equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare qwords
                let qword1 = self.read_memory_sized(rsi, 8)?;
                let qword2 = self.read_memory_sized(rdi, 8)?;

                // Update flags
                self.update_flags_arithmetic_iced(
                    qword1,
                    qword2,
                    qword1.wrapping_sub(qword2),
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -8i64 as u64 } else { 8 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else if inst.has_rep_prefix() {
            // REPE CMPSQ: Repeat while equal and RCX > 0
            while self.engine.cpu.read_reg(Register::RCX) > 0 {
                let rsi = self.engine.cpu.read_reg(Register::RSI);
                let rdi = self.engine.cpu.read_reg(Register::RDI);

                // Compare qwords
                let qword1 = self.read_memory_sized(rsi, 8)?;
                let qword2 = self.read_memory_sized(rdi, 8)?;

                // Update flags
                self.update_flags_arithmetic_iced(
                    qword1,
                    qword2,
                    qword1.wrapping_sub(qword2),
                    true,
                    inst,
                )?;

                // Update RSI and RDI
                let df = self.engine.cpu.rflags.contains(Flags::DF);
                let increment = if df { -8i64 as u64 } else { 8 };
                self.engine
                    .cpu
                    .write_reg(Register::RSI, rsi.wrapping_add(increment));
                self.engine
                    .cpu
                    .write_reg(Register::RDI, rdi.wrapping_add(increment));

                // Decrement RCX
                let rcx = self.engine.cpu.read_reg(Register::RCX);
                self.engine.cpu.write_reg(Register::RCX, rcx - 1);

                // Check ZF for termination
                if !self.engine.cpu.rflags.contains(Flags::ZF) {
                    break;
                }
            }
        } else {
            // Single CMPSQ
            let rsi = self.engine.cpu.read_reg(Register::RSI);
            let rdi = self.engine.cpu.read_reg(Register::RDI);

            // Compare qwords
            let qword1 = self.read_memory_sized(rsi, 8)?;
            let qword2 = self.read_memory_sized(rdi, 8)?;

            // Update flags
            self.update_flags_arithmetic_iced(
                qword1,
                qword2,
                qword1.wrapping_sub(qword2),
                true,
                inst,
            )?;

            // Update RSI and RDI
            let df = self.engine.cpu.rflags.contains(Flags::DF);
            let increment = if df { -8i64 as u64 } else { 8 };
            self.engine
                .cpu
                .write_reg(Register::RSI, rsi.wrapping_add(increment));
            self.engine
                .cpu
                .write_reg(Register::RDI, rdi.wrapping_add(increment));
        }

        Ok(())
    }

    pub(crate) fn execute_pcmpistri(&mut self, inst: &Instruction) -> Result<()> {
        // PCMPISTRI: Packed Compare Implicit Length Strings, Return Index
        // Compares two null-terminated strings and returns the index of first matching/non-matching character
        // Format: PCMPISTRI xmm1, xmm2/m128, imm8

        use crate::error::EmulatorError;
        use iced_x86::OpKind;

        if inst.op_count() != 3 {
            return Err(EmulatorError::UnsupportedInstruction(
                "PCMPISTRI requires exactly 3 operands".to_string(),
            ));
        }

        let src1_reg = self.convert_register(inst.op_register(0))?;
        let src1_data = self.engine.cpu.read_xmm(src1_reg);

        let src2_data = match inst.op_kind(1) {
            OpKind::Register => {
                let src2_reg = self.convert_register(inst.op_register(1))?;
                self.engine.cpu.read_xmm(src2_reg)
            }
            OpKind::Memory => {
                let addr = self.calculate_memory_address(inst, 1)?;
                self.read_memory_128(addr)?
            }
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(
                    "Invalid PCMPISTRI operand types".to_string(),
                ));
            }
        };

        let control = inst.immediate8();

        // Extract strings from XMM registers (16 bytes each)
        let mut str1 = Vec::new();
        let mut str2 = Vec::new();

        // Convert 128-bit values to byte arrays
        for i in 0..16 {
            let byte1 = ((src1_data >> (i * 8)) & 0xFF) as u8;
            let byte2 = ((src2_data >> (i * 8)) & 0xFF) as u8;

            str1.push(byte1);
            str2.push(byte2);

            // For implicit length strings, stop at null terminator
            if byte1 == 0 {
                break;
            }
        }

        for i in 0..16 {
            let byte2 = ((src2_data >> (i * 8)) & 0xFF) as u8;
            if i >= str2.len() {
                str2.push(byte2);
            }
            if byte2 == 0 {
                str2.truncate(i + 1);
                break;
            }
        }

        // Perform comparison based on control byte
        let result_index = match control & 0x0F {
            0x0C => {
                // Equal ordered: Find first character in str1 that matches any character in str2
                let mut index = str1.len() as u32;
                for (i, &ch1) in str1.iter().enumerate() {
                    if ch1 == 0 {
                        break;
                    }
                    for &ch2 in &str2 {
                        if ch2 == 0 {
                            break;
                        }
                        if ch1 == ch2 {
                            index = i as u32;
                            break;
                        }
                    }
                    if index != str1.len() as u32 {
                        break;
                    }
                }
                if index == str1.len() as u32 {
                    str1.len() as u32
                } else {
                    index
                }
            }
            0x0D => {
                // Ranges: More complex range-based comparison (simplified implementation)
                let mut index = str1.len() as u32;
                for (i, &ch1) in str1.iter().enumerate() {
                    if ch1 == 0 {
                        break;
                    }
                    // Simplified: just check if character is in reasonable ASCII range
                    if ch1 >= 0x20 && ch1 <= 0x7E {
                        for &ch2 in &str2 {
                            if ch2 == 0 {
                                break;
                            }
                            if ch1 == ch2 {
                                index = i as u32;
                                break;
                            }
                        }
                    }
                    if index != str1.len() as u32 {
                        break;
                    }
                }
                if index == str1.len() as u32 {
                    str1.len() as u32
                } else {
                    index
                }
            }
            _ => {
                // Default: simple character-by-character comparison
                let mut index = 0;
                let min_len = std::cmp::min(str1.len(), str2.len());
                for i in 0..min_len {
                    if str1[i] == 0 || str2[i] == 0 {
                        break;
                    }
                    if str1[i] != str2[i] {
                        index = i as u32;
                        break;
                    }
                    index = (i + 1) as u32;
                }
                index
            }
        };

        // Store result in ECX register
        self.engine
            .cpu
            .write_reg(Register::RCX, result_index as u64);

        // Set flags based on result
        if result_index < 16 {
            self.engine.cpu.rflags.insert(Flags::CF);
        } else {
            self.engine.cpu.rflags.remove(Flags::CF);
        }

        if str1.is_empty() || str1[0] == 0 {
            self.engine.cpu.rflags.insert(Flags::ZF);
        } else {
            self.engine.cpu.rflags.remove(Flags::ZF);
        }

        if str2.is_empty() || str2[0] == 0 {
            self.engine.cpu.rflags.insert(Flags::SF);
        } else {
            self.engine.cpu.rflags.remove(Flags::SF);
        }

        // Clear other flags
        self.engine.cpu.rflags.remove(Flags::OF);
        self.engine.cpu.rflags.remove(Flags::AF);
        self.engine.cpu.rflags.remove(Flags::PF);

        Ok(())
    }
}
