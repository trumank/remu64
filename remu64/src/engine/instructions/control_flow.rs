use crate::engine::ExecutionContext;
use crate::error::{EmulatorError, Result};
use crate::memory::MemoryTrait;
use crate::{EngineMode, Flags, HookManager, Register};
use iced_x86::{Instruction, OpKind};

impl<H: HookManager<M>, M: MemoryTrait> ExecutionContext<'_, H, M> {
    pub(crate) fn execute_call(&mut self, inst: &Instruction) -> Result<()> {
        // Push return address onto stack
        let return_addr = inst.next_ip();
        let new_rsp = self.engine.cpu.read_reg(Register::RSP).wrapping_sub(8);
        self.engine.cpu.write_reg(Register::RSP, new_rsp);
        self.write_memory_sized(new_rsp, return_addr, 8)?;

        // Get target address
        let target = match inst.op_kind(0) {
            OpKind::NearBranch64 => inst.near_branch64(),
            OpKind::Memory => self.read_operand(inst, 0)?,
            OpKind::Register => self.read_operand(inst, 0)?,
            _ => {
                return Err(EmulatorError::UnsupportedInstruction(format!(
                    "Unsupported call target: {:?}",
                    inst.op_kind(0)
                )));
            }
        };

        // Update RIP to target
        self.engine.cpu.write_reg(Register::RIP, target);
        Ok(())
    }

    pub(crate) fn execute_jcc(&mut self, inst: &Instruction, condition: bool) -> Result<()> {
        if condition {
            let target = self.read_operand(inst, 0)?;
            self.engine.cpu.write_reg(Register::RIP, target);
        }
        Ok(())
    }

    pub(crate) fn execute_jmp(&mut self, inst: &Instruction) -> Result<()> {
        let target = self.read_operand(inst, 0)?;
        self.engine.cpu.write_reg(Register::RIP, target);
        Ok(())
    }

    pub(crate) fn execute_ret(&mut self, inst: &Instruction) -> Result<()> {
        // Pop return address from stack
        let rsp = self.engine.cpu.read_reg(Register::RSP);
        let return_addr = self.read_memory_sized(rsp, 8)?;
        let new_rsp = rsp + 8;

        // Handle ret with immediate (ret imm16) - adjust stack pointer by additional amount
        if inst.op_count() > 0 {
            let imm = self.read_operand(inst, 0)?;
            self.engine.cpu.write_reg(Register::RSP, new_rsp + imm);
        } else {
            self.engine.cpu.write_reg(Register::RSP, new_rsp);
        }

        // Jump to return address
        self.engine.cpu.write_reg(Register::RIP, return_addr);
        Ok(())
    }

    pub(crate) fn execute_loop(&mut self, inst: &Instruction) -> Result<()> {
        // LOOP: Decrement RCX/ECX and jump if not zero
        // Get address mode to determine if using RCX or ECX
        let address_size = match self.engine.mode {
            EngineMode::Mode64 => 8, // Use RCX in 64-bit mode
            EngineMode::Mode32 => 4, // Use ECX in 32-bit mode
            EngineMode::Mode16 => 2, // Use CX in 16-bit mode
        };

        let counter_reg = Register::RCX;
        let counter_value = self.engine.cpu.read_reg(counter_reg);

        // Decrement counter based on address size
        let new_counter = match address_size {
            8 => counter_value.wrapping_sub(1),
            4 => {
                (counter_value & 0xFFFFFFFF00000000)
                    | ((counter_value as u32).wrapping_sub(1) as u64)
            }
            2 => {
                (counter_value & 0xFFFFFFFFFFFF0000)
                    | ((counter_value as u16).wrapping_sub(1) as u64)
            }
            _ => unreachable!(),
        };

        self.engine.cpu.write_reg(counter_reg, new_counter);

        // Check if counter is zero (based on address size)
        let counter_zero = match address_size {
            8 => new_counter == 0,
            4 => (new_counter as u32) == 0,
            2 => (new_counter as u16) == 0,
            _ => unreachable!(),
        };

        // Jump if counter is not zero
        if !counter_zero {
            let target_address = inst.near_branch_target();
            self.engine.cpu.rip = target_address;
        }

        Ok(())
    }

    pub(crate) fn execute_loope(&mut self, inst: &Instruction) -> Result<()> {
        // LOOPE: Decrement RCX/ECX and jump if not zero AND ZF=1
        let address_size = match self.engine.mode {
            EngineMode::Mode64 => 8,
            EngineMode::Mode32 => 4,
            EngineMode::Mode16 => 2,
        };

        let counter_reg = Register::RCX;
        let counter_value = self.engine.cpu.read_reg(counter_reg);

        // Decrement counter
        let new_counter = match address_size {
            8 => counter_value.wrapping_sub(1),
            4 => {
                (counter_value & 0xFFFFFFFF00000000)
                    | ((counter_value as u32).wrapping_sub(1) as u64)
            }
            2 => {
                (counter_value & 0xFFFFFFFFFFFF0000)
                    | ((counter_value as u16).wrapping_sub(1) as u64)
            }
            _ => unreachable!(),
        };

        self.engine.cpu.write_reg(counter_reg, new_counter);

        // Check conditions
        let counter_zero = match address_size {
            8 => new_counter == 0,
            4 => (new_counter as u32) == 0,
            2 => (new_counter as u16) == 0,
            _ => unreachable!(),
        };

        let zero_flag_set = self.engine.cpu.rflags.contains(Flags::ZF);

        // Jump if counter is not zero AND zero flag is set
        if !counter_zero && zero_flag_set {
            let target_address = inst.near_branch_target();
            self.engine.cpu.rip = target_address;
        }

        Ok(())
    }

    pub(crate) fn execute_loopne(&mut self, inst: &Instruction) -> Result<()> {
        // LOOPNE: Decrement RCX/ECX and jump if not zero AND ZF=0
        let address_size = match self.engine.mode {
            EngineMode::Mode64 => 8,
            EngineMode::Mode32 => 4,
            EngineMode::Mode16 => 2,
        };

        let counter_reg = Register::RCX;
        let counter_value = self.engine.cpu.read_reg(counter_reg);

        // Decrement counter
        let new_counter = match address_size {
            8 => counter_value.wrapping_sub(1),
            4 => {
                (counter_value & 0xFFFFFFFF00000000)
                    | ((counter_value as u32).wrapping_sub(1) as u64)
            }
            2 => {
                (counter_value & 0xFFFFFFFFFFFF0000)
                    | ((counter_value as u16).wrapping_sub(1) as u64)
            }
            _ => unreachable!(),
        };

        self.engine.cpu.write_reg(counter_reg, new_counter);

        // Check conditions
        let counter_zero = match address_size {
            8 => new_counter == 0,
            4 => (new_counter as u32) == 0,
            2 => (new_counter as u16) == 0,
            _ => unreachable!(),
        };

        let zero_flag_clear = !self.engine.cpu.rflags.contains(Flags::ZF);

        // Jump if counter is not zero AND zero flag is clear
        if !counter_zero && zero_flag_clear {
            let target_address = inst.near_branch_target();
            self.engine.cpu.rip = target_address;
        }

        Ok(())
    }

    pub(crate) fn execute_enter(&mut self, inst: &Instruction) -> Result<()> {
        // ENTER: Create stack frame for procedure
        // Enter imm16, imm8
        // imm16 = size of stack frame, imm8 = nesting level (we'll only implement level 0)

        // Get operands - for ENTER, operands are immediates
        let frame_size = inst.immediate(0);
        let nesting_level = inst.immediate(1) as u8;

        if nesting_level != 0 {
            return Err(EmulatorError::UnsupportedInstruction(format!(
                "ENTER with nesting level {} not supported",
                nesting_level
            )));
        }

        // Push RBP
        let rbp_value = self.engine.cpu.read_reg(Register::RBP);
        let rsp_value = self.engine.cpu.read_reg(Register::RSP);

        // Decrement RSP and store RBP
        let new_rsp = rsp_value.wrapping_sub(8);
        // Write 64-bit value to memory
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&rbp_value.to_le_bytes());
        self.engine.memory.write(new_rsp, &bytes)?;
        self.engine.cpu.write_reg(Register::RSP, new_rsp);

        // Set RBP to current RSP
        self.engine.cpu.write_reg(Register::RBP, new_rsp);

        // Allocate space for local variables (subtract frame_size from RSP)
        let final_rsp = new_rsp.wrapping_sub(frame_size);
        self.engine.cpu.write_reg(Register::RSP, final_rsp);

        Ok(())
    }

    pub(crate) fn execute_leave(&mut self, _inst: &Instruction) -> Result<()> {
        // LEAVE: Destroy stack frame before returning
        // Equivalent to: MOV RSP, RBP; POP RBP

        // Set RSP to RBP
        let rbp_value = self.engine.cpu.read_reg(Register::RBP);
        self.engine.cpu.write_reg(Register::RSP, rbp_value);

        // Pop RBP
        // Read 64-bit value from memory
        let mut bytes = [0u8; 8];
        self.engine.memory.read(rbp_value, &mut bytes)?;
        let old_rbp = u64::from_le_bytes(bytes);
        self.engine.cpu.write_reg(Register::RBP, old_rbp);

        // Increment RSP
        let new_rsp = rbp_value.wrapping_add(8);
        self.engine.cpu.write_reg(Register::RSP, new_rsp);

        Ok(())
    }
}
