use crate::engine::ExecutionContext;
use crate::error::Result;
use crate::memory::MemoryTrait;
use crate::{Flags, HookManager};
use iced_x86::Instruction;

impl<H: HookManager<M, PS>, M: MemoryTrait<PS>, const PS: u64> ExecutionContext<'_, H, M, PS> {
    pub(crate) fn execute_setbe(&mut self, inst: &Instruction) -> Result<()> {
        // SETBE: Set if below or equal (CF=1 or ZF=1)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let result = if cf || zf { 1u64 } else { 0u64 };

        // Write 1 byte result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_sete(&mut self, inst: &Instruction) -> Result<()> {
        // SETE: Set if equal (ZF=1)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let result = if zf { 1u64 } else { 0u64 };

        // Write 1 byte result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setne(&mut self, inst: &Instruction) -> Result<()> {
        // SETNE: Set if not equal (ZF=0)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let result = if !zf { 1u64 } else { 0u64 };

        // Write 1 byte result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setle(&mut self, inst: &Instruction) -> Result<()> {
        // SETLE: Set if less than or equal (ZF=1 or SF!=OF)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if zf || (sf != of) { 1u64 } else { 0u64 };

        // Write 1 byte result to destination
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_seta(&mut self, inst: &Instruction) -> Result<()> {
        // SETA: Set if above (CF=0 and ZF=0)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let result = if !cf && !zf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setae(&mut self, inst: &Instruction) -> Result<()> {
        // SETAE: Set if above or equal (CF=0)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let result = if !cf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setb(&mut self, inst: &Instruction) -> Result<()> {
        // SETB: Set if below (CF=1)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let result = if cf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setg(&mut self, inst: &Instruction) -> Result<()> {
        // SETG: Set if greater (ZF=0 and SF=OF)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if !zf && (sf == of) { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setge(&mut self, inst: &Instruction) -> Result<()> {
        // SETGE: Set if greater or equal (SF=OF)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if sf == of { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setl(&mut self, inst: &Instruction) -> Result<()> {
        // SETL: Set if less (SF!=OF)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if sf != of { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_sets(&mut self, inst: &Instruction) -> Result<()> {
        // SETS: Set if sign (SF=1)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let result = if sf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setns(&mut self, inst: &Instruction) -> Result<()> {
        // SETNS: Set if not sign (SF=0)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let result = if !sf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_seto(&mut self, inst: &Instruction) -> Result<()> {
        // SETO: Set if overflow (OF=1)
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if of { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setno(&mut self, inst: &Instruction) -> Result<()> {
        // SETNO: Set if not overflow (OF=0)
        let of = self.engine.cpu.rflags.contains(Flags::OF);
        let result = if !of { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setp(&mut self, inst: &Instruction) -> Result<()> {
        // SETP: Set if parity (PF=1)
        let pf = self.engine.cpu.rflags.contains(Flags::PF);
        let result = if pf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }

    pub(crate) fn execute_setnp(&mut self, inst: &Instruction) -> Result<()> {
        // SETNP: Set if not parity (PF=0)
        let pf = self.engine.cpu.rflags.contains(Flags::PF);
        let result = if !pf { 1u64 } else { 0u64 };
        self.write_operand(inst, 0, result)?;
        Ok(())
    }
}
