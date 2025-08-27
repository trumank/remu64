use crate::engine::ExecutionContext;
use crate::error::Result;
use crate::memory::MemoryTrait;
use crate::{Flags, HookManager};
use iced_x86::Instruction;

impl<H: HookManager<M>, M: MemoryTrait> ExecutionContext<'_, H, M> {
    pub(crate) fn execute_cmovb(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVB: Conditional move if below (CF=1)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);

        if cf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmovg(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVG: Conditional move if greater (ZF=0 and SF=OF)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if !zf && (sf == of) {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmovbe(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVBE: Conditional move if below or equal (CF=1 or ZF=1)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);

        if cf || zf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmovns(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNS: Conditional move if not sign (SF=0)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);

        if !sf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmova(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVA: Conditional move if above (CF=0 and ZF=0)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);

        if !cf && !zf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmovl(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVL: Conditional move if less than (SF!=OF)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if sf != of {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmovle(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVLE: Conditional move if less than or equal (ZF=1 or SF!=OF)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if zf || (sf != of) {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmove(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVE: Conditional move if equal (ZF=1), same as CMOVZ
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);

        if zf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmovne(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNE: Conditional move if not equal (ZF=0)
        let zf = self.engine.cpu.rflags.contains(Flags::ZF);

        if !zf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }
        // If condition is false, no move occurs

        Ok(())
    }

    pub(crate) fn execute_cmovae(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVAE: Conditional move if above or equal (CF=0)
        let cf = self.engine.cpu.rflags.contains(Flags::CF);

        if !cf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }

        Ok(())
    }

    pub(crate) fn execute_cmovge(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVGE: Conditional move if greater or equal (SF=OF)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if sf == of {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }

        Ok(())
    }

    pub(crate) fn execute_cmovs(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVS: Conditional move if sign (SF=1)
        let sf = self.engine.cpu.rflags.contains(Flags::SF);

        if sf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }

        Ok(())
    }

    pub(crate) fn execute_cmovo(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVO: Conditional move if overflow (OF=1)
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if of {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }

        Ok(())
    }

    pub(crate) fn execute_cmovno(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNO: Conditional move if not overflow (OF=0)
        let of = self.engine.cpu.rflags.contains(Flags::OF);

        if !of {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }

        Ok(())
    }

    pub(crate) fn execute_cmovp(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVP: Conditional move if parity (PF=1)
        let pf = self.engine.cpu.rflags.contains(Flags::PF);

        if pf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }

        Ok(())
    }

    pub(crate) fn execute_cmovnp(&mut self, inst: &Instruction) -> Result<()> {
        // CMOVNP: Conditional move if not parity (PF=0)
        let pf = self.engine.cpu.rflags.contains(Flags::PF);

        if !pf {
            let src_value = self.read_operand(inst, 1)?;
            self.write_operand(inst, 0, src_value)?;
        }

        Ok(())
    }
}
