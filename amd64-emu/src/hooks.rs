use crate::cpu::CpuState;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookType {
    Code,
    MemRead,
    MemWrite,
    MemAccess,
    MemFault, // Called when memory access fails
    Interrupt,
    Invalid,
}

pub struct HookManager<Context> {
    pub code_hook: Option<Box<dyn FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()>>>,
    pub mem_read_hook:
        Option<Box<dyn FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()>>>,
    pub mem_write_hook:
        Option<Box<dyn FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()>>>,
    pub mem_access_hook:
        Option<Box<dyn FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()>>>,
    pub mem_fault_hook:
        Option<Box<dyn FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<bool>>>,
    pub interrupt_hook:
        Option<Box<dyn FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()>>>,
    pub invalid_hook: Option<Box<dyn FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()>>>,
}

impl<Context> Default for HookManager<Context> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Context> HookManager<Context> {
    pub fn new() -> Self {
        Self {
            code_hook: None,
            mem_read_hook: None,
            mem_write_hook: None,
            mem_access_hook: None,
            mem_fault_hook: None,
            interrupt_hook: None,
            invalid_hook: None,
        }
    }

    pub fn set_code_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()> + 'static,
    {
        self.code_hook = Some(Box::new(hook));
    }

    pub fn set_mem_read_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()> + 'static,
    {
        self.mem_read_hook = Some(Box::new(hook));
    }

    pub fn set_mem_write_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()> + 'static,
    {
        self.mem_write_hook = Some(Box::new(hook));
    }

    pub fn set_mem_access_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()> + 'static,
    {
        self.mem_access_hook = Some(Box::new(hook));
    }

    pub fn set_mem_fault_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<bool> + 'static,
    {
        self.mem_fault_hook = Some(Box::new(hook));
    }

    pub fn set_interrupt_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()> + 'static,
    {
        self.interrupt_hook = Some(Box::new(hook));
    }

    pub fn set_invalid_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&mut CpuState, &mut Context, u64, usize) -> Result<()> + 'static,
    {
        self.invalid_hook = Some(Box::new(hook));
    }

    pub fn run_code_hook(
        &mut self,
        cpu: &mut CpuState,
        context: &mut Context,
        address: u64,
        size: usize,
    ) -> Result<()> {
        if let Some(hook) = &mut self.code_hook {
            hook(cpu, context, address, size)?;
        }
        Ok(())
    }

    pub fn run_mem_read_hook(
        &mut self,
        cpu: &mut CpuState,
        context: &mut Context,
        address: u64,
        size: usize,
    ) -> Result<()> {
        if let Some(hook) = &mut self.mem_read_hook {
            hook(cpu, context, address, size)?;
        }
        if let Some(hook) = &mut self.mem_access_hook {
            hook(cpu, context, address, size)?;
        }
        Ok(())
    }

    pub fn run_mem_write_hook(
        &mut self,
        cpu: &mut CpuState,
        context: &mut Context,
        address: u64,
        size: usize,
    ) -> Result<()> {
        if let Some(hook) = &mut self.mem_write_hook {
            hook(cpu, context, address, size)?;
        }
        if let Some(hook) = &mut self.mem_access_hook {
            hook(cpu, context, address, size)?;
        }
        Ok(())
    }

    pub fn run_interrupt_hook(
        &mut self,
        cpu: &mut CpuState,
        context: &mut Context,
        intno: u64,
    ) -> Result<()> {
        if let Some(hook) = &mut self.interrupt_hook {
            hook(cpu, context, intno, 0)?;
        }
        Ok(())
    }

    pub fn run_invalid_hook(
        &mut self,
        cpu: &mut CpuState,
        context: &mut Context,
        address: u64,
    ) -> Result<()> {
        if let Some(hook) = &mut self.invalid_hook {
            hook(cpu, context, address, 0)?;
        }
        Ok(())
    }

    pub fn run_mem_fault_hook(
        &mut self,
        cpu: &mut CpuState,
        context: &mut Context,
        address: u64,
        size: usize,
    ) -> Result<bool> {
        if let Some(hook) = &mut self.mem_fault_hook {
            hook(cpu, context, address, size)
        } else {
            Ok(false)
        }
    }

    pub fn clear(&mut self) {
        self.code_hook = None;
        self.mem_read_hook = None;
        self.mem_write_hook = None;
        self.mem_access_hook = None;
        self.mem_fault_hook = None;
        self.interrupt_hook = None;
        self.invalid_hook = None;
    }
}
