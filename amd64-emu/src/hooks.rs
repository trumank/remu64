use crate::cpu::CpuState;
use crate::error::Result;
use std::collections::HashMap;

pub type HookId = usize;
pub type HookCallback = dyn FnMut(&mut CpuState, u64, usize) -> Result<()>;

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

pub struct Hook<'a> {
    pub hook_type: HookType,
    pub callback: Box<dyn FnMut(&mut CpuState, u64, usize) -> Result<()> + 'a>,
    pub begin: u64,
    pub end: u64,
}

pub struct HookManager<'a> {
    hooks: HashMap<HookId, Hook<'a>>,
    next_id: HookId,
    by_type: HashMap<HookType, Vec<HookId>>,
}

impl Default for HookManager<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> HookManager<'a> {
    pub fn new() -> Self {
        let mut by_type = HashMap::new();
        by_type.insert(HookType::Code, Vec::new());
        by_type.insert(HookType::MemRead, Vec::new());
        by_type.insert(HookType::MemWrite, Vec::new());
        by_type.insert(HookType::MemAccess, Vec::new());
        by_type.insert(HookType::MemFault, Vec::new());
        by_type.insert(HookType::Interrupt, Vec::new());
        by_type.insert(HookType::Invalid, Vec::new());

        Self {
            hooks: HashMap::new(),
            next_id: 1,
            by_type,
        }
    }

    pub fn add_hook<F: 'a>(
        &mut self,
        hook_type: HookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> HookId
    where
        F: FnMut(&mut CpuState, u64, usize) -> Result<()> + 'a,
    {
        let id = self.next_id;
        self.next_id += 1;

        let hook = Hook {
            hook_type,
            callback: Box::new(callback),
            begin,
            end,
        };

        self.hooks.insert(id, hook);
        self.by_type.get_mut(&hook_type).unwrap().push(id);

        id
    }

    pub fn remove_hook(&mut self, id: HookId) -> bool {
        if let Some(hook) = self.hooks.remove(&id) {
            if let Some(ids) = self.by_type.get_mut(&hook.hook_type) {
                ids.retain(|&x| x != id);
            }
            true
        } else {
            false
        }
    }

    pub fn run_code_hooks(&mut self, cpu: &mut CpuState, address: u64, size: usize) -> Result<()> {
        if let Some(ids) = self.by_type.get(&HookType::Code) {
            for &id in ids {
                if let Some(hook) = self.hooks.get_mut(&id) {
                    if address >= hook.begin && address < hook.end {
                        (hook.callback)(cpu, address, size)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn run_mem_read_hooks(
        &mut self,
        cpu: &mut CpuState,
        address: u64,
        size: usize,
    ) -> Result<()> {
        for hook_type in [HookType::MemRead, HookType::MemAccess] {
            if let Some(ids) = self.by_type.get(&hook_type) {
                for &id in ids {
                    if let Some(hook) = self.hooks.get_mut(&id) {
                        if address >= hook.begin && address < hook.end {
                            (hook.callback)(cpu, address, size)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn run_mem_write_hooks(
        &mut self,
        cpu: &mut CpuState,
        address: u64,
        size: usize,
    ) -> Result<()> {
        for hook_type in [HookType::MemWrite, HookType::MemAccess] {
            if let Some(ids) = self.by_type.get(&hook_type) {
                for &id in ids {
                    if let Some(hook) = self.hooks.get_mut(&id) {
                        if address >= hook.begin && address < hook.end {
                            (hook.callback)(cpu, address, size)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn run_interrupt_hooks(&mut self, cpu: &mut CpuState, intno: u64) -> Result<()> {
        if let Some(ids) = self.by_type.get(&HookType::Interrupt) {
            for &id in ids {
                if let Some(hook) = self.hooks.get_mut(&id) {
                    (hook.callback)(cpu, intno, 0)?;
                }
            }
        }
        Ok(())
    }

    pub fn run_invalid_hooks(&mut self, cpu: &mut CpuState, address: u64) -> Result<()> {
        if let Some(ids) = self.by_type.get(&HookType::Invalid) {
            for &id in ids {
                if let Some(hook) = self.hooks.get_mut(&id) {
                    (hook.callback)(cpu, address, 0)?;
                }
            }
        }
        Ok(())
    }

    pub fn run_mem_fault_hooks(
        &mut self,
        cpu: &mut CpuState,
        address: u64,
        size: usize,
    ) -> Result<bool> {
        let mut handled = false;
        if let Some(ids) = self.by_type.get(&HookType::MemFault) {
            for &id in ids {
                if let Some(hook) = self.hooks.get_mut(&id) {
                    if address >= hook.begin && address < hook.end {
                        (hook.callback)(cpu, address, size)?;
                        handled = true;
                    }
                }
            }
        }
        Ok(handled)
    }

    pub fn clear(&mut self) {
        self.hooks.clear();
        for ids in self.by_type.values_mut() {
            ids.clear();
        }
        self.next_id = 1;
    }
}
