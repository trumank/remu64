use crate::minidump_memory::MinidumpMemory;
use crate::process_trait::{ModuleInfo, ProcessArchitecture, ProcessTrait};
use anyhow::{Context, Result};
use minidump::*;
use std::collections::HashMap;
use std::path::Path;

pub struct MinidumpLoader<'a> {
    dump: &'a MmapMinidump,
    modules: Vec<MinidumpModule>,
    memory_regions: HashMap<u64, (u64, usize)>, // (base_address, size)
}

impl<'a> MinidumpLoader<'a> {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<MinidumpLoader<'static>> {
        let dump = Box::leak(Box::new(MmapMinidump::read_path(&path).with_context(
            || format!("Failed to read minidump file: {:?}", path.as_ref()),
        )?));
        MinidumpLoader::from_minidump(dump)
    }

    pub fn from_minidump(dump: &'a MmapMinidump) -> Result<MinidumpLoader<'a>> {
        let modules = if let Ok(module_list) = dump.get_stream::<MinidumpModuleList>() {
            module_list.iter().cloned().collect()
        } else {
            Vec::new()
        };

        let mut memory_regions = HashMap::new();
        if let Some(memory_list) = dump.get_memory() {
            for region in memory_list.iter() {
                let (base_address, size) = match region {
                    UnifiedMemory::Memory(mem) => (mem.base_address, mem.bytes.len()),
                    UnifiedMemory::Memory64(mem) => (mem.base_address, mem.bytes.len()),
                };
                memory_regions.insert(base_address, (base_address, size));
            }
        }

        Ok(MinidumpLoader {
            dump,
            modules,
            memory_regions,
        })
    }

    pub fn get_module_by_name(&self, name: &str) -> Option<&MinidumpModule> {
        self.modules.iter().find(|module| {
            let code_file = module.code_file();
            code_file.to_lowercase().contains(&name.to_lowercase())
        })
    }

    pub fn get_module_base_address(&self, name: &str) -> Option<u64> {
        self.get_module_by_name(name)
            .map(|module| module.base_address())
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        if let Some(memory_list) = self.dump.get_memory()
            && let Some(memory) = memory_list.memory_at_address(address)
        {
            let bytes = match memory {
                UnifiedMemory::Memory(mem) => mem.bytes,
                UnifiedMemory::Memory64(mem) => mem.bytes,
            };

            let base_address = match memory {
                UnifiedMemory::Memory(mem) => mem.base_address,
                UnifiedMemory::Memory64(mem) => mem.base_address,
            };

            let offset = (address - base_address) as usize;
            let available_size = std::cmp::min(size, bytes.len().saturating_sub(offset));

            if offset < bytes.len() && available_size > 0 {
                return Ok(bytes[offset..offset + available_size].to_vec());
            }
        }

        anyhow::bail!("Memory address 0x{:x} not found in minidump", address);
    }

    pub fn get_memory_regions(&self) -> &HashMap<u64, (u64, usize)> {
        &self.memory_regions
    }

    pub fn get_modules(&self) -> &[MinidumpModule] {
        &self.modules
    }

    pub fn list_modules(&self) -> Vec<(String, u64, u64)> {
        self.modules
            .iter()
            .map(|module| {
                let name = module.code_file().to_string();
                let base = module.base_address();
                let size = module.size();
                (name, base, size)
            })
            .collect()
    }

    pub fn find_module_for_address(&self, address: u64) -> Option<(String, u64, u64)> {
        self.modules.iter().find_map(|module| {
            let base = module.base_address();
            let size = module.size();
            if address >= base && address < base + size {
                let name = module.code_file();
                // Extract just the filename from the full path (handle both Unix and Windows separators)
                let filename = name
                    .rsplit_once(['/', '\\'])
                    .map(|(_, name)| name)
                    .unwrap_or(&*name)
                    .to_string();
                Some((filename, base, address - base))
            } else {
                None
            }
        })
    }

    pub fn get_dump(&self) -> &MmapMinidump {
        self.dump
    }

    pub fn get_teb_address(&self) -> Result<u64> {
        let thread_list = self
            .dump
            .get_stream::<MinidumpThreadList>()
            .with_context(|| "Failed to get thread list from minidump")?;

        if thread_list.threads.is_empty() {
            anyhow::bail!("No threads found in minidump");
        }

        let teb_address = thread_list.threads[0].raw.teb;

        Ok(teb_address)
    }
}

impl<'a> ProcessTrait for MinidumpLoader<'a> {
    type Memory = MinidumpMemory<'a>;

    fn get_module_by_name(&self, name: &str) -> Option<ModuleInfo> {
        MinidumpLoader::get_module_by_name(self, name).map(|module| ModuleInfo {
            name: module.code_file().to_string(),
            base_address: module.base_address(),
            size: module.size(),
            path: Some(module.code_file().to_string()),
        })
    }
    fn get_module_base_address(&self, name: &str) -> Option<u64> {
        MinidumpLoader::get_module_base_address(self, name)
    }
    fn list_modules(&self) -> Vec<ModuleInfo> {
        self.modules
            .iter()
            .map(|module| ModuleInfo {
                name: module.code_file().to_string(),
                base_address: module.base_address(),
                size: module.size(),
                path: Some(module.code_file().to_string()),
            })
            .collect()
    }
    fn find_module_for_address(&self, address: u64) -> Option<(String, u64, u64)> {
        MinidumpLoader::find_module_for_address(self, address)
    }
    fn create_memory(&self) -> Result<Self::Memory> {
        Ok(MinidumpMemory::new(self.dump)?)
    }
    fn get_teb_address(&self) -> Result<u64> {
        MinidumpLoader::get_teb_address(self)
    }
    fn get_architecture(&self) -> ProcessArchitecture {
        ProcessArchitecture::X64
    }
}

// Also implement for &MinidumpLoader to support borrowing
impl<'a> ProcessTrait for &MinidumpLoader<'a> {
    type Memory = MinidumpMemory<'a>;

    fn get_module_by_name(&self, name: &str) -> Option<ModuleInfo> {
        <MinidumpLoader<'a> as ProcessTrait>::get_module_by_name(*self, name)
    }
    fn get_module_base_address(&self, name: &str) -> Option<u64> {
        <MinidumpLoader<'a> as ProcessTrait>::get_module_base_address(*self, name)
    }
    fn list_modules(&self) -> Vec<ModuleInfo> {
        <MinidumpLoader<'a> as ProcessTrait>::list_modules(*self)
    }
    fn find_module_for_address(&self, address: u64) -> Option<(String, u64, u64)> {
        <MinidumpLoader<'a> as ProcessTrait>::find_module_for_address(*self, address)
    }
    fn create_memory(&self) -> Result<Self::Memory> {
        <MinidumpLoader<'a> as ProcessTrait>::create_memory(*self)
    }
    fn get_teb_address(&self) -> Result<u64> {
        <MinidumpLoader<'a> as ProcessTrait>::get_teb_address(*self)
    }
    fn get_architecture(&self) -> ProcessArchitecture {
        <MinidumpLoader<'a> as ProcessTrait>::get_architecture(*self)
    }
}
