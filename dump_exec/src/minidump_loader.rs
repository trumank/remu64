use anyhow::{Context, Result};
use minidump::*;
use std::collections::HashMap;
use std::path::Path;

pub struct MinidumpLoader {
    dump: MmapMinidump,
    modules: Vec<MinidumpModule>,
    memory_regions: HashMap<u64, (u64, usize)>, // (base_address, size)
}

impl MinidumpLoader {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let dump = MmapMinidump::read_path(&path)
            .with_context(|| format!("Failed to read minidump file: {:?}", path.as_ref()))?;

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
        if let Some(memory_list) = self.dump.get_memory() {
            if let Some(memory) = memory_list.memory_at_address(address) {
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
                    .rfind(['/', '\\'])
                    .map(|pos| &name[pos + 1..])
                    .unwrap_or(&*name)
                    .to_string();
                Some((filename, base, address - base))
            } else {
                None
            }
        })
    }
}
