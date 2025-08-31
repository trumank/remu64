use minidump::{MmapMinidump, UnifiedMemory};
use remu64::{
    EmulatorError, Permission, Result,
    memory::{MemoryRegionMut, MemoryRegionRef, MemoryTrait},
};
use std::collections::BTreeMap;

// MinidumpMemoryRegion holds a slice directly from the mmap'd minidump
pub struct MinidumpMemory<'a> {
    regions: BTreeMap<u64, MemoryRegionRef<'a>>,
}

impl<'a> MinidumpMemory<'a> {
    pub fn new(dump: &'a MmapMinidump) -> Result<Self> {
        let mut regions = BTreeMap::new();

        if let Some(memory_list) = dump.get_memory() {
            for memory in memory_list.iter() {
                let (base_address, bytes) = match memory {
                    UnifiedMemory::Memory(mem) => (mem.base_address, mem.bytes),
                    UnifiedMemory::Memory64(mem) => (mem.base_address, mem.bytes),
                };

                let size = bytes.len();
                if size == 0 {
                    continue;
                }

                let region = MemoryRegionRef {
                    address: base_address,
                    data: bytes,
                    permissions: Permission::READ | Permission::WRITE | Permission::EXEC, // Minidump doesn't preserve original permissions
                };

                regions.insert(base_address, region);
            }
        }

        Ok(MinidumpMemory { regions })
    }

    pub fn regions(&self) -> impl Iterator<Item = &MemoryRegionRef<'a>> {
        self.regions.values()
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    pub fn memory_ranges(&self) -> Vec<(u64, u64)> {
        self.regions
            .values()
            .map(|region| (region.start(), region.end()))
            .collect()
    }
}

impl<'a> MemoryTrait for MinidumpMemory<'a> {
    fn find_region(&self, addr: u64) -> Option<MemoryRegionRef<'_>> {
        self.regions
            .range(..=addr)
            .next_back()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region.clone())
                } else {
                    None
                }
            })
    }

    fn find_region_mut(&mut self, _addr: u64) -> Option<MemoryRegionMut<'_>> {
        None
    }

    fn permissions(&self, addr: u64) -> Result<Permission> {
        let region = self
            .find_region(addr)
            .ok_or(EmulatorError::UnmappedMemory(addr))?;
        Ok(region.permissions)
    }

    fn map(&mut self, _addr: u64, _size: usize, _perms: Permission) -> Result<()> {
        Err(EmulatorError::InvalidArgument(
            "Cannot map new memory regions in MinidumpMemory".into(),
        ))
    }

    fn unmap(&mut self, _addr: u64, _size: usize) -> Result<()> {
        Err(EmulatorError::InvalidArgument(
            "Cannot unmap memory regions in MinidumpMemory".into(),
        ))
    }

    fn protect(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        let end = addr + size as u64;

        let mut regions_to_update = Vec::new();
        for (&start, region) in &self.regions {
            if addr < region.end() && region.start() < end {
                regions_to_update.push(start);
            }
        }

        if regions_to_update.is_empty() {
            return Err(EmulatorError::UnmappedMemory(addr));
        }

        for start in regions_to_update {
            if let Some(region) = self.regions.get_mut(&start) {
                region.permissions = perms;
            }
        }

        Ok(())
    }
}

impl<'a> MemoryTrait for &MinidumpMemory<'a> {
    fn find_region(&self, addr: u64) -> Option<MemoryRegionRef<'_>> {
        <MinidumpMemory>::find_region(self, addr)
    }
    fn find_region_mut(&mut self, _addr: u64) -> Option<MemoryRegionMut<'_>> {
        None
    }
    fn permissions(&self, addr: u64) -> Result<Permission> {
        <MinidumpMemory>::permissions(self, addr)
    }
    fn map(&mut self, _addr: u64, _size: usize, _perms: Permission) -> Result<()> {
        Err(EmulatorError::InvalidArgument(
            "Cannot map new memory regions in MinidumpMemory".into(),
        ))
    }
    fn unmap(&mut self, _addr: u64, _size: usize) -> Result<()> {
        Err(EmulatorError::InvalidArgument(
            "Cannot unmap memory regions in MinidumpMemory".into(),
        ))
    }
    fn protect(&mut self, _addr: u64, _size: usize, _perms: Permission) -> Result<()> {
        Err(EmulatorError::InvalidArgument(
            "Cannot protect memory regions in &MinidumpMemory".into(),
        ))
    }
}

#[cfg(test)]
mod tests {

    // Note: These tests would need actual minidump data to run properly
    // For now they serve as documentation of the intended behavior

    #[test]
    fn test_minidump_memory_read_basic() {
        // This test would verify basic read operations work
        // let dump = create_test_minidump();
        // let memory = MinidumpMemory::new(&dump).unwrap();
        // assert_eq!(memory.read_u8(0x1000).unwrap(), expected_value);
    }

    #[test]
    fn test_minidump_memory_region_lookup() {
        // This test would verify region lookup works correctly
        // let dump = create_test_minidump();
        // let memory = MinidumpMemory::new(&dump).unwrap();
        // assert!(memory.find_region(0x1000).is_some());
        // assert!(memory.find_region(0x500).is_none());
    }

    #[test]
    fn test_minidump_memory_immutable_operations() {
        // This test would verify that map/unmap operations fail appropriately
        // let dump = create_test_minidump();
        // let mut memory = MinidumpMemory::new(&dump).unwrap();
        // assert!(memory.map(0x50000, 4096, Permission::READ).is_err());
        // assert!(memory.unmap(0x1000, 4096).is_err());
    }
}
