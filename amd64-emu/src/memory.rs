use crate::error::{EmulatorError, Result};
use bitflags::bitflags;
use std::{collections::BTreeMap, ops::Range};

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct Permission: u32 {
        const NONE = 0;
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
        const ALL = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

pub trait MemoryRegionTrait {
    fn range(&self) -> Range<u64>;
    fn data(&self) -> &[u8];
    fn data_mut(&mut self) -> &mut [u8];
    fn perms(&self) -> Permission;
    fn contains(&self, addr: u64) -> bool {
        self.range().contains(&addr)
    }
    fn size(&self) -> usize {
        let range = self.range();
        (range.end - range.start) as usize
    }
    fn offset(&self, addr: u64) -> Option<usize> {
        let range = self.range();
        range.contains(&addr).then(|| (addr - range.start) as usize)
    }
}

pub trait MemoryTrait {
    type MemoryRegion: MemoryRegionTrait;

    fn find_region(&self, addr: u64) -> Option<&Self::MemoryRegion>;
    fn find_region_mut(&mut self, addr: u64) -> Option<&mut Self::MemoryRegion>;

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < buf.len() {
            let region = self
                .find_region(current_addr)
                .ok_or(EmulatorError::UnmappedMemory(current_addr))?;

            if !region.perms().contains(Permission::READ) {
                return Err(EmulatorError::PermissionDenied(current_addr));
            }

            let region_offset = region.offset(current_addr).unwrap();
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, buf.len() - offset);

            buf[offset..offset + to_copy]
                .copy_from_slice(&region.data()[region_offset..region_offset + to_copy]);

            offset += to_copy;
            current_addr += to_copy as u64;
        }

        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < data.len() {
            let region = self
                .find_region_mut(current_addr)
                .ok_or(EmulatorError::UnmappedMemory(current_addr))?;

            if !region.perms().contains(Permission::WRITE) {
                return Err(EmulatorError::PermissionDenied(current_addr));
            }

            let region_offset = region.offset(current_addr).unwrap();
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);

            region.data_mut()[region_offset..region_offset + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);

            offset += to_copy;
            current_addr += to_copy as u64;
        }

        Ok(())
    }

    // Write bytes without permission checks - used for loading code
    fn write_code(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < data.len() {
            let region = self
                .find_region_mut(current_addr)
                .ok_or(EmulatorError::UnmappedMemory(current_addr))?;

            let region_offset = region.offset(current_addr).unwrap();
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);

            region.data_mut()[region_offset..region_offset + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);

            offset += to_copy;
            current_addr += to_copy as u64;
        }

        Ok(())
    }

    fn read_u8(&self, addr: u64) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read(addr, &mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&self, addr: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read(addr, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_u32(&self, addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_u64(&self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn write_u8(&mut self, addr: u64, value: u8) -> Result<()> {
        self.write(addr, &[value])
    }

    fn write_u16(&mut self, addr: u64, value: u16) -> Result<()> {
        self.write(addr, &value.to_le_bytes())
    }

    fn write_u32(&mut self, addr: u64, value: u32) -> Result<()> {
        self.write(addr, &value.to_le_bytes())
    }

    fn write_u64(&mut self, addr: u64, value: u64) -> Result<()> {
        self.write(addr, &value.to_le_bytes())
    }

    fn check_exec(&self, addr: u64) -> Result<()> {
        let region = self
            .find_region(addr)
            .ok_or(EmulatorError::UnmappedMemory(addr))?;

        if !region.perms().contains(Permission::EXEC) {
            return Err(EmulatorError::PermissionDenied(addr));
        }

        Ok(())
    }

    fn map(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()>;
    fn unmap(&mut self, addr: u64, size: usize) -> Result<()>;
    fn protect(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()>;

    // fn regions(&self) -> impl Iterator<Item = &MemoryRegion>;
    fn total_size(&self) -> usize;
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub perms: Permission,
    pub data: Vec<u8>,
}

impl MemoryRegionTrait for MemoryRegion {
    fn range(&self) -> Range<u64> {
        self.start..self.end
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
    fn perms(&self) -> Permission {
        self.perms
    }
}

impl MemoryRegion {
    pub fn new(start: u64, size: usize, perms: Permission) -> Self {
        Self {
            start,
            end: start + size as u64,
            perms,
            data: vec![0; size],
        }
    }
}

pub struct OwnedMemory {
    regions: BTreeMap<u64, MemoryRegion>,
    page_size: usize,
}

impl Default for OwnedMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnedMemory {
    pub fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            page_size: 4096,
        }
    }
    pub fn regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions.values()
    }
}

impl MemoryTrait for OwnedMemory {
    type MemoryRegion = MemoryRegion;

    fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions
            .range(..=addr)
            .next_back()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region)
                } else {
                    None
                }
            })
    }

    fn find_region_mut(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        self.regions
            .range_mut(..=addr)
            .next_back()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region)
                } else {
                    None
                }
            })
    }

    fn map(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        if size == 0 {
            return Err(EmulatorError::InvalidArgument("Size cannot be zero".into()));
        }

        let aligned_addr = addr & !(self.page_size as u64 - 1);
        let aligned_size =
            ((addr - aligned_addr) as usize + size + self.page_size - 1) & !(self.page_size - 1);

        let end = aligned_addr + aligned_size as u64;

        for region in self.regions.values() {
            if (aligned_addr >= region.start && aligned_addr < region.end)
                || (end > region.start && end <= region.end)
                || (aligned_addr <= region.start && end >= region.end)
            {
                return Err(EmulatorError::InvalidArgument(format!(
                    "Memory overlap at {:#x}-{:#x}",
                    aligned_addr, end
                )));
            }
        }

        let region = MemoryRegion::new(aligned_addr, aligned_size, perms);
        self.regions.insert(aligned_addr, region);
        Ok(())
    }

    fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        let aligned_addr = addr & !(self.page_size as u64 - 1);
        let aligned_size =
            ((addr - aligned_addr) as usize + size + self.page_size - 1) & !(self.page_size - 1);
        let end = aligned_addr + aligned_size as u64;

        let mut to_remove = Vec::new();
        for (&start, region) in &self.regions {
            if start >= aligned_addr && region.end <= end {
                to_remove.push(start);
            }
        }

        if to_remove.is_empty() {
            return Err(EmulatorError::UnmappedMemory(addr));
        }

        for start in to_remove {
            self.regions.remove(&start);
        }

        Ok(())
    }

    fn protect(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        let end = addr + size as u64;

        let mut regions_to_update = Vec::new();
        for (&start, region) in &self.regions {
            if (addr >= region.start && addr < region.end)
                || (end > region.start && end <= region.end)
                || (addr <= region.start && end >= region.end)
            {
                regions_to_update.push(start);
            }
        }

        if regions_to_update.is_empty() {
            return Err(EmulatorError::UnmappedMemory(addr));
        }

        for start in regions_to_update {
            if let Some(region) = self.regions.get_mut(&start) {
                region.perms = perms;
            }
        }

        Ok(())
    }

    fn total_size(&self) -> usize {
        self.regions.values().map(|r| r.size()).sum()
    }
}

pub struct CowMemory<T: MemoryTrait> {
    base: T,
    overlay: BTreeMap<u64, MemoryRegion>,
    page_size: usize,
}

impl<T: MemoryTrait> CowMemory<T> {
    pub fn new(base: T) -> Self {
        Self {
            base,
            overlay: BTreeMap::new(),
            page_size: 4096,
        }
    }

    pub fn base(&self) -> &T {
        &self.base
    }

    pub fn overlay_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.overlay.values()
    }

    fn copy_page(&mut self, addr: u64) -> Result<()> {
        let page_addr = addr & !(self.page_size as u64 - 1);

        if self.overlay.contains_key(&page_addr) {
            return Ok(());
        }

        let base_region = self
            .base
            .find_region(page_addr)
            .ok_or(EmulatorError::UnmappedMemory(page_addr))?;

        let page_offset = base_region.offset(page_addr).unwrap();
        let copy_size = std::cmp::min(self.page_size, base_region.size() - page_offset);

        let mut cow_region = MemoryRegion::new(page_addr, copy_size, base_region.perms());
        cow_region
            .data_mut()
            .copy_from_slice(&base_region.data()[page_offset..page_offset + copy_size]);

        self.overlay.insert(page_addr, cow_region);
        Ok(())
    }
}

impl<T: MemoryTrait> MemoryTrait for CowMemory<T> {
    type MemoryRegion = MemoryRegion;

    fn find_region(&self, addr: u64) -> Option<&Self::MemoryRegion> {
        self.overlay
            .range(..=addr)
            .next_back()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region)
                } else {
                    None
                }
            })
    }

    fn find_region_mut(&mut self, addr: u64) -> Option<&mut Self::MemoryRegion> {
        if let Some(overlay_region) =
            self.overlay
                .range_mut(..=addr)
                .next_back()
                .and_then(|(_, region)| {
                    if region.contains(addr) {
                        Some(region)
                    } else {
                        None
                    }
                })
        {
            Some(overlay_region)
        } else {
            None
        }
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < buf.len() {
            // First check overlay
            if let Some(overlay_region) = self.find_region(current_addr) {
                let region_offset = overlay_region.offset(current_addr).unwrap();
                let available = overlay_region.size() - region_offset;
                let to_copy = std::cmp::min(available, buf.len() - offset);

                buf[offset..offset + to_copy].copy_from_slice(
                    &overlay_region.data()[region_offset..region_offset + to_copy],
                );

                offset += to_copy;
                current_addr += to_copy as u64;
            } else {
                // Fall back to base memory
                let base_region = self
                    .base
                    .find_region(current_addr)
                    .ok_or(EmulatorError::UnmappedMemory(current_addr))?;

                if !base_region.perms().contains(Permission::READ) {
                    return Err(EmulatorError::PermissionDenied(current_addr));
                }

                let region_offset = base_region.offset(current_addr).unwrap();
                let available = base_region.size() - region_offset;
                let to_copy = std::cmp::min(available, buf.len() - offset);

                buf[offset..offset + to_copy]
                    .copy_from_slice(&base_region.data()[region_offset..region_offset + to_copy]);

                offset += to_copy;
                current_addr += to_copy as u64;
            }
        }

        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < data.len() {
            let page_addr = current_addr & !(self.page_size as u64 - 1);

            // Check if page_addr is already covered by an existing overlay region
            let page_already_in_overlay = self
                .overlay
                .range(..=page_addr)
                .next_back()
                .is_some_and(|(_, region)| region.contains(page_addr));

            if !page_already_in_overlay {
                self.copy_page(current_addr)?;
            }

            let region = self
                .find_region_mut(current_addr)
                .ok_or(EmulatorError::UnmappedMemory(current_addr))?;

            if !region.perms().contains(Permission::WRITE) {
                return Err(EmulatorError::PermissionDenied(current_addr));
            }

            let region_offset = region.offset(current_addr).unwrap();
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);

            region.data_mut()[region_offset..region_offset + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);

            offset += to_copy;
            current_addr += to_copy as u64;
        }

        Ok(())
    }

    fn write_code(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < data.len() {
            let page_addr = current_addr & !(self.page_size as u64 - 1);

            // Check if page_addr is already covered by an existing overlay region
            let page_already_in_overlay = self
                .overlay
                .range(..=page_addr)
                .next_back()
                .is_some_and(|(_, region)| region.contains(page_addr));

            if !page_already_in_overlay {
                self.copy_page(current_addr)?;
            }

            let region = self
                .find_region_mut(current_addr)
                .ok_or(EmulatorError::UnmappedMemory(current_addr))?;

            let region_offset = region.offset(current_addr).unwrap();
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);

            region.data_mut()[region_offset..region_offset + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);

            offset += to_copy;
            current_addr += to_copy as u64;
        }

        Ok(())
    }

    fn map(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        if size == 0 {
            return Err(EmulatorError::InvalidArgument("Size cannot be zero".into()));
        }

        let aligned_addr = addr & !(self.page_size as u64 - 1);
        let aligned_size =
            ((addr - aligned_addr) as usize + size + self.page_size - 1) & !(self.page_size - 1);

        let end = aligned_addr + aligned_size as u64;

        for region in self.overlay.values() {
            if (aligned_addr >= region.start && aligned_addr < region.end)
                || (end > region.start && end <= region.end)
                || (aligned_addr <= region.start && end >= region.end)
            {
                return Err(EmulatorError::InvalidArgument(format!(
                    "Memory overlap at {:#x}-{:#x}",
                    aligned_addr, end
                )));
            }
        }

        if let Some(base_region) = self.base.find_region(aligned_addr) {
            if (aligned_addr >= base_region.range().start && aligned_addr < base_region.range().end)
                || (end > base_region.range().start && end <= base_region.range().end)
                || (aligned_addr <= base_region.range().start && end >= base_region.range().end)
            {
                return Err(EmulatorError::InvalidArgument(format!(
                    "Memory overlap with base at {:#x}-{:#x}",
                    aligned_addr, end
                )));
            }
        }

        let region = MemoryRegion::new(aligned_addr, aligned_size, perms);
        self.overlay.insert(aligned_addr, region);
        Ok(())
    }

    fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        let aligned_addr = addr & !(self.page_size as u64 - 1);
        let aligned_size =
            ((addr - aligned_addr) as usize + size + self.page_size - 1) & !(self.page_size - 1);
        let end = aligned_addr + aligned_size as u64;

        let mut to_remove = Vec::new();
        for (&start, region) in &self.overlay {
            if start >= aligned_addr && region.end <= end {
                to_remove.push(start);
            }
        }

        if to_remove.is_empty() {
            return Err(EmulatorError::UnmappedMemory(addr));
        }

        for start in to_remove {
            self.overlay.remove(&start);
        }

        Ok(())
    }

    fn protect(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        let end = addr + size as u64;

        let mut regions_to_update = Vec::new();
        for (&start, region) in &self.overlay {
            if (addr >= region.start && addr < region.end)
                || (end > region.start && end <= region.end)
                || (addr <= region.start && end >= region.end)
            {
                regions_to_update.push(start);
            }
        }

        if regions_to_update.is_empty() {
            return Err(EmulatorError::UnmappedMemory(addr));
        }

        for start in regions_to_update {
            if let Some(region) = self.overlay.get_mut(&start) {
                region.perms = perms;
            }
        }

        Ok(())
    }

    fn check_exec(&self, addr: u64) -> Result<()> {
        // First check overlay regions
        if let Some(region) = self.find_region(addr) {
            if !region.perms().contains(Permission::EXEC) {
                return Err(EmulatorError::PermissionDenied(addr));
            }
            return Ok(());
        }

        // Fall back to base memory
        self.base.check_exec(addr)
    }

    fn total_size(&self) -> usize {
        let base_size = self.base.total_size();
        let overlay_size = self.overlay.values().map(|r| r.size()).sum::<usize>();
        base_size + overlay_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_base_memory() -> OwnedMemory {
        let mut memory = OwnedMemory::new();
        // Map some base pages with test data
        memory
            .map(0x1000, 0x3000, Permission::READ | Permission::WRITE)
            .unwrap();

        // Fill base memory with predictable pattern
        for i in 0..0x3000u64 {
            memory.write_u8(0x1000 + i, (i % 256) as u8).unwrap();
        }

        memory
    }

    #[test]
    fn test_cow_memory_basic_reads() {
        let base = create_base_memory();
        let cow = CowMemory::new(base);

        // Verify we can read from base memory
        assert_eq!(cow.read_u8(0x1000).unwrap(), 0);
        assert_eq!(cow.read_u8(0x1001).unwrap(), 1);
        assert_eq!(cow.read_u8(0x1100).unwrap(), 0); // 0x100 % 256 = 0
        assert_eq!(cow.read_u8(0x3fff).unwrap(), 255); // (0x2fff) % 256 = 255

        // Verify no overlay pages exist yet
        assert_eq!(cow.overlay_regions().count(), 0);
    }

    #[test]
    fn test_cow_memory_basic_writes() {
        let base = create_base_memory();
        let mut cow = CowMemory::new(base);

        // Write to first page - should trigger CoW
        cow.write_u8(0x1000, 42).unwrap();

        // Verify write took effect
        assert_eq!(cow.read_u8(0x1000).unwrap(), 42);

        // Verify overlay page was created
        assert_eq!(cow.overlay_regions().count(), 1);
        let overlay_region = cow.overlay_regions().next().unwrap();
        assert_eq!(overlay_region.start, 0x1000);
        assert_eq!(overlay_region.end, 0x2000);

        // Verify base memory is unchanged
        assert_eq!(cow.base().read_u8(0x1000).unwrap(), 0);

        // Verify other data in the same page was copied correctly
        assert_eq!(cow.read_u8(0x1001).unwrap(), 1);
        assert_eq!(cow.read_u8(0x1fff).unwrap(), 255); // (0xfff) % 256 = 255
    }

    #[test]
    fn test_cow_memory_overlapping_pages() {
        let base = create_base_memory();
        let mut cow = CowMemory::new(base);

        // Write to multiple overlapping locations in the same page
        cow.write_u8(0x1000, 100).unwrap();
        cow.write_u8(0x1500, 200).unwrap(); // Same page as 0x1000
        cow.write_u8(0x1fff, 255).unwrap(); // Same page as 0x1000

        // Should only have one overlay page
        assert_eq!(cow.overlay_regions().count(), 1);

        // Verify all writes are visible
        assert_eq!(cow.read_u8(0x1000).unwrap(), 100);
        assert_eq!(cow.read_u8(0x1500).unwrap(), 200);
        assert_eq!(cow.read_u8(0x1fff).unwrap(), 255);

        // Write to different page
        cow.write_u8(0x2000, 50).unwrap();

        // Should now have two overlay pages
        assert_eq!(cow.overlay_regions().count(), 2);

        // Verify reads from both pages
        assert_eq!(cow.read_u8(0x1000).unwrap(), 100);
        assert_eq!(cow.read_u8(0x2000).unwrap(), 50);
    }

    #[test]
    fn test_cow_memory_page_copying_preserves_data() {
        let base = create_base_memory();
        let mut cow = CowMemory::new(base);

        // Read original values from a page
        let original_values: Vec<u8> = (0..4096).map(|i| ((0x1000 + i) % 256) as u8).collect();

        // Write to one byte in the middle of the page
        cow.write_u8(0x1800, 123).unwrap();

        // Verify the rest of the page was preserved during CoW
        for i in 0..4096u64 {
            let addr = 0x1000 + i;
            let expected = if addr == 0x1800 {
                123
            } else {
                original_values[i as usize]
            };
            assert_eq!(
                cow.read_u8(addr).unwrap(),
                expected,
                "Mismatch at address {:#x}",
                addr
            );
        }
    }

    #[test]
    fn test_cow_memory_cross_page_operations() {
        let base = create_base_memory();
        let mut cow = CowMemory::new(base);

        // Write data that spans two pages
        let test_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        cow.write(0x1ffe, &test_data).unwrap(); // Spans pages 0x1000 and 0x2000

        // Should have created two overlay pages
        assert_eq!(cow.overlay_regions().count(), 2);

        // Verify we can read the data back correctly
        let mut read_data = vec![0u8; 8];
        cow.read(0x1ffe, &mut read_data).unwrap();
        assert_eq!(read_data, test_data);

        // Verify the data is split correctly across pages
        assert_eq!(cow.read_u8(0x1ffe).unwrap(), 1);
        assert_eq!(cow.read_u8(0x1fff).unwrap(), 2);
        assert_eq!(cow.read_u8(0x2000).unwrap(), 3);
        assert_eq!(cow.read_u8(0x2005).unwrap(), 8);
    }

    #[test]
    fn test_cow_memory_multiple_layers() {
        // Test CoW on top of CoW
        let base = create_base_memory();
        let mut cow1 = CowMemory::new(base);

        // Modify first layer
        cow1.write_u8(0x1000, 42).unwrap();

        // Create second layer on top
        let mut cow2 = CowMemory::new(cow1);

        // Verify we can read from the stack
        assert_eq!(cow2.read_u8(0x1000).unwrap(), 42); // From cow1
        assert_eq!(cow2.read_u8(0x1001).unwrap(), 1); // From original base

        // Modify second layer
        cow2.write_u8(0x1000, 99).unwrap();

        // Verify layered changes
        assert_eq!(cow2.read_u8(0x1000).unwrap(), 99); // From cow2 overlay
        assert_eq!(cow2.base().read_u8(0x1000).unwrap(), 42); // cow1 still has 42
        assert_eq!(cow2.base().base().read_u8(0x1000).unwrap(), 0); // original base unchanged
    }

    #[test]
    fn test_cow_memory_permissions() {
        let mut base = OwnedMemory::new();
        base.map(0x1000, 0x1000, Permission::READ).unwrap(); // Read-only base

        // Fill with data
        base.write_code(0x1000, &vec![42u8; 0x1000]).unwrap(); // Use write_bytes to bypass permission check

        let mut cow = CowMemory::new(base);

        // Should be able to read
        assert_eq!(cow.read_u8(0x1000).unwrap(), 42);

        // Should fail to write due to permission
        assert!(cow.write_u8(0x1000, 99).is_err());
    }

    #[test]
    fn test_cow_memory_unmap_overlay_pages() {
        let base = create_base_memory();
        let mut cow = CowMemory::new(base);

        // Create some overlay pages
        cow.write_u8(0x1000, 1).unwrap();
        cow.write_u8(0x2000, 2).unwrap();
        cow.write_u8(0x3000, 3).unwrap();

        assert_eq!(cow.overlay_regions().count(), 3);

        // Unmap middle page
        cow.unmap(0x2000, 0x1000).unwrap();

        assert_eq!(cow.overlay_regions().count(), 2);

        // Verify other pages still work
        assert_eq!(cow.read_u8(0x1000).unwrap(), 1);
        assert_eq!(cow.read_u8(0x3000).unwrap(), 3);

        // Verify unmapped page falls back to base (if it exists there)
        assert_eq!(cow.read_u8(0x2000).unwrap(), 0); // Original base value
    }

    #[test]
    fn test_cow_memory_map_new_regions() {
        let base = create_base_memory();
        let mut cow = CowMemory::new(base);

        // Map a new region that doesn't exist in base
        cow.map(0x5000, 0x1000, Permission::READ | Permission::WRITE)
            .unwrap();

        // Should be able to write to it
        cow.write_u8(0x5000, 123).unwrap();
        assert_eq!(cow.read_u8(0x5000).unwrap(), 123);

        // Should appear in overlay
        assert_eq!(cow.overlay_regions().count(), 1);
    }

    #[test]
    fn test_cow_memory_write_bytes_bypass_permissions() {
        let mut base = OwnedMemory::new();
        base.map(0x1000, 0x1000, Permission::READ).unwrap(); // Read-only

        let mut cow = CowMemory::new(base);

        // write_bytes should bypass permission checks
        cow.write_code(0x1000, &[1, 2, 3, 4]).unwrap();

        // Should be able to read back the data
        assert_eq!(cow.read_u8(0x1000).unwrap(), 1);
        assert_eq!(cow.read_u8(0x1003).unwrap(), 4);

        // Should have created overlay page
        assert_eq!(cow.overlay_regions().count(), 1);
    }

    #[test]
    fn test_cow_memory_large_cross_page_write() {
        let base = create_base_memory();
        let mut cow = CowMemory::new(base);

        // Write 8KB of data spanning 3 pages
        let large_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        cow.write(0x1800, &large_data).unwrap(); // Spans pages 0x1000, 0x2000, 0x3000

        // Should create 3 overlay pages
        assert_eq!(cow.overlay_regions().count(), 3);

        // Verify we can read all data back
        let mut read_back = vec![0u8; 8192];
        cow.read(0x1800, &mut read_back).unwrap();
        assert_eq!(read_back, large_data);
    }

    #[test]
    fn test_cow_memory_total_size_calculation() {
        let base = create_base_memory(); // 3 pages
        let base_size = base.total_size();

        let mut cow = CowMemory::new(base);

        // Initially should match base size
        assert_eq!(cow.total_size(), base_size);

        // Add overlay pages
        cow.write_u8(0x1000, 1).unwrap(); // Overlaps with base
        cow.map(0x5000, 0x1000, Permission::READ | Permission::WRITE)
            .unwrap(); // New region

        // Total size should include overlay pages
        // Note: overlapping pages are counted in both base and overlay
        let expected_size = base_size + 4096 + 4096; // original + cow page + new region
        assert_eq!(cow.total_size(), expected_size);
    }

    // Mock memory type to test CowMemory flexibility with different MemoryRegion types
    struct MockMemoryRegion {
        start: u64,
        end: u64,
        data: Vec<u8>,
    }

    impl MemoryRegionTrait for MockMemoryRegion {
        fn range(&self) -> std::ops::Range<u64> {
            self.start..self.end
        }

        fn data(&self) -> &[u8] {
            &self.data
        }

        fn data_mut(&mut self) -> &mut [u8] {
            &mut self.data
        }

        fn perms(&self) -> Permission {
            Permission::READ | Permission::WRITE
        }
    }

    struct MockMemory {
        regions: BTreeMap<u64, MockMemoryRegion>,
    }

    impl MockMemory {
        fn new() -> Self {
            let mut regions = BTreeMap::new();
            regions.insert(
                0x1000,
                MockMemoryRegion {
                    start: 0x1000,
                    end: 0x2000,
                    data: (0..4096).map(|i| (i % 256) as u8).collect(),
                },
            );
            MockMemory { regions }
        }
    }

    impl MemoryTrait for MockMemory {
        type MemoryRegion = MockMemoryRegion;

        fn find_region(&self, addr: u64) -> Option<&Self::MemoryRegion> {
            self.regions
                .range(..=addr)
                .next_back()
                .and_then(|(_, region)| {
                    if region.contains(addr) {
                        Some(region)
                    } else {
                        None
                    }
                })
        }

        fn find_region_mut(&mut self, addr: u64) -> Option<&mut Self::MemoryRegion> {
            self.regions
                .range_mut(..=addr)
                .next_back()
                .and_then(|(_, region)| {
                    if region.contains(addr) {
                        Some(region)
                    } else {
                        None
                    }
                })
        }

        fn map(&mut self, _addr: u64, _size: usize, _perms: Permission) -> Result<()> {
            Err(EmulatorError::InvalidArgument(
                "Mock memory doesn't support mapping".into(),
            ))
        }

        fn unmap(&mut self, _addr: u64, _size: usize) -> Result<()> {
            Err(EmulatorError::InvalidArgument(
                "Mock memory doesn't support unmapping".into(),
            ))
        }

        fn protect(&mut self, _addr: u64, _size: usize, _perms: Permission) -> Result<()> {
            Ok(())
        }

        fn total_size(&self) -> usize {
            self.regions.values().map(|r| r.size()).sum()
        }
    }

    #[test]
    fn test_cow_memory_with_different_region_types() {
        // Test that CowMemory works with different underlying MemoryRegion types
        let base = MockMemory::new();
        let mut cow = CowMemory::new(base);

        // Should be able to read from the mock memory
        assert_eq!(cow.read_u8(0x1000).unwrap(), 0);
        assert_eq!(cow.read_u8(0x1001).unwrap(), 1);

        // Should be able to write (triggering CoW)
        cow.write_u8(0x1000, 42).unwrap();

        // Should read modified value from overlay
        assert_eq!(cow.read_u8(0x1000).unwrap(), 42);
        // Should read original value from base for unmodified addresses
        assert_eq!(cow.read_u8(0x1001).unwrap(), 1);

        // Should have created overlay region
        assert_eq!(cow.overlay_regions().count(), 1);

        // Base should still have original value
        assert_eq!(cow.base().read_u8(0x1000).unwrap(), 0);
    }

    #[test]
    fn test_cow_memory_write_to_mapped_region() {
        // Test the specific case that was failing: write to address within a mapped overlay region
        let base = create_base_memory();
        let mut cow = CowMemory::new(base);

        // Map a large region (like a stack)
        let stack_base = 0x7fff_f000_0000u64;
        let stack_size = 0x100000; // 1MB
        cow.map(
            stack_base - stack_size,
            stack_size as usize,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

        // Should have one overlay region
        assert_eq!(cow.overlay_regions().count(), 1);

        // Test writing to various addresses within the mapped region
        let test_addresses = [
            stack_base - stack_size,          // Start of region
            stack_base - stack_size + 0x1000, // One page in
            stack_base - 0x1000,              // Near end of region
            stack_base - 8,                   // Very end of region (typical stack pointer)
        ];

        for &addr in &test_addresses {
            // Write should succeed
            cow.write_u8(addr, 0x42).unwrap();

            // Read back should work
            assert_eq!(cow.read_u8(addr).unwrap(), 0x42);
        }

        // Test the specific failing case from the bug report
        let failing_addr = 0x7fffeffff000; // Page-aligned address within stack
        cow.write_u8(failing_addr, 0x55).unwrap();
        assert_eq!(cow.read_u8(failing_addr).unwrap(), 0x55);

        // Should still have only one overlay region (the original mapped region)
        assert_eq!(cow.overlay_regions().count(), 1);
    }

    #[test]
    fn test_cow_memory_check_exec_fallback() {
        // Test that check_exec properly falls back to base memory
        let mut base = create_base_memory();

        // Map an executable region in base
        base.map(0x10000, 0x1000, Permission::READ | Permission::EXEC)
            .unwrap();

        let mut cow = CowMemory::new(base);

        // Map a stack region in overlay (without EXEC)
        cow.map(0x7fff0000, 0x1000, Permission::READ | Permission::WRITE)
            .unwrap();

        // check_exec should succeed for base memory executable region
        cow.check_exec(0x10000).unwrap();

        // check_exec should fail for overlay region without EXEC permission
        assert!(cow.check_exec(0x7fff0000).is_err());

        // Map an executable region in overlay
        cow.map(
            0x20000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

        // check_exec should succeed for overlay executable region
        cow.check_exec(0x20000).unwrap();

        // Test addresses not in either overlay or base
        assert!(cow.check_exec(0x50000).is_err());
    }
}
