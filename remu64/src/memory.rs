use crate::DEFAULT_PAGE_SIZE;
use crate::error::{EmulatorError, Result};
use bitflags::bitflags;
use std::{collections::BTreeMap, ops::Range};

fn assert_valid_region(addr: u64, size: usize, page_size: u64, operation: &str) {
    assert_eq!(
        addr & (page_size - 1),
        0,
        "{}() addr must be page-aligned: {:#x}",
        operation,
        addr
    );
    assert!(size > 0, "{}() size must > 0: {:#x}", operation, addr);
    assert_eq!(
        size & (page_size as usize - 1),
        0,
        "{}() size must be page-aligned: {:#x}",
        operation,
        size
    );
}

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

/// **IMPORTANT: Memory regions must be aligned to page boundaries.**
#[derive(Clone)]
pub struct MemoryRegion {
    pub address: u64,
    pub data: Vec<u8>,
    pub permissions: Permission,
}
/// **IMPORTANT: Memory regions must be aligned to page boundaries.**
#[derive(Clone)]
pub struct MemoryRegionRef<'a> {
    pub address: u64,
    pub data: &'a [u8],
    pub permissions: Permission,
}
/// **IMPORTANT: Memory regions must be aligned to page boundaries.**
pub struct MemoryRegionMut<'a> {
    pub address: u64,
    pub data: &'a mut [u8],
    pub permissions: Permission,
}

macro_rules! region {
    ($name:ident) => {
        pub fn start(&self) -> u64 {
            self.address
        }
        pub fn end(&self) -> u64 {
            self.address + self.data.len() as u64
        }
        pub fn range(&self) -> Range<u64> {
            self.start()..self.end()
        }
        pub fn contains(&self, addr: u64) -> bool {
            self.range().contains(&addr)
        }
        pub fn size(&self) -> usize {
            (self.end() - self.start()) as usize
        }
        pub fn offset(&self, addr: u64) -> usize {
            assert!(self.contains(addr));
            (addr - self.address) as usize
        }
    };
}
impl MemoryRegion {
    region!(MemoryRegionOwned);
}
impl MemoryRegionRef<'_> {
    region!(MemoryRegionOwned);
}
impl MemoryRegionMut<'_> {
    region!(MemoryRegionOwned);
}

impl MemoryRegion {
    pub fn new(address: u64, size: usize, permissions: Permission) -> Self {
        assert_valid_region(address, size, DEFAULT_PAGE_SIZE, "MemoryRegion::new");

        Self {
            address,
            permissions,
            data: vec![0; size],
        }
    }
    pub fn as_ref(&self) -> MemoryRegionRef<'_> {
        MemoryRegionRef {
            address: self.address,
            data: &self.data,
            permissions: self.permissions,
        }
    }
    pub fn as_mut(&mut self) -> MemoryRegionMut<'_> {
        MemoryRegionMut {
            address: self.address,
            data: &mut self.data,
            permissions: self.permissions,
        }
    }
}

pub trait MemoryTrait<const PS: u64 = DEFAULT_PAGE_SIZE> {
    /// Find a memory region containing the given address.
    ///
    /// **IMPORTANT: This method is for optimization purposes ONLY.**
    /// It is NOT required to return a region even if the address is valid.
    /// If this method returns `None`, callers should fall back to using
    /// `read`/`write` methods instead.
    fn find_region(&self, addr: u64) -> Option<MemoryRegionRef<'_>>;

    /// Find a mutable memory region containing the given address.
    ///
    /// **IMPORTANT: This method is for optimization purposes ONLY.**
    /// It is NOT required to return a region even if the address is valid.
    /// If this method returns `None`, callers should fall back to using
    /// `read`/`write` methods instead.
    fn find_region_mut(&mut self, addr: u64) -> Option<MemoryRegionMut<'_>>;

    /// Get the permissions for the memory at the given address.
    /// Returns the permissions if the address is valid, or an error if unmapped.
    fn permissions(&self, addr: u64) -> Result<Permission>;

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < buf.len() {
            let region = self
                .find_region(current_addr)
                .ok_or(EmulatorError::UnmappedMemory(current_addr))?;

            if !region.permissions.contains(Permission::READ) {
                return Err(EmulatorError::PermissionDenied(current_addr));
            }

            let region_offset = region.offset(current_addr);
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, buf.len() - offset);

            buf[offset..offset + to_copy]
                .copy_from_slice(&region.data[region_offset..region_offset + to_copy]);

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

            if !region.permissions.contains(Permission::WRITE) {
                return Err(EmulatorError::PermissionDenied(current_addr));
            }

            let region_offset = region.offset(current_addr);
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);

            region.data[region_offset..region_offset + to_copy]
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

            let region_offset = region.offset(current_addr);
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);

            region.data[region_offset..region_offset + to_copy]
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

    /// Map memory at the given address with the specified permissions.
    ///
    /// **IMPORTANT: All parameters must be aligned to page boundaries.**
    /// - `addr` must be page-aligned
    /// - `size` must be a multiple of the page size
    fn map(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()>;

    /// Unmap memory at the given address.
    ///
    /// **IMPORTANT: All parameters must be aligned to page boundaries.**
    /// - `addr` must be page-aligned
    /// - `size` must be a multiple of the page size
    fn unmap(&mut self, addr: u64, size: usize) -> Result<()>;

    /// Change memory permissions for the given address range.
    ///
    /// **IMPORTANT: All parameters must be aligned to page boundaries.**
    /// - `addr` must be page-aligned
    /// - `size` must be a multiple of the page size
    fn protect(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()>;
}

pub struct OwnedMemory<const PS: u64 = DEFAULT_PAGE_SIZE> {
    regions: BTreeMap<u64, MemoryRegion>,
}

impl<const PS: u64> Default for OwnedMemory<PS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const PS: u64> OwnedMemory<PS> {
    pub fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
        }
    }
    pub fn regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions.values()
    }
}

impl<const PS: u64> MemoryTrait<PS> for OwnedMemory<PS> {
    fn find_region(&self, addr: u64) -> Option<MemoryRegionRef<'_>> {
        self.regions
            .range(..=addr)
            .next_back()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region.as_ref())
                } else {
                    None
                }
            })
    }

    fn find_region_mut(&mut self, addr: u64) -> Option<MemoryRegionMut<'_>> {
        self.regions
            .range_mut(..=addr)
            .next_back()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region.as_mut())
                } else {
                    None
                }
            })
    }

    fn permissions(&self, addr: u64) -> Result<Permission> {
        let region = self
            .find_region(addr)
            .ok_or(EmulatorError::UnmappedMemory(addr))?;
        Ok(region.permissions)
    }

    fn map(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        assert_valid_region(addr, size, PS, "map");

        let end = addr + size as u64;

        for region in self.regions.values() {
            if addr < region.end() && region.start() < end {
                return Err(EmulatorError::InvalidArgument(format!(
                    "Memory overlap at {:#x}-{:#x}",
                    addr, end
                )));
            }
        }

        let region = MemoryRegion::new(addr, size, perms);
        self.regions.insert(addr, region);
        Ok(())
    }

    fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        assert_valid_region(addr, size, PS, "unmap");

        let end = addr + size as u64;

        let mut to_remove = Vec::new();
        for (&start, region) in &self.regions {
            if start >= addr && region.end() <= end {
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
        assert_valid_region(addr, size, PS, "protect");

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

pub struct CowMemory<T: MemoryTrait<PS>, const PS: u64 = DEFAULT_PAGE_SIZE> {
    base: T,
    overlay: BTreeMap<u64, MemoryRegion>,
}

impl<T: MemoryTrait<PS>, const PS: u64> CowMemory<T, PS> {
    pub fn new(base: T) -> Self {
        Self {
            base,
            overlay: BTreeMap::new(),
        }
    }

    /// Reset the copy-on-write overlay, discarding all modifications
    /// and returning to the original base memory state
    pub fn reset_to_base(&mut self) {
        self.overlay.clear();
    }

    pub fn base(&self) -> &T {
        &self.base
    }

    pub fn overlay_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.overlay.values()
    }

    fn copy_page(&mut self, addr: u64) -> Result<()> {
        let page_addr = addr & !(PS - 1);

        if self.overlay.contains_key(&page_addr) {
            return Ok(());
        }

        // Try to read a full page from base memory to determine actual accessible size
        let mut page_data = vec![0u8; PS as usize];
        let mut actual_size = 0;

        // Read byte by byte to find the extent of readable memory
        for offset in 0..PS as usize {
            match self.base.read(page_addr + offset as u64, &mut [0u8; 1]) {
                Ok(_) => actual_size += 1,
                Err(_) => break, // Stop at first inaccessible byte
            }
        }

        if actual_size == 0 {
            return Err(EmulatorError::UnmappedMemory(page_addr));
        }

        // Read the actual accessible data
        page_data.resize(actual_size, 0);
        self.base.read(page_addr, &mut page_data)?;

        // Get permissions from the base memory
        let perms = self.base.permissions(page_addr)?;

        let mut cow_region = MemoryRegion::new(page_addr, actual_size, perms);
        cow_region.data.copy_from_slice(&page_data);

        self.overlay.insert(page_addr, cow_region);
        Ok(())
    }
}

impl<T: MemoryTrait<PS>, const PS: u64> MemoryTrait<PS> for CowMemory<T, PS> {
    /// Find a region in the CoW overlay only (optimization method).
    ///
    /// This only searches overlay regions for performance. If no overlay
    /// region is found, this returns `None` even if the address exists
    /// in the base memory. Callers must fall back to `read`/`write`.
    fn find_region(&self, addr: u64) -> Option<MemoryRegionRef<'_>> {
        self.overlay
            .range(..=addr)
            .next_back()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region.as_ref())
                } else {
                    None
                }
            })
    }

    /// Find a mutable region in the CoW overlay only (optimization method).
    ///
    /// This only searches overlay regions for performance. If no overlay
    /// region is found, this returns `None` even if the address exists
    /// in the base memory. Callers must fall back to `read`/`write`.
    fn find_region_mut(&mut self, addr: u64) -> Option<MemoryRegionMut<'_>> {
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
            .map(|overlay_region| overlay_region.as_mut())
    }

    fn permissions(&self, addr: u64) -> Result<Permission> {
        // First check overlay regions
        if let Some(region) = self.find_region(addr) {
            return Ok(region.permissions);
        }

        // Fall back to base memory
        self.base.permissions(addr)
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < buf.len() {
            // First check overlay
            if let Some(overlay_region) = self.find_region(current_addr) {
                let region_offset = overlay_region.offset(current_addr);
                let available = overlay_region.size() - region_offset;
                let to_copy = std::cmp::min(available, buf.len() - offset);

                buf[offset..offset + to_copy]
                    .copy_from_slice(&overlay_region.data[region_offset..region_offset + to_copy]);

                offset += to_copy;
                current_addr += to_copy as u64;
            } else {
                // Fall back to base memory - use base.read() instead of find_region
                // since find_region is optimization-only and may return None for valid addresses
                let remaining = buf.len() - offset;
                self.base
                    .read(current_addr, &mut buf[offset..offset + remaining])?;

                // If we got here, the entire remaining buffer was read successfully
                break;
            }
        }

        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;

        while offset < data.len() {
            let page_addr = current_addr & !(PS - 1);

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

            if !region.permissions.contains(Permission::WRITE) {
                return Err(EmulatorError::PermissionDenied(current_addr));
            }

            let region_offset = region.offset(current_addr);
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);

            region.data[region_offset..region_offset + to_copy]
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
            let page_addr = current_addr & !(PS - 1);

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

            let region_offset = region.offset(current_addr);
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);

            region.data[region_offset..region_offset + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);

            offset += to_copy;
            current_addr += to_copy as u64;
        }

        Ok(())
    }

    fn map(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        assert_valid_region(addr, size, PS, "map");

        let end = addr + size as u64;

        for region in self.overlay.values() {
            if addr < region.end() && region.start() < end {
                return Err(EmulatorError::InvalidArgument(format!(
                    "Memory overlap at {:#x}-{:#x}",
                    addr, end
                )));
            }
        }

        // Check for overlap with base memory by testing if any part of the range is readable
        // We test a few key points: start, middle, and end of the range
        let test_points = [addr, addr + size as u64 / 2, end - 1];

        for &test_addr in &test_points {
            if self.base.read(test_addr, &mut [0u8; 1]).is_ok() {
                return Err(EmulatorError::InvalidArgument(format!(
                    "Memory overlap with base at {:#x}-{:#x}",
                    addr, end
                )));
            }
        }

        let region = MemoryRegion::new(addr, size, perms);
        self.overlay.insert(addr, region);
        Ok(())
    }

    fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        assert_valid_region(addr, size, PS, "unmap");

        let end = addr + size as u64;

        let mut to_remove = Vec::new();
        for (&start, region) in &self.overlay {
            if start >= addr && region.end() <= end {
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
        assert_valid_region(addr, size, PS, "protect");

        let end = addr + size as u64;

        let mut regions_to_update = Vec::new();
        for (&start, region) in &self.overlay {
            if addr < region.end() && region.start() < end {
                regions_to_update.push(start);
            }
        }

        if regions_to_update.is_empty() {
            return Err(EmulatorError::UnmappedMemory(addr));
        }

        for start in regions_to_update {
            if let Some(region) = self.overlay.get_mut(&start) {
                region.permissions = perms;
            }
        }

        Ok(())
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
        assert_eq!(overlay_region.start(), 0x1000);
        assert_eq!(overlay_region.end(), 0x2000);

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
        let mut base = <OwnedMemory>::new();
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
        let mut base = <OwnedMemory>::new();
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
    fn test_cow_memory_permissions_fallback() {
        // Test that permissions properly falls back to base memory
        let mut base = create_base_memory();

        // Map an executable region in base
        base.map(0x10000, 0x1000, Permission::READ | Permission::EXEC)
            .unwrap();

        let mut cow = CowMemory::new(base);

        // Map a stack region in overlay (without EXEC)
        cow.map(0x7fff0000, 0x1000, Permission::READ | Permission::WRITE)
            .unwrap();

        // permissions should return EXEC for base memory executable region
        let perms = cow.permissions(0x10000).unwrap();
        assert!(perms.contains(Permission::EXEC));

        // permissions should not return EXEC for overlay region without EXEC permission
        let perms = cow.permissions(0x7fff0000).unwrap();
        assert!(!perms.contains(Permission::EXEC));
        assert!(perms.contains(Permission::READ | Permission::WRITE));

        // Map an executable region in overlay
        cow.map(
            0x20000,
            0x1000,
            Permission::READ | Permission::WRITE | Permission::EXEC,
        )
        .unwrap();

        // permissions should return EXEC for overlay executable region
        let perms = cow.permissions(0x20000).unwrap();
        assert!(perms.contains(Permission::EXEC));

        // Test addresses not in either overlay or base
        assert!(cow.permissions(0x50000).is_err());
    }
}
