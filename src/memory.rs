use crate::error::{EmulatorError, Result};
use bitflags::bitflags;
use std::collections::BTreeMap;
use std::ops::Range;

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

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub perms: Permission,
    pub data: Vec<u8>,
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
    
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
    
    pub fn size(&self) -> usize {
        (self.end - self.start) as usize
    }
    
    pub fn offset(&self, addr: u64) -> Option<usize> {
        if self.contains(addr) {
            Some((addr - self.start) as usize)
        } else {
            None
        }
    }
}

pub struct Memory {
    regions: BTreeMap<u64, MemoryRegion>,
    page_size: usize,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            page_size: 4096,
        }
    }
    
    pub fn map(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        if size == 0 {
            return Err(EmulatorError::InvalidArgument("Size cannot be zero".into()));
        }
        
        let aligned_addr = addr & !(self.page_size as u64 - 1);
        let aligned_size = ((addr - aligned_addr) as usize + size + self.page_size - 1) 
            & !(self.page_size - 1);
        
        let end = aligned_addr + aligned_size as u64;
        
        for (_, region) in &self.regions {
            if (aligned_addr >= region.start && aligned_addr < region.end) ||
               (end > region.start && end <= region.end) ||
               (aligned_addr <= region.start && end >= region.end) {
                return Err(EmulatorError::InvalidArgument(
                    format!("Memory overlap at {:#x}-{:#x}", aligned_addr, end)
                ));
            }
        }
        
        let region = MemoryRegion::new(aligned_addr, aligned_size, perms);
        self.regions.insert(aligned_addr, region);
        Ok(())
    }
    
    pub fn unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        let aligned_addr = addr & !(self.page_size as u64 - 1);
        let aligned_size = ((addr - aligned_addr) as usize + size + self.page_size - 1) 
            & !(self.page_size - 1);
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
    
    pub fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions
            .range(..=addr)
            .rev()
            .next()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region)
                } else {
                    None
                }
            })
    }
    
    pub fn find_region_mut(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        self.regions
            .range_mut(..=addr)
            .rev()
            .next()
            .and_then(|(_, region)| {
                if region.contains(addr) {
                    Some(region)
                } else {
                    None
                }
            })
    }
    
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;
        
        while offset < buf.len() {
            let region = self.find_region(current_addr)
                .ok_or(EmulatorError::UnmappedMemory(current_addr))?;
            
            if !region.perms.contains(Permission::READ) {
                return Err(EmulatorError::PermissionDenied(current_addr));
            }
            
            let region_offset = region.offset(current_addr).unwrap();
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, buf.len() - offset);
            
            buf[offset..offset + to_copy].copy_from_slice(
                &region.data[region_offset..region_offset + to_copy]
            );
            
            offset += to_copy;
            current_addr += to_copy as u64;
        }
        
        Ok(())
    }
    
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        let mut current_addr = addr;
        
        while offset < data.len() {
            let region = self.find_region_mut(current_addr)
                .ok_or(EmulatorError::UnmappedMemory(current_addr))?;
            
            if !region.perms.contains(Permission::WRITE) {
                return Err(EmulatorError::PermissionDenied(current_addr));
            }
            
            let region_offset = region.offset(current_addr).unwrap();
            let available = region.size() - region_offset;
            let to_copy = std::cmp::min(available, data.len() - offset);
            
            region.data[region_offset..region_offset + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            
            offset += to_copy;
            current_addr += to_copy as u64;
        }
        
        Ok(())
    }
    
    pub fn read_u8(&self, addr: u64) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read(addr, &mut buf)?;
        Ok(buf[0])
    }
    
    pub fn read_u16(&self, addr: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read(addr, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }
    
    pub fn read_u32(&self, addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
    
    pub fn read_u64(&self, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
    
    pub fn write_u8(&mut self, addr: u64, value: u8) -> Result<()> {
        self.write(addr, &[value])
    }
    
    pub fn write_u16(&mut self, addr: u64, value: u16) -> Result<()> {
        self.write(addr, &value.to_le_bytes())
    }
    
    pub fn write_u32(&mut self, addr: u64, value: u32) -> Result<()> {
        self.write(addr, &value.to_le_bytes())
    }
    
    pub fn write_u64(&mut self, addr: u64, value: u64) -> Result<()> {
        self.write(addr, &value.to_le_bytes())
    }
    
    pub fn check_exec(&self, addr: u64) -> Result<()> {
        let region = self.find_region(addr)
            .ok_or(EmulatorError::UnmappedMemory(addr))?;
        
        if !region.perms.contains(Permission::EXEC) {
            return Err(EmulatorError::PermissionDenied(addr));
        }
        
        Ok(())
    }
    
    pub fn protect(&mut self, addr: u64, size: usize, perms: Permission) -> Result<()> {
        let end = addr + size as u64;
        
        let mut regions_to_update = Vec::new();
        for (&start, region) in &self.regions {
            if (addr >= region.start && addr < region.end) ||
               (end > region.start && end <= region.end) ||
               (addr <= region.start && end >= region.end) {
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
    
    pub fn regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions.values()
    }
    
    pub fn total_size(&self) -> usize {
        self.regions.values().map(|r| r.size()).sum()
    }
}