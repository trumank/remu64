use crate::minidump_loader::MinidumpLoader;
use amd64_emu::{Engine, Memory};
use anyhow::{Context, Result};
use std::collections::HashMap;

const PAGE_SIZE: u64 = 4096;

#[derive(Debug, Clone)]
pub struct MemoryPage {
    pub base_address: u64,
    pub data: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl MemoryPage {
    pub fn new(base_address: u64, size: usize) -> Self {
        MemoryPage {
            base_address: align_down(base_address, PAGE_SIZE),
            data: vec![0; align_up(size, PAGE_SIZE as usize)],
            readable: true,
            writable: true,
            executable: false,
        }
    }

    pub fn from_data(base_address: u64, data: Vec<u8>) -> Self {
        let aligned_base = align_down(base_address, PAGE_SIZE);
        let aligned_size = align_up(data.len(), PAGE_SIZE as usize);

        let mut page_data = vec![0; aligned_size];
        let offset = (base_address - aligned_base) as usize;
        page_data[offset..offset + data.len()].copy_from_slice(&data);

        MemoryPage {
            base_address: aligned_base,
            data: page_data,
            readable: true,
            writable: true,
            executable: true,
        }
    }

    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.base_address && address < self.base_address + self.data.len() as u64
    }
}

pub struct MemoryManager {
    pages: HashMap<u64, MemoryPage>,
    minidump_loader: Option<MinidumpLoader>,
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryManager {
    pub fn new() -> Self {
        MemoryManager {
            pages: HashMap::new(),
            minidump_loader: None,
        }
    }

    pub fn with_minidump(minidump_loader: MinidumpLoader) -> Self {
        MemoryManager {
            pages: HashMap::new(),
            minidump_loader: Some(minidump_loader),
        }
    }

    pub fn handle_page_fault(
        &mut self,
        address: u64,
        _engine: &mut Engine<Memory>,
    ) -> Result<bool> {
        let page_base = align_down(address, PAGE_SIZE);

        if self.pages.contains_key(&page_base) {
            return Ok(true);
        }

        if let Some(ref loader) = self.minidump_loader {
            match loader.read_memory(page_base, PAGE_SIZE as usize) {
                Ok(data) => {
                    let page = MemoryPage::from_data(page_base, data);
                    self.pages.insert(page_base, page);
                    return Ok(true);
                }
                Err(_) => {
                    let page = MemoryPage::new(page_base, PAGE_SIZE as usize);
                    self.pages.insert(page_base, page);
                    return Ok(true);
                }
            }
        }

        let page = MemoryPage::new(page_base, PAGE_SIZE as usize);
        self.pages.insert(page_base, page);
        Ok(true)
    }

    pub fn read_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(size);
        let mut current_addr = address;
        let mut remaining = size;

        while remaining > 0 {
            let page_base = align_down(current_addr, PAGE_SIZE);

            if !self.pages.contains_key(&page_base) {
                // Try to load from minidump first
                if let Some(ref loader) = self.minidump_loader {
                    match loader.read_memory(page_base, PAGE_SIZE as usize) {
                        Ok(data) => {
                            let page = MemoryPage::from_data(page_base, data);
                            self.pages.insert(page_base, page);
                        }
                        Err(_) => {
                            // If minidump doesn't have this memory, create a dummy page
                            let page = MemoryPage::new(page_base, PAGE_SIZE as usize);
                            self.pages.insert(page_base, page);
                        }
                    }
                } else {
                    // No minidump loader, create dummy page
                    let page = MemoryPage::new(page_base, PAGE_SIZE as usize);
                    self.pages.insert(page_base, page);
                }
            }

            let page = self
                .pages
                .get(&page_base)
                .context("Page should exist after handling page fault")?;

            if !page.readable {
                anyhow::bail!(
                    "Attempted to read from non-readable memory at 0x{:x}",
                    current_addr
                );
            }

            let page_offset = (current_addr - page_base) as usize;
            let bytes_in_page = std::cmp::min(remaining, PAGE_SIZE as usize - page_offset);

            if page_offset + bytes_in_page > page.data.len() {
                anyhow::bail!("Read would exceed page bounds at 0x{:x}", current_addr);
            }

            result.extend_from_slice(&page.data[page_offset..page_offset + bytes_in_page]);

            current_addr += bytes_in_page as u64;
            remaining -= bytes_in_page;
        }

        Ok(result)
    }

    pub fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<()> {
        let mut current_addr = address;
        let mut remaining_data = data;

        while !remaining_data.is_empty() {
            let page_base = align_down(current_addr, PAGE_SIZE);

            if !self.pages.contains_key(&page_base) {
                // Try to load from minidump first
                if let Some(ref loader) = self.minidump_loader {
                    match loader.read_memory(page_base, PAGE_SIZE as usize) {
                        Ok(data) => {
                            let page = MemoryPage::from_data(page_base, data);
                            self.pages.insert(page_base, page);
                        }
                        Err(_) => {
                            // If minidump doesn't have this memory, create a dummy page
                            let page = MemoryPage::new(page_base, PAGE_SIZE as usize);
                            self.pages.insert(page_base, page);
                        }
                    }
                } else {
                    // No minidump loader, create dummy page
                    let page = MemoryPage::new(page_base, PAGE_SIZE as usize);
                    self.pages.insert(page_base, page);
                }
            }

            let page = self
                .pages
                .get_mut(&page_base)
                .context("Page should exist after handling page fault")?;

            if !page.writable {
                anyhow::bail!(
                    "Attempted to write to non-writable memory at 0x{:x}",
                    current_addr
                );
            }

            let page_offset = (current_addr - page_base) as usize;
            let bytes_in_page =
                std::cmp::min(remaining_data.len(), PAGE_SIZE as usize - page_offset);

            if page_offset + bytes_in_page > page.data.len() {
                anyhow::bail!("Write would exceed page bounds at 0x{:x}", current_addr);
            }

            page.data[page_offset..page_offset + bytes_in_page]
                .copy_from_slice(&remaining_data[..bytes_in_page]);

            current_addr += bytes_in_page as u64;
            remaining_data = &remaining_data[bytes_in_page..];
        }

        Ok(())
    }

    pub fn map_memory(&mut self, base_address: u64, data: Vec<u8>, executable: bool) -> Result<()> {
        let aligned_base = align_down(base_address, PAGE_SIZE);
        let mut page = MemoryPage::from_data(base_address, data);
        page.executable = executable;
        self.pages.insert(aligned_base, page);
        Ok(())
    }

    pub fn allocate_stack(&mut self, size: u64) -> Result<u64> {
        let stack_base = 0x500000u64;
        let aligned_size = align_up(size as usize, PAGE_SIZE as usize);

        for i in 0..(aligned_size / PAGE_SIZE as usize) {
            let page_addr = stack_base - ((i + 1) as u64 * PAGE_SIZE);
            let page = MemoryPage::new(page_addr, PAGE_SIZE as usize);
            self.pages.insert(page_addr, page);
        }

        Ok(stack_base)
    }

    pub fn is_executable(&self, address: u64) -> bool {
        let page_base = align_down(address, PAGE_SIZE);
        self.pages
            .get(&page_base)
            .is_some_and(|page| page.executable)
    }

    pub fn get_loader(&self) -> &MinidumpLoader {
        self.minidump_loader
            .as_ref()
            .expect("MinidumpLoader not available")
    }
}

fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

fn align_up(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}
