use remu64::{DEFAULT_PAGE_SIZE, memory::MemoryTrait};

/// Information about a resolved symbol
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub module: String,
}

/// Trait for resolving addresses to symbols
pub trait Symbolizer<M: MemoryTrait<PS>, const PS: u64 = DEFAULT_PAGE_SIZE> {
    /// Resolve an address to a symbol if possible
    fn resolve_address(&mut self, memory: &M, address: u64) -> Option<&SymbolInfo>;
}

/// A no-op symbolizer that doesn't resolve any symbols
pub struct NoSymbolizer;

impl<M: MemoryTrait<PS>, const PS: u64> Symbolizer<M, PS> for NoSymbolizer {
    fn resolve_address(&mut self, _memory: &M, _address: u64) -> Option<&SymbolInfo> {
        None
    }
}
