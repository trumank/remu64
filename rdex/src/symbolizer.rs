use remu64::memory::MemoryTrait;

/// Information about a resolved symbol
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: Option<String>,
    pub module: String,
}

/// A resolved symbol with offset information
#[derive(Debug)]
pub struct ResolvedSymbol<'a> {
    pub symbol: &'a SymbolInfo,
    pub offset: u64, // Offset from the symbol's base address
}

/// Object-safe trait for resolving addresses to symbols
pub trait Symbolizer {
    /// Resolve an address to a symbol if possible, returning the symbol and offset
    fn resolve_address(
        &mut self,
        memory: &dyn MemoryTrait,
        address: u64,
    ) -> Option<ResolvedSymbol<'_>>;
}
