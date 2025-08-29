use std::collections::HashMap;
use std::path::Path;

use crate::process_trait::ProcessTrait;
use crate::symbolizer::{ResolvedSymbol, SymbolInfo, Symbolizer};
use anyhow::{Result, anyhow};
use pdb::FallibleIterator;
use remu64::memory::MemoryTrait;

#[derive(Debug, Clone)]
struct ModuleRange {
    start: u64,
    end: u64,
    name: String,
    base_address: u64,
    analyzed: bool,
}

#[derive(Debug, Clone)]
pub struct PdbInfo {
    pub guid: [u8; 16],
    pub age: u32,
    pub filename: String,
}

#[derive(Debug, Clone)]
struct ProcedureRange {
    start: u64,
    end: u64,
    symbol: SymbolInfo,
}

// Hash bucket approach for fast range lookups
// Bucket size: 4KB (page size) for good cache locality and reasonable bucket fill
const BUCKET_SIZE: u64 = 4096;

#[derive(Debug, Default)]
struct RangeBucket {
    ranges: Vec<ProcedureRange>,
}

/// A symbolizer that resolves symbols from PE files loaded in a minidump
pub struct PeSymbolizer {
    module_ranges: Vec<ModuleRange>, // sorted by start address for binary search
    symbol_cache: SymbolCache,       // Point symbols (exports, imports, data)
    pdb_info_cache: HashMap<u64, Option<PdbInfo>>, // base_address -> PdbInfo
    range_buckets: HashMap<u64, RangeBucket>, // bucket_id -> ranges in bucket
}

type SymbolCache = HashMap<u64, SymbolInfo>;

impl<M: MemoryTrait> Symbolizer<M> for PeSymbolizer {
    fn resolve_address(&mut self, memory: &M, address: u64) -> Option<ResolvedSymbol<'_>> {
        // Use binary search to find the module containing this address
        let module_idx = self.module_ranges.binary_search_by(|range| {
            if address < range.start {
                std::cmp::Ordering::Greater
            } else if address >= range.end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        });

        if let Ok(idx) = module_idx {
            let module = &mut self.module_ranges[idx];

            if !module.analyzed {
                let _res = analyze_module(
                    &mut self.symbol_cache,
                    &mut self.pdb_info_cache,
                    &mut self.range_buckets,
                    &module.name,
                    module.base_address,
                    memory,
                );
            }
            module.analyzed = true;
        }

        self.resolve_symbol_with_offset(address)
    }
}

fn read_cstring<M: MemoryTrait>(memory: &M, mut address: u64) -> Result<String> {
    let mut result = Vec::new();
    loop {
        let mut byte = 0;
        memory.read(address, std::slice::from_mut(&mut byte))?;
        if byte == 0 {
            break;
        }
        result.push(byte);
        address += 1;
        if result.len() > 1024 {
            return Err(anyhow!("String too long"));
        }
    }
    Ok(String::from_utf8_lossy(&result).to_string())
}

impl PeSymbolizer {
    pub fn new<P: ProcessTrait>(process: P) -> Self {
        // Pre-populate module ranges cache sorted by start address
        let mut module_ranges: Vec<ModuleRange> = process
            .list_modules()
            .into_iter()
            .map(|module| {
                let filename = module
                    .name
                    .rfind(['/', '\\'])
                    .map(|pos| &module.name[pos + 1..])
                    .unwrap_or(&module.name)
                    .to_string();

                ModuleRange {
                    start: module.base_address,
                    end: module.base_address + module.size,
                    name: filename,
                    base_address: module.base_address,
                    analyzed: false,
                }
            })
            .collect();

        // Sort by start address for binary search
        module_ranges.sort_by_key(|range| range.start);

        Self {
            module_ranges,
            symbol_cache: HashMap::new(),
            pdb_info_cache: HashMap::new(),
            range_buckets: HashMap::new(),
        }
    }

    pub fn resolve_symbol_with_offset(&self, address: u64) -> Option<ResolvedSymbol<'_>> {
        if let Some(symbol) = self.find_procedure_symbol_with_offset(address) {
            Some(symbol)
        } else {
            self.symbol_cache
                .get(&address)
                .map(|symbol| ResolvedSymbol { symbol, offset: 0 })
        }
    }

    fn find_procedure_symbol_with_offset(&self, address: u64) -> Option<ResolvedSymbol<'_>> {
        let bucket_id = address / BUCKET_SIZE;

        if let Some(bucket) = self.range_buckets.get(&bucket_id) {
            for range in &bucket.ranges {
                if address >= range.start && address < range.end {
                    return Some(ResolvedSymbol {
                        symbol: &range.symbol,
                        offset: address - range.start,
                    });
                }
            }
        }

        None
    }

    pub fn get_pdb_info(&self, base_address: u64) -> Option<&PdbInfo> {
        self.pdb_info_cache.get(&base_address)?.as_ref()
    }
}

fn analyze_module<M>(
    cache: &mut SymbolCache,
    pdb_cache: &mut HashMap<u64, Option<PdbInfo>>,
    range_buckets: &mut HashMap<u64, RangeBucket>,
    module_name: &str,
    base_address: u64,
    memory: &M,
) -> Result<()>
where
    M: MemoryTrait,
{
    // Parse DOS header
    let signature = memory.read_u16(base_address)?;
    if signature != 0x5A4D {
        return Err(anyhow!("Invalid DOS signature"));
    }
    let e_lfanew = memory.read_u32(base_address + 0x3c)?;

    let pe_offset = base_address + e_lfanew as u64;

    // verify COFF_Header
    let pe_signature = memory.read_u32(pe_offset)?;
    if pe_signature != 0x00004550 {
        return Err(anyhow!("Invalid PE signature"));
    }

    let opt_header_offset = pe_offset + 0x18;
    let opt_header_signature = memory.read_u16(opt_header_offset)?;
    if opt_header_signature != 0x20b {
        return Err(anyhow!("Not PE_64BIT"));
    }

    let data_dir_offset = opt_header_offset + 0x70;

    // Parse import table
    if let Some(import_dir) = get_data_directory(memory, data_dir_offset, 1)? {
        parse_import_table(
            cache,
            memory,
            base_address + import_dir as u64,
            base_address,
        )?;
    }

    // Parse export table
    if let Some(export_dir) = get_data_directory(memory, data_dir_offset, 0)? {
        parse_export_table(
            cache,
            memory,
            base_address + export_dir as u64,
            base_address,
            module_name,
        )?;
    }

    // Parse debug directory (data directory entry 6)
    let pdb_info = if let Some(debug_dir) = get_data_directory(memory, data_dir_offset, 6)? {
        parse_debug_directory(memory, base_address + debug_dir as u64, base_address)?
    } else {
        None
    };

    // Attempt to load symbols from PDB file if available
    if let Some(ref pdb_info) = pdb_info {
        let _ = load_pdb_symbols(cache, range_buckets, &pdb_info.filename, base_address);
    }

    pdb_cache.insert(base_address, pdb_info);

    Ok(())
}

fn get_data_directory<M: MemoryTrait>(
    memory: &M,
    data_dir_base: u64,
    index: u32,
) -> Result<Option<u32>> {
    let offset = data_dir_base + (index * 8) as u64;
    let virtual_address = memory.read_u32(offset)?;
    let size = memory.read_u32(offset + 4)?;

    if virtual_address == 0 || size == 0 {
        return Ok(None);
    }

    Ok(Some(virtual_address))
}

fn parse_import_table<M: MemoryTrait>(
    cache: &mut SymbolCache,
    memory: &M,
    import_table_address: u64,
    base_address: u64,
) -> Result<()> {
    let mut offset = 0;
    loop {
        let descriptor_address = import_table_address + offset;

        let import_lookup_table = memory.read_u32(descriptor_address)?;
        let time_date_stamp = memory.read_u32(descriptor_address + 4)?;
        let forwarder_chain = memory.read_u32(descriptor_address + 8)?;
        let name_rva = memory.read_u32(descriptor_address + 12)?;
        let import_address_table = memory.read_u32(descriptor_address + 16)?;

        if import_lookup_table == 0
            && time_date_stamp == 0
            && forwarder_chain == 0
            && name_rva == 0
            && import_address_table == 0
        {
            break;
        }

        if name_rva != 0 {
            let dll_name = read_cstring(memory, base_address + name_rva as u64)?;

            let lookup_table_address = base_address + import_lookup_table as u64;
            let iat_address = base_address + import_address_table as u64;

            parse_import_address_table(
                cache,
                memory,
                lookup_table_address,
                iat_address,
                base_address,
                &dll_name,
            )?;
        }

        offset += 20;
    }
    Ok(())
}

fn parse_import_address_table<M: MemoryTrait>(
    cache: &mut SymbolCache,
    memory: &M,
    lookup_table_address: u64,
    iat_address: u64,
    base_address: u64,
    dll_name: &str,
) -> Result<()> {
    let mut offset = 0;
    loop {
        let lookup_entry = memory.read_u64(lookup_table_address + offset)?;
        if lookup_entry == 0 {
            break;
        }

        let symbol_name = if (lookup_entry & 0x8000000000000000) != 0 {
            let ordinal = lookup_entry & 0xFFFF;
            format!("{}#{}", dll_name, ordinal)
        } else {
            let name_table_rva = lookup_entry & 0x7FFFFFFF;
            let hint_name_address = base_address + name_table_rva;
            let name = read_cstring(memory, hint_name_address + 2)?;
            format!("{}!{}", dll_name, name)
        };

        let iat_entry_address = iat_address + offset;
        let function_address = memory.read_u64(iat_entry_address)?;
        let symbol = SymbolInfo {
            name: symbol_name,
            module: dll_name.to_string(),
        };
        cache.insert(function_address, symbol);

        offset += 8;
    }
    Ok(())
}

fn parse_export_table<M: MemoryTrait>(
    cache: &mut SymbolCache,
    memory: &M,
    export_table_address: u64,
    base_address: u64,
    module_name: &str,
) -> Result<()> {
    let base_ordinal = memory.read_u32(export_table_address + 16)?;
    let number_of_functions = memory.read_u32(export_table_address + 20)?;
    let number_of_names = memory.read_u32(export_table_address + 24)?;
    let address_of_functions_rva = memory.read_u32(export_table_address + 28)?;
    let address_of_names_rva = memory.read_u32(export_table_address + 32)?;
    let address_of_name_ordinals_rva = memory.read_u32(export_table_address + 36)?;

    let functions_table = base_address + address_of_functions_rva as u64;
    let names_table = base_address + address_of_names_rva as u64;
    let ordinals_table = base_address + address_of_name_ordinals_rva as u64;

    for i in 0..number_of_names {
        let name_rva_address = names_table + (i * 4) as u64;
        let name_rva = memory.read_u32(name_rva_address)?;
        let function_name = read_cstring(memory, base_address + name_rva as u64)?;

        let ordinal_address = ordinals_table + (i * 2) as u64;
        let ordinal_index = memory.read_u16(ordinal_address)? as u32;

        if ordinal_index < number_of_functions {
            let function_address_rva_address = functions_table + (ordinal_index * 4) as u64;
            let function_rva = memory.read_u32(function_address_rva_address)?;

            if function_rva != 0 {
                let function_address = base_address + function_rva as u64;

                cache.insert(
                    function_address,
                    SymbolInfo {
                        name: format!("{}!{}", module_name, function_name),
                        module: module_name.to_string(),
                    },
                );
            }
        }
    }

    for ordinal_index in 0..number_of_functions {
        let function_address_rva_address = functions_table + (ordinal_index * 4) as u64;
        let function_rva = memory.read_u32(function_address_rva_address)?;

        if function_rva != 0 {
            let function_address = base_address + function_rva as u64;

            cache.entry(function_address).or_insert_with(|| {
                let ordinal = base_ordinal + ordinal_index;
                SymbolInfo {
                    name: format!("{}!#{}", module_name, ordinal),
                    module: module_name.to_string(),
                }
            });
        }
    }

    Ok(())
}

fn parse_debug_directory<M: MemoryTrait>(
    memory: &M,
    debug_dir_address: u64,
    base_address: u64,
) -> Result<Option<PdbInfo>> {
    // Debug directory entry structure:
    // DWORD Characteristics;    // 0x00 - unused
    // DWORD TimeDateStamp;      // 0x04
    // WORD  MajorVersion;       // 0x08
    // WORD  MinorVersion;       // 0x0A
    // DWORD Type;               // 0x0C - IMAGE_DEBUG_TYPE_CODEVIEW = 2
    // DWORD SizeOfData;         // 0x10
    // DWORD AddressOfRawData;   // 0x14 - RVA to debug info
    // DWORD PointerToRawData;   // 0x18 - file offset (we use RVA)

    let mut offset = 0;
    loop {
        let entry_address = debug_dir_address + offset;

        // Read debug directory entry
        let characteristics = memory.read_u32(entry_address)?;
        // let timestamp = memory.read_u32(entry_address + 4)?;
        // let major_version = memory.read_u16(entry_address + 8)?;
        // let minor_version = memory.read_u16(entry_address + 10)?;
        let debug_type = memory.read_u32(entry_address + 12)?;
        let size_of_data = memory.read_u32(entry_address + 16)?;
        let address_of_raw_data = memory.read_u32(entry_address + 20)?;

        // Check if this is the end of debug directory entries
        if characteristics == 0 && debug_type == 0 && size_of_data == 0 && address_of_raw_data == 0
        {
            break;
        }

        // IMAGE_DEBUG_TYPE_CODEVIEW = 2
        if debug_type == 2 && address_of_raw_data != 0 && size_of_data >= 24 {
            let debug_data_address = base_address + address_of_raw_data as u64;

            // Read CodeView signature (should be "RSDS" for PDB 7.0)
            let mut signature = [0; 4];
            memory.read(debug_data_address, &mut signature)?;
            if &signature == b"RSDS" {
                // Read PDB GUID (16 bytes)
                let mut guid = [0u8; 16];
                memory.read(debug_data_address + 4, &mut guid)?;

                // Read age (4 bytes)
                let age = memory.read_u32(debug_data_address + 20)?;

                // Read filename (null-terminated string after age)
                let filename_address = debug_data_address + 24;
                let filename = read_cstring(memory, filename_address)?;

                return Ok(Some(PdbInfo {
                    guid,
                    age,
                    filename,
                }));
            }
        }

        offset += 28; // Size of IMAGE_DEBUG_DIRECTORY entry
    }

    Ok(None)
}

fn load_pdb_symbols(
    cache: &mut SymbolCache,
    range_buckets: &mut HashMap<u64, RangeBucket>,
    pdb_filename: &str,
    base_address: u64,
) -> Result<()> {
    // Try to find PDB file in current directory
    let pdb_path = Path::new(pdb_filename);
    let pdb_path = if pdb_path.exists() {
        pdb_path.to_path_buf()
    } else {
        // Try just the filename in current directory
        Path::new(".").join(
            pdb_path
                .file_name()
                .ok_or_else(|| anyhow!("Invalid PDB filename"))?,
        )
    };

    if !pdb_path.exists() {
        return Ok(());
    }

    let file = std::fs::File::open(&pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;

    // Get address map for RVA translation
    let address_map = pdb.address_map()?;

    // Load global symbols
    if let Ok(symbol_table) = pdb.global_symbols() {
        load_symbols_from_iter(
            cache,
            range_buckets,
            symbol_table.iter(),
            base_address,
            &address_map,
        )?;
    }

    // Load module-specific symbols
    if let Ok(dbi) = pdb.debug_information()
        && let Ok(mut modules) = dbi.modules()
    {
        while let Some(module) = modules.next()? {
            if let Some(info) = pdb.module_info(&module)?
                && let Ok(symbols) = info.symbols()
            {
                load_symbols_from_iter(cache, range_buckets, symbols, base_address, &address_map)?;
            }
        }
    }

    Ok(())
}

fn load_symbols_from_iter(
    cache: &mut SymbolCache,
    range_buckets: &mut HashMap<u64, RangeBucket>,
    mut symbols: pdb::SymbolIter<'_>,
    base_address: u64,
    address_map: &pdb::AddressMap,
) -> Result<()> {
    while let Some(symbol) = symbols.next()? {
        if let Ok(symbol_data) = symbol.parse() {
            match symbol_data {
                pdb::SymbolData::Public(data) => {
                    if let Some(rva) = data.offset.to_rva(address_map) {
                        let address = base_address + rva.0 as u64;
                        let symbol_info = SymbolInfo {
                            name: data.name.to_string().into_owned(),
                            module: "pdb".to_string(),
                        };
                        cache.insert(address, symbol_info);
                    }
                }
                pdb::SymbolData::Procedure(data) => {
                    if let Some(rva) = data.offset.to_rva(address_map) {
                        let start_address = base_address + rva.0 as u64;
                        let end_address = start_address + data.len as u64;
                        let symbol_info = SymbolInfo {
                            name: data.name.to_string().into_owned(),
                            module: "pdb".to_string(),
                        };

                        // Add to range buckets for fast interval lookup
                        add_procedure_range_to_buckets(
                            range_buckets,
                            start_address,
                            end_address,
                            symbol_info,
                        );
                    }
                }
                pdb::SymbolData::Data(data) => {
                    if let Some(rva) = data.offset.to_rva(address_map) {
                        let address = base_address + rva.0 as u64;
                        let symbol_info = SymbolInfo {
                            name: data.name.to_string().into_owned(),
                            module: "pdb".to_string(),
                        };
                        cache.insert(address, symbol_info);
                    }
                }
                _ => {} // Ignore other symbol types for now
            }
        }
    }
    Ok(())
}

fn add_procedure_range_to_buckets(
    range_buckets: &mut HashMap<u64, RangeBucket>,
    start: u64,
    end: u64,
    symbol: SymbolInfo,
) {
    let range = ProcedureRange { start, end, symbol };

    // Add this range to all buckets it overlaps
    let start_bucket = start / BUCKET_SIZE;
    let end_bucket = if end > start {
        (end - 1) / BUCKET_SIZE
    } else {
        start_bucket
    };

    for bucket_id in start_bucket..=end_bucket {
        range_buckets
            .entry(bucket_id)
            .or_default()
            .ranges
            .push(range.clone());
    }
}
