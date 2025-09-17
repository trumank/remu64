use anyhow::Result;
use rdex::{
    MinidumpLoader, ProcessTrait as _, pe_symbolizer::PeSymbolizer, process_trait::VmMemory,
};
use remu64::{CowMemory, Engine, HookAction, Register, memory::MemoryTrait};
use remu64_tui::{TracerHook, TuiContext, VmConfig, VmSetupProvider, run_tui};

fn main() -> Result<()> {
    // fname CTor
    // [141144EE0, 141151C70]
    let path = "../meatloaf/dumps/Borderlands4.DMP";
    // buh why is lsp not working
    let setup = FNameSetupProvider {
        minidump: MinidumpLoader::load(path)?,
    };

    run_tui(setup)?;

    Ok(())
}

struct FNameSetupProvider {
    pub minidump: rdex::MinidumpLoader<'static>,
}

impl VmSetupProvider for FNameSetupProvider {
    type Memory = VmMemory;
    type Symbolizer = PeSymbolizer;
    type Hooks = FNameHooks;

    fn create_backend(&self) -> Result<(Self::Memory, Self::Symbolizer)> {
        let memory = self.minidump.create_memory()?;
        let symbolizer = PeSymbolizer::new(&self.minidump);
        Ok((memory, symbolizer))
    }

    fn setup_engine(
        &mut self,
        engine: &mut Engine<CowMemory<Self::Memory>>,
    ) -> Result<VmConfig<Self::Hooks>> {
        // Set up stack memory region
        let stack_base = 0x7fff_f000_0000;
        let stack_size = 0x100000;
        engine.memory.map(
            stack_base - stack_size,
            stack_size as usize,
            remu64::memory::Permission::READ | remu64::memory::Permission::WRITE,
        )?;

        // Set initial stack pointer
        let initial_rsp = stack_base - 0x1000;
        engine.reg_write(Register::RSP, initial_rsp);

        engine.set_gs_base(self.minidump.get_teb_address()?);

        // [141144EE0, 141151C70]
        engine.reg_write(Register::RIP, 0x141151C70);
        // engine.reg_write(Register::RIP, 0x141144EE0);

        // let bytes = "IntProperty"
        //     .encode_utf16()
        //     .flat_map(|c| c.to_le_bytes())
        //     .chain([0, 0])
        //     .collect::<Vec<_>>();
        let bytes = b"IntProperty BUH GUH CUH\0";

        let _shadow_space = push_bytes_to_stack(engine, &[0; 64])?;

        // FName
        let rcx = push_bytes_to_stack(engine, &u64::to_le_bytes(0))?;
        // string
        let rdx = push_bytes_to_stack(engine, bytes)?;
        let r8 = 1; // FNAME_Find

        engine.reg_write(Register::RCX, rcx);
        engine.reg_write(Register::RDX, rdx);
        engine.reg_write(Register::R8, r8);

        let return_address = 0xFFFF800000000000u64;
        engine
            .memory
            .write(initial_rsp - 8, &return_address.to_le_bytes())?;
        engine.reg_write(Register::RSP, initial_rsp - 8);

        Ok(VmConfig {
            until_address: return_address,
            max_instructions: 0x10000,
            instruction_actions: Default::default(),
            hooks: FNameHooks::new(rcx, (rdx, bytes.len())),
        })
    }

    fn display_name(&self) -> &str {
        "FName Ctor"
    }

    fn check_reload_signal(&mut self) -> Result<bool> {
        Ok(false)
    }
}

fn push_bytes_to_stack<M: MemoryTrait>(engine: &mut Engine<M>, data: &[u8]) -> Result<u64> {
    let current_rsp = engine.reg_read(Register::RSP);

    // Calculate aligned size (round up to next 16-byte boundary)
    let aligned_size = (data.len() + 15) & !15;
    let new_rsp = current_rsp - aligned_size as u64;

    // Write data to the new stack location
    engine.memory.write(new_rsp, data)?;

    // Zero out any padding for security
    if aligned_size > data.len() {
        let padding_start = new_rsp + data.len() as u64;
        let padding_size = aligned_size - data.len();
        let zero_padding = vec![0u8; padding_size];
        engine.memory.write(padding_start, &zero_padding)?;
    }

    // Update RSP (maintains 16-byte alignment)
    engine.reg_write(Register::RSP, new_rsp);

    Ok(new_rsp)
}

#[derive(Clone)]
struct FNameHooks {
    fname_addr: u64,
    string: (u64, usize),
}
impl FNameHooks {
    fn new(fname_addr: u64, string: (u64, usize)) -> Self {
        Self { fname_addr, string }
    }
}

fn overlaps(addr1: u64, size1: usize, addr2: u64, size2: usize) -> bool {
    addr1 < addr2 + size2 as u64 && addr2 < addr1 + size1 as u64
}

impl<M: MemoryTrait> TracerHook<M> for FNameHooks {
    fn on_mem_write(
        &mut self,
        mut ctx: TuiContext,
        engine: &mut Engine<CowMemory<M>>,
        address: u64,
        size: usize,
    ) -> remu64::Result<()> {
        if overlaps(self.fname_addr, 8, address, size) {
            let fname = engine.memory.read_u64(self.fname_addr)?;
            ctx.log(format!(
                "write FName = {:08x} {:x} {:x}",
                fname, address, self.fname_addr
            ));
        }
        Ok(())
    }
    fn on_code(
        &mut self,
        mut ctx: TuiContext,
        engine: &mut Engine<CowMemory<M>>,
        _address: u64,
        _size: usize,
    ) -> remu64::Result<HookAction> {
        let fname = engine.memory.read_u64(self.fname_addr)?;
        ctx.log(format!(
            "code  FName = {:08x} = {}",
            fname,
            read_fname(&engine.memory, self.fname_addr)?
        ));
        Ok(HookAction::Continue)
    }
}

fn read_fname<const PS: u64, M: MemoryTrait<PS>>(mem: &M, fname: u64) -> remu64::Result<String> {
    let fnamepool = 0x15129CC80u64;

    let value = mem.read_u32(fname)? as u64;
    let number = mem.read_u32(fname + 4)?;

    let blocks = fnamepool + 0x10;
    let block_index = value >> 16;
    let offset = (value & 0xffff) * 2;

    let block = mem.read_u64(blocks + block_index * 8)?;
    let entry = block + offset;

    let header = mem.read_u16(entry)?;

    let len = (header >> 6) as usize;
    let is_wide = header & 1 != 0;

    let mut buf = vec![0; if is_wide { len * 2 } else { len }];
    mem.read(entry + 2, &mut buf)?;

    let base = if is_wide {
        String::from_utf16_lossy(
            &buf.chunks(2)
                .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<_>>(),
        )
    } else {
        String::from_utf8_lossy(&buf).to_string()
    };
    let name = if number == 0 {
        base
    } else {
        format!("{base}_{}", number - 1)
    };
    Ok(name)
    // return Ok(format!(
    //     "{value}_{number} {entry:x} {header:04x} {len} {is_wide} \"{name}\" {buf:02x?}",
    // ));
}
