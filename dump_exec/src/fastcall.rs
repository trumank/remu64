use crate::stack_manager::StackManager;
use amd64_emu::{memory::MemoryTrait, Engine, Register};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct FName {
    pub comparison_index: i32,
    pub value: i32,
}

#[derive(Debug, Clone)]
pub struct FString {
    pub data: Option<Vec<u16>>, // wchar_t* as Vec<u16>
    pub num: i32,
    pub max: i32,
}

#[derive(Debug, Clone)]
pub enum ArgumentType {
    Integer(u64),
    Float(f64),
    Pointer(u64),
    FName(FName),
    FString(FString),
}

pub struct CallingConvention;

impl CallingConvention {
    pub const INTEGER_REGISTERS: [Register; 4] =
        [Register::RCX, Register::RDX, Register::R8, Register::R9];

    pub fn set_register_args<M: MemoryTrait>(engine: &mut Engine<M>, args: &[u64]) {
        for (i, &value) in args.iter().enumerate() {
            if i < Self::INTEGER_REGISTERS.len() {
                engine.reg_write(Self::INTEGER_REGISTERS[i], value);
            }
        }
    }

    pub fn push_fname_to_stack<M: MemoryTrait>(
        engine: &mut Engine<M>,
        stack: &mut StackManager,
        fname: &FName,
    ) -> Result<u64> {
        let addr = stack.allocate(8);
        let comparison_bytes = fname.comparison_index.to_le_bytes();
        let value_bytes = fname.value.to_le_bytes();
        engine.memory.write(addr, &comparison_bytes)?;
        engine.memory.write(addr + 4, &value_bytes)?;
        Ok(addr)
    }

    pub fn push_fstring_to_stack<M: MemoryTrait>(
        engine: &mut Engine<M>,
        stack: &mut StackManager,
        fstring: &FString,
    ) -> Result<u64> {
        let data_ptr = if let Some(ref data) = fstring.data {
            let data_size = data.len() * 2;
            let data_addr = stack.allocate(data_size as u64);
            for (i, &wchar) in data.iter().enumerate() {
                let wchar_bytes = wchar.to_le_bytes();
                engine
                    .memory
                    .write(data_addr + (i * 2) as u64, &wchar_bytes)?;
            }
            data_addr
        } else {
            0u64
        };

        let struct_addr = stack.allocate(16);
        let data_ptr_bytes = data_ptr.to_le_bytes();
        let num_bytes = fstring.num.to_le_bytes();
        let max_bytes = fstring.max.to_le_bytes();

        engine.memory.write(struct_addr, &data_ptr_bytes)?;
        engine.memory.write(struct_addr + 8, &num_bytes)?;
        engine.memory.write(struct_addr + 12, &max_bytes)?;

        Ok(struct_addr)
    }

    pub fn setup_fastcall<M: MemoryTrait>(
        engine: &mut Engine<M>,
        args: Vec<ArgumentType>,
        stack_pointer: u64,
        return_address: u64,
    ) -> Result<(Vec<u64>, Vec<u64>)> {
        let mut stack = StackManager::new(stack_pointer);
        let mut register_args = Vec::new();
        let mut stack_args = Vec::new();
        let mut struct_addresses = Vec::new();
        let mut fstring_addresses = Vec::new();

        for arg in args.into_iter() {
            let arg_value = match arg {
                ArgumentType::Integer(val) | ArgumentType::Pointer(val) => val,
                ArgumentType::Float(val) => val.to_bits(),
                ArgumentType::FName(fname) => {
                    let addr = Self::push_fname_to_stack(engine, &mut stack, &fname)?;
                    struct_addresses.push(addr);
                    addr
                }
                ArgumentType::FString(fstring) => {
                    let addr = Self::push_fstring_to_stack(engine, &mut stack, &fstring)?;
                    fstring_addresses.push(addr);
                    addr
                }
            };

            if register_args.len() < 4 {
                register_args.push(arg_value);
            } else {
                stack_args.push(arg_value);
            }
        }

        Self::set_register_args(engine, &register_args);

        stack.reserve_shadow_space();
        stack.push_u64(engine, return_address)?;

        for &arg in stack_args.iter().rev() {
            stack.push_u64(engine, arg)?;
        }

        stack.set_stack_pointer(engine);

        Ok((struct_addresses, fstring_addresses))
    }

    pub fn read_fstring_output<M: MemoryTrait>(
        engine: &mut Engine<M>,
        fstring_addr: u64,
    ) -> Result<FString> {
        // Read FString struct from memory
        let mut data_ptr_bytes = [0u8; 8];
        engine.memory.read(fstring_addr, &mut data_ptr_bytes)?;
        let data_ptr = u64::from_le_bytes(data_ptr_bytes);

        let mut num_bytes = [0u8; 4];
        engine.memory.read(fstring_addr + 8, &mut num_bytes)?;
        let num = i32::from_le_bytes(num_bytes);

        let mut max_bytes = [0u8; 4];
        engine.memory.read(fstring_addr + 12, &mut max_bytes)?;
        let max = i32::from_le_bytes(max_bytes);

        // Read wide character data if pointer is valid and num > 0
        let data = if data_ptr != 0 && num > 0 {
            let mut wide_chars = Vec::new();
            for i in 0..num {
                let mut wchar_bytes = [0u8; 2];
                engine
                    .memory
                    .read(data_ptr + (i * 2) as u64, &mut wchar_bytes)?;
                wide_chars.push(u16::from_le_bytes(wchar_bytes));
            }
            Some(wide_chars)
        } else {
            None
        };

        Ok(FString { data, num, max })
    }

    pub fn read_u64_from_stack<M: MemoryTrait>(
        engine: &mut Engine<M>,
        stack: &mut StackManager,
    ) -> Result<u64> {
        let mut bytes = [0u8; 8];
        engine.memory.read(stack.current, &mut bytes)?;
        stack.current += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn write_u64_to_stack<M: MemoryTrait>(
        engine: &mut Engine<M>,
        stack: &mut StackManager,
        value: u64,
    ) -> Result<()> {
        stack.push_u64(engine, value)
    }
}
