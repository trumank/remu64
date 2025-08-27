use crate::vm_context::VMContext;
use anyhow::Result;
use remu64::{memory::MemoryTrait, Engine, Register};

#[derive(Debug, Clone, Copy)]
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

    pub fn push_fname_to_stack<M: remu64::memory::MemoryTrait>(
        vm_context: &mut VMContext<M>,
        fname: &FName,
    ) -> Result<u64> {
        let fname_bytes = [
            fname.comparison_index.to_le_bytes(),
            fname.value.to_le_bytes(),
        ]
        .concat();
        vm_context.push_bytes_to_stack(&fname_bytes)
    }

    pub fn push_fstring_to_stack<M: remu64::memory::MemoryTrait>(
        vm_context: &mut VMContext<M>,
        fstring: &FString,
    ) -> Result<u64> {
        let data_ptr = if let Some(ref data) = fstring.data {
            let mut data_bytes = Vec::with_capacity(data.len() * 2);
            for &wchar in data {
                data_bytes.extend_from_slice(&wchar.to_le_bytes());
            }
            vm_context.push_bytes_to_stack(&data_bytes)?
        } else {
            0u64
        };

        let mut fstring_bytes = Vec::with_capacity(16);
        fstring_bytes.extend_from_slice(&data_ptr.to_le_bytes()); // 8 bytes
        fstring_bytes.extend_from_slice(&fstring.num.to_le_bytes()); // 4 bytes
        fstring_bytes.extend_from_slice(&fstring.max.to_le_bytes()); // 4 bytes
        vm_context.push_bytes_to_stack(&fstring_bytes)
    }

    pub fn setup_fastcall<M: remu64::memory::MemoryTrait>(
        vm_context: &mut VMContext<M>,
        args: Vec<ArgumentType>,
        return_address: u64,
    ) -> Result<(Vec<u64>, Vec<u64>)> {
        let mut register_args = Vec::new();
        let mut stack_args = Vec::new();
        let mut struct_addresses = Vec::new();
        let mut fstring_addresses = Vec::new();

        for arg in args.into_iter() {
            let arg_value = match arg {
                ArgumentType::Integer(val) | ArgumentType::Pointer(val) => val,
                ArgumentType::Float(val) => val.to_bits(),
                ArgumentType::FName(fname) => {
                    let addr = Self::push_fname_to_stack(vm_context, &fname)?;
                    struct_addresses.push(addr);
                    addr
                }
                ArgumentType::FString(fstring) => {
                    let addr = Self::push_fstring_to_stack(vm_context, &fstring)?;
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

        Self::set_register_args(&mut vm_context.engine, &register_args);

        vm_context.reserve_stack_space(32); // shadow space
        vm_context.push_u64(return_address)?;

        for &arg in stack_args.iter().rev() {
            vm_context.push_u64(arg)?;
        }

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
}
