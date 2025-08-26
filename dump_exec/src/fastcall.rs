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
    pub fn setup_fastcall<M: MemoryTrait>(
        engine: &mut Engine<M>,
        args: Vec<ArgumentType>,
        stack_pointer: u64,
        return_address: u64,
    ) -> Result<(Vec<u64>, Vec<u64>)> {
        // Return (struct_addresses, fstring_addresses)
        let integer_registers = [Register::RCX, Register::RDX, Register::R8, Register::R9];

        // Separate arguments into register and stack arguments
        let mut integer_args = Vec::new();
        let mut stack_args = Vec::new();
        let mut struct_addresses = Vec::new();
        let mut fstring_addresses = Vec::new();

        let mut current_stack = stack_pointer;

        // First, allocate space for structs on the stack
        for arg in args.into_iter() {
            match arg {
                ArgumentType::Integer(val) | ArgumentType::Pointer(val) => {
                    if integer_args.len() < 4 {
                        integer_args.push(val);
                    } else {
                        stack_args.push(val);
                    }
                }
                ArgumentType::Float(val) => {
                    // For simplicity, treat floats as integers for now
                    let int_val = val.to_bits();
                    if integer_args.len() < 4 {
                        integer_args.push(int_val);
                    } else {
                        stack_args.push(int_val);
                    }
                }
                ArgumentType::FName(fname) => {
                    // Allocate 8 bytes for FName struct (two i32s)
                    current_stack -= 8;
                    let struct_addr = current_stack;

                    // Write FName data to stack
                    let comparison_bytes = fname.comparison_index.to_le_bytes();
                    let value_bytes = fname.value.to_le_bytes();
                    engine.memory.write(struct_addr, &comparison_bytes)?;
                    engine.memory.write(struct_addr + 4, &value_bytes)?;

                    struct_addresses.push(struct_addr);

                    // Pass pointer to struct as argument
                    if integer_args.len() < 4 {
                        integer_args.push(struct_addr);
                    } else {
                        stack_args.push(struct_addr);
                    }
                }
                ArgumentType::FString(fstring) => {
                    // Allocate space for FString struct (16 bytes: ptr + i32 + i32 + padding)
                    current_stack -= 16;
                    let struct_addr = current_stack;

                    // Allocate space for the wide character data if provided
                    let data_ptr = if let Some(ref data) = fstring.data {
                        let data_size = data.len() * 2; // u16 = 2 bytes each
                        current_stack -= data_size as u64;
                        let data_addr = current_stack;

                        // Write wide character data to stack
                        for (i, &wchar) in data.iter().enumerate() {
                            let wchar_bytes = wchar.to_le_bytes();
                            engine
                                .memory
                                .write(data_addr + (i * 2) as u64, &wchar_bytes)?;
                        }
                        data_addr
                    } else {
                        0u64 // null pointer
                    };

                    // Write FString struct to stack
                    let data_ptr_bytes = data_ptr.to_le_bytes();
                    let num_bytes = fstring.num.to_le_bytes();
                    let max_bytes = fstring.max.to_le_bytes();

                    engine.memory.write(struct_addr, &data_ptr_bytes)?; // data pointer
                    engine.memory.write(struct_addr + 8, &num_bytes)?; // num
                    engine.memory.write(struct_addr + 12, &max_bytes)?; // max

                    fstring_addresses.push(struct_addr);

                    // Pass pointer to struct as argument
                    if integer_args.len() < 4 {
                        integer_args.push(struct_addr);
                    } else {
                        stack_args.push(struct_addr);
                    }
                }
            }
        }

        // Set up register arguments
        for (i, &value) in integer_args.iter().enumerate() {
            if i < integer_registers.len() {
                engine.reg_write(integer_registers[i], value);
            }
        }

        // Reserve shadow space (32 bytes) before placing return address
        current_stack -= 32;

        // Push the return address to the stack (simulating a CALL instruction)
        current_stack -= 8;
        let return_bytes = return_address.to_le_bytes();
        engine.memory.write(current_stack, &return_bytes)?;

        // Push any stack arguments
        for &arg in stack_args.iter().rev() {
            current_stack -= 8;
            let bytes = arg.to_le_bytes();
            engine.memory.write(current_stack, &bytes)?;
        }

        // Set RSP to point to the return address location
        engine.reg_write(Register::RSP, current_stack);

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
