use amd64_emu::{Engine, Register};
use anyhow::Result;

#[derive(Debug, Clone)]
pub enum ArgumentType {
    Integer(u64),
    Float(f64),
    Pointer(u64),
}

pub struct CallingConvention;

impl CallingConvention {
    pub fn setup_fastcall(
        engine: &mut Engine,
        args: Vec<ArgumentType>,
        stack_pointer: u64,
        return_address: u64,
    ) -> Result<()> {
        let integer_registers = [Register::RCX, Register::RDX, Register::R8, Register::R9];

        // Separate arguments into register and stack arguments
        let mut integer_args = Vec::new();
        let mut stack_args = Vec::new();

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
            }
        }

        // Set up register arguments
        for (i, &value) in integer_args.iter().enumerate() {
            if i < integer_registers.len() {
                engine.reg_write(integer_registers[i], value);
            }
        }

        let mut current_stack = stack_pointer;

        // Reserve shadow space (32 bytes) before placing return address
        current_stack -= 32;

        // Push the return address to the stack (simulating a CALL instruction)
        current_stack -= 8;
        let return_bytes = return_address.to_le_bytes();
        engine.mem_write(current_stack, &return_bytes)?;

        // Push any stack arguments
        for &arg in stack_args.iter().rev() {
            current_stack -= 8;
            let bytes = arg.to_le_bytes();
            engine.mem_write(current_stack, &bytes)?;
        }

        // Set RSP to point to the return address location
        engine.reg_write(Register::RSP, current_stack);

        Ok(())
    }
}
