use amd64_emu::{Engine, Register};
use anyhow::Result;

#[derive(Debug, Clone)]
pub enum ArgumentType {
    Integer(u64),
    Float(f64),
    Pointer(u64),
}

pub struct FastcallSetup {
    integer_args: Vec<u64>,
    float_args: Vec<f64>,
    stack_args: Vec<ArgumentType>,
    return_address: u64,
}

impl FastcallSetup {
    pub fn new(args: Vec<ArgumentType>, return_address: u64) -> Self {
        let mut integer_args = Vec::new();
        let mut float_args = Vec::new();
        let mut stack_args = Vec::new();

        for arg in args.into_iter() {
            match arg {
                ArgumentType::Integer(val) | ArgumentType::Pointer(val) => {
                    if integer_args.len() < 4 {
                        integer_args.push(val);
                    } else {
                        stack_args.push(ArgumentType::Integer(val));
                    }
                }
                ArgumentType::Float(val) => {
                    if float_args.len() < 4 {
                        float_args.push(val);
                    } else {
                        stack_args.push(ArgumentType::Float(val));
                    }
                }
            }
        }

        FastcallSetup {
            integer_args,
            float_args,
            stack_args,
            return_address,
        }
    }

    pub fn setup_registers(&self, engine: &mut Engine, stack_pointer: u64) -> Result<u64> {
        let integer_registers = [Register::RCX, Register::RDX, Register::R8, Register::R9];

        for (_i, &value) in self.integer_args.iter().enumerate() {
            if _i < integer_registers.len() {
                engine.reg_write(integer_registers[_i], value);
            }
        }

        let mut current_stack = stack_pointer;

        // First, push the return address to the stack (simulating a CALL instruction)
        current_stack -= 8;
        let return_bytes = self.return_address.to_le_bytes();
        engine.mem_write(current_stack, &return_bytes)?;

        // Then push any stack arguments
        for arg in self.stack_args.iter().rev() {
            current_stack -= 8;
            match arg {
                ArgumentType::Integer(val) | ArgumentType::Pointer(val) => {
                    let bytes = val.to_le_bytes();
                    engine.mem_write(current_stack, &bytes)?;
                }
                ArgumentType::Float(val) => {
                    let bytes = val.to_bits().to_le_bytes();
                    engine.mem_write(current_stack, &bytes)?;
                }
            }
        }

        // Set RSP to point to the current stack position
        engine.reg_write(Register::RSP, current_stack);

        Ok(current_stack)
    }

    pub fn get_return_value(&self, engine: &Engine) -> u64 {
        engine.reg_read(Register::RAX)
    }
}

pub struct CallingConvention;

impl CallingConvention {
    pub fn setup_fastcall(
        engine: &mut Engine,
        args: Vec<ArgumentType>,
        stack_pointer: u64,
        return_address: u64,
    ) -> Result<FastcallSetup> {
        let setup = FastcallSetup::new(args, return_address);
        setup.setup_registers(engine, stack_pointer)?;
        Ok(setup)
    }

    pub fn setup_shadow_space(engine: &mut Engine) {
        let current_rsp = engine.reg_read(Register::RSP);
        let shadow_space_rsp = current_rsp - 32;
        engine.reg_write(Register::RSP, shadow_space_rsp);
    }
}
