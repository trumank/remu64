use bitflags::bitflags;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    RAX, RBX, RCX, RDX,
    RSI, RDI, RBP, RSP,
    R8, R9, R10, R11,
    R12, R13, R14, R15,
    RIP,
    RFLAGS,
    CS, DS, ES, FS, GS, SS,
    EAX, EBX, ECX, EDX,
    ESI, EDI, EBP, ESP,
    AX, BX, CX, DX,
    SI, DI, BP, SP,
    AL, BL, CL, DL,
    AH, BH, CH, DH,
    SIL, DIL, BPL, SPL,
}

impl Register {
    pub fn size(&self) -> usize {
        use Register::*;
        match self {
            RAX | RBX | RCX | RDX | RSI | RDI | RBP | RSP |
            R8 | R9 | R10 | R11 | R12 | R13 | R14 | R15 |
            RIP | RFLAGS => 8,
            EAX | EBX | ECX | EDX | ESI | EDI | EBP | ESP => 4,
            AX | BX | CX | DX | SI | DI | BP | SP | CS | DS | ES | FS | GS | SS => 2,
            AL | BL | CL | DL | AH | BH | CH | DH | SIL | DIL | BPL | SPL => 1,
        }
    }
    
    pub fn parent_64(&self) -> Option<Register> {
        use Register::*;
        match self {
            RAX | EAX | AX | AL | AH => Some(RAX),
            RBX | EBX | BX | BL | BH => Some(RBX),
            RCX | ECX | CX | CL | CH => Some(RCX),
            RDX | EDX | DX | DL | DH => Some(RDX),
            RSI | ESI | SI | SIL => Some(RSI),
            RDI | EDI | DI | DIL => Some(RDI),
            RBP | EBP | BP | BPL => Some(RBP),
            RSP | ESP | SP | SPL => Some(RSP),
            R8 => Some(R8),
            R9 => Some(R9),
            R10 => Some(R10),
            R11 => Some(R11),
            R12 => Some(R12),
            R13 => Some(R13),
            R14 => Some(R14),
            R15 => Some(R15),
            RIP => Some(RIP),
            RFLAGS => Some(RFLAGS),
            _ => None,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct Flags: u64 {
        const CF = 1 << 0;     // Carry Flag
        const PF = 1 << 2;     // Parity Flag
        const AF = 1 << 4;     // Auxiliary Carry Flag
        const ZF = 1 << 6;     // Zero Flag
        const SF = 1 << 7;     // Sign Flag
        const TF = 1 << 8;     // Trap Flag
        const IF = 1 << 9;     // Interrupt Enable Flag
        const DF = 1 << 10;    // Direction Flag
        const OF = 1 << 11;    // Overflow Flag
        const IOPL = 3 << 12;  // I/O Privilege Level
        const NT = 1 << 14;    // Nested Task
        const RF = 1 << 16;    // Resume Flag
        const VM = 1 << 17;    // Virtual-8086 Mode
        const AC = 1 << 18;    // Alignment Check
        const VIF = 1 << 19;   // Virtual Interrupt Flag
        const VIP = 1 << 20;   // Virtual Interrupt Pending
        const ID = 1 << 21;    // ID Flag
    }
}

#[derive(Debug, Clone)]
pub struct CpuState {
    pub regs: [u64; 16],
    pub rip: u64,
    pub rflags: Flags,
    pub segments: SegmentRegisters,
}

#[derive(Debug, Clone)]
pub struct SegmentRegisters {
    pub cs: SegmentDescriptor,
    pub ds: SegmentDescriptor,
    pub es: SegmentDescriptor,
    pub fs: SegmentDescriptor,
    pub gs: SegmentDescriptor,
    pub ss: SegmentDescriptor,
}

#[derive(Debug, Clone, Copy)]
pub struct SegmentDescriptor {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub attributes: u16,
}

impl Default for SegmentDescriptor {
    fn default() -> Self {
        Self {
            selector: 0,
            base: 0,
            limit: 0xFFFFFFFF,
            attributes: 0x0093,
        }
    }
}

impl Default for SegmentRegisters {
    fn default() -> Self {
        Self {
            cs: SegmentDescriptor { selector: 0x10, ..Default::default() },
            ds: Default::default(),
            es: Default::default(),
            fs: Default::default(),
            gs: Default::default(),
            ss: Default::default(),
        }
    }
}

impl CpuState {
    pub fn new() -> Self {
        Self {
            regs: [0; 16],
            rip: 0,
            rflags: Flags::empty(),
            segments: SegmentRegisters::default(),
        }
    }
    
    pub fn read_reg(&self, reg: Register) -> u64 {
        use Register::*;
        match reg {
            RAX => self.regs[0],
            RBX => self.regs[3],
            RCX => self.regs[1],
            RDX => self.regs[2],
            RSI => self.regs[6],
            RDI => self.regs[7],
            RBP => self.regs[5],
            RSP => self.regs[4],
            R8 => self.regs[8],
            R9 => self.regs[9],
            R10 => self.regs[10],
            R11 => self.regs[11],
            R12 => self.regs[12],
            R13 => self.regs[13],
            R14 => self.regs[14],
            R15 => self.regs[15],
            RIP => self.rip,
            RFLAGS => self.rflags.bits(),
            EAX => self.regs[0] as u32 as u64,
            EBX => self.regs[3] as u32 as u64,
            ECX => self.regs[1] as u32 as u64,
            EDX => self.regs[2] as u32 as u64,
            ESI => self.regs[6] as u32 as u64,
            EDI => self.regs[7] as u32 as u64,
            EBP => self.regs[5] as u32 as u64,
            ESP => self.regs[4] as u32 as u64,
            AX => self.regs[0] as u16 as u64,
            BX => self.regs[3] as u16 as u64,
            CX => self.regs[1] as u16 as u64,
            DX => self.regs[2] as u16 as u64,
            SI => self.regs[6] as u16 as u64,
            DI => self.regs[7] as u16 as u64,
            BP => self.regs[5] as u16 as u64,
            SP => self.regs[4] as u16 as u64,
            AL => self.regs[0] as u8 as u64,
            BL => self.regs[3] as u8 as u64,
            CL => self.regs[1] as u8 as u64,
            DL => self.regs[2] as u8 as u64,
            AH => (self.regs[0] >> 8) as u8 as u64,
            BH => (self.regs[3] >> 8) as u8 as u64,
            CH => (self.regs[1] >> 8) as u8 as u64,
            DH => (self.regs[2] >> 8) as u8 as u64,
            SIL => self.regs[6] as u8 as u64,
            DIL => self.regs[7] as u8 as u64,
            BPL => self.regs[5] as u8 as u64,
            SPL => self.regs[4] as u8 as u64,
            CS => self.segments.cs.selector as u64,
            DS => self.segments.ds.selector as u64,
            ES => self.segments.es.selector as u64,
            FS => self.segments.fs.selector as u64,
            GS => self.segments.gs.selector as u64,
            SS => self.segments.ss.selector as u64,
        }
    }
    
    pub fn write_reg(&mut self, reg: Register, value: u64) {
        use Register::*;
        match reg {
            RAX => self.regs[0] = value,
            RBX => self.regs[3] = value,
            RCX => self.regs[1] = value,
            RDX => self.regs[2] = value,
            RSI => self.regs[6] = value,
            RDI => self.regs[7] = value,
            RBP => self.regs[5] = value,
            RSP => self.regs[4] = value,
            R8 => self.regs[8] = value,
            R9 => self.regs[9] = value,
            R10 => self.regs[10] = value,
            R11 => self.regs[11] = value,
            R12 => self.regs[12] = value,
            R13 => self.regs[13] = value,
            R14 => self.regs[14] = value,
            R15 => self.regs[15] = value,
            RIP => self.rip = value,
            RFLAGS => self.rflags = Flags::from_bits_truncate(value),
            EAX => self.regs[0] = (self.regs[0] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF),
            EBX => self.regs[3] = (self.regs[3] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF),
            ECX => self.regs[1] = (self.regs[1] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF),
            EDX => self.regs[2] = (self.regs[2] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF),
            ESI => self.regs[6] = (self.regs[6] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF),
            EDI => self.regs[7] = (self.regs[7] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF),
            EBP => self.regs[5] = (self.regs[5] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF),
            ESP => self.regs[4] = (self.regs[4] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF),
            AX => self.regs[0] = (self.regs[0] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            BX => self.regs[3] = (self.regs[3] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            CX => self.regs[1] = (self.regs[1] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            DX => self.regs[2] = (self.regs[2] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            SI => self.regs[6] = (self.regs[6] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            DI => self.regs[7] = (self.regs[7] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            BP => self.regs[5] = (self.regs[5] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            SP => self.regs[4] = (self.regs[4] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            AL => self.regs[0] = (self.regs[0] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            BL => self.regs[3] = (self.regs[3] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            CL => self.regs[1] = (self.regs[1] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            DL => self.regs[2] = (self.regs[2] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            AH => self.regs[0] = (self.regs[0] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8),
            BH => self.regs[3] = (self.regs[3] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8),
            CH => self.regs[1] = (self.regs[1] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8),
            DH => self.regs[2] = (self.regs[2] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8),
            SIL => self.regs[6] = (self.regs[6] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            DIL => self.regs[7] = (self.regs[7] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            BPL => self.regs[5] = (self.regs[5] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            SPL => self.regs[4] = (self.regs[4] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            CS => self.segments.cs.selector = value as u16,
            DS => self.segments.ds.selector = value as u16,
            ES => self.segments.es.selector = value as u16,
            FS => self.segments.fs.selector = value as u16,
            GS => self.segments.gs.selector = value as u16,
            SS => self.segments.ss.selector = value as u16,
        }
    }
}

impl fmt::Display for CpuState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CPU State:")?;
        writeln!(f, "  RAX: {:#018x}  R8:  {:#018x}", self.regs[0], self.regs[8])?;
        writeln!(f, "  RBX: {:#018x}  R9:  {:#018x}", self.regs[3], self.regs[9])?;
        writeln!(f, "  RCX: {:#018x}  R10: {:#018x}", self.regs[1], self.regs[10])?;
        writeln!(f, "  RDX: {:#018x}  R11: {:#018x}", self.regs[2], self.regs[11])?;
        writeln!(f, "  RSI: {:#018x}  R12: {:#018x}", self.regs[6], self.regs[12])?;
        writeln!(f, "  RDI: {:#018x}  R13: {:#018x}", self.regs[7], self.regs[13])?;
        writeln!(f, "  RBP: {:#018x}  R14: {:#018x}", self.regs[5], self.regs[14])?;
        writeln!(f, "  RSP: {:#018x}  R15: {:#018x}", self.regs[4], self.regs[15])?;
        writeln!(f, "  RIP: {:#018x}", self.rip)?;
        writeln!(f, "  RFLAGS: {:#018x} {:?}", self.rflags.bits(), self.rflags)?;
        Ok(())
    }
}