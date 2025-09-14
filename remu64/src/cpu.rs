use bitflags::bitflags;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    RAX,
    RBX,
    RCX,
    RDX,
    RSI,
    RDI,
    RBP,
    RSP,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    RIP,
    RFLAGS,
    CS,
    DS,
    ES,
    FS,
    GS,
    SS,
    EAX,
    EBX,
    ECX,
    EDX,
    ESI,
    EDI,
    EBP,
    ESP,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D,
    AX,
    BX,
    CX,
    DX,
    SI,
    DI,
    BP,
    SP,
    R8W,
    R9W,
    R10W,
    R11W,
    R12W,
    R13W,
    R14W,
    R15W,
    AL,
    BL,
    CL,
    DL,
    AH,
    BH,
    CH,
    DH,
    SIL,
    DIL,
    BPL,
    SPL,
    R8B,
    R9B,
    R10B,
    R11B,
    R12B,
    R13B,
    R14B,
    R15B,
    XMM0,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
    XMM8,
    XMM9,
    XMM10,
    XMM11,
    XMM12,
    XMM13,
    XMM14,
    XMM15,
    XMM16,
    XMM17,
    XMM18,
    XMM19,
    XMM20,
    XMM21,
    XMM22,
    XMM23,
    XMM24,
    XMM25,
    XMM26,
    XMM27,
    XMM28,
    XMM29,
    XMM30,
    XMM31,
    YMM0,
    YMM1,
    YMM2,
    YMM3,
    YMM4,
    YMM5,
    YMM6,
    YMM7,
    YMM8,
    YMM9,
    YMM10,
    YMM11,
    YMM12,
    YMM13,
    YMM14,
    YMM15,
    YMM16,
    YMM17,
    YMM18,
    YMM19,
    YMM20,
    YMM21,
    YMM22,
    YMM23,
    YMM24,
    YMM25,
    YMM26,
    YMM27,
    YMM28,
    YMM29,
    YMM30,
    YMM31,
    K0,
    K1,
    K2,
    K3,
    K4,
    K5,
    K6,
    K7,
}

impl Register {
    pub fn size(&self) -> usize {
        use Register::*;
        match self {
            XMM0 | XMM1 | XMM2 | XMM3 | XMM4 | XMM5 | XMM6 | XMM7 | XMM8 | XMM9 | XMM10 | XMM11
            | XMM12 | XMM13 | XMM14 | XMM15 | XMM16 | XMM17 | XMM18 | XMM19 | XMM20 | XMM21
            | XMM22 | XMM23 | XMM24 | XMM25 | XMM26 | XMM27 | XMM28 | XMM29 | XMM30 | XMM31 => 16,
            YMM0 | YMM1 | YMM2 | YMM3 | YMM4 | YMM5 | YMM6 | YMM7 | YMM8 | YMM9 | YMM10 | YMM11
            | YMM12 | YMM13 | YMM14 | YMM15 | YMM16 | YMM17 | YMM18 | YMM19 | YMM20 | YMM21
            | YMM22 | YMM23 | YMM24 | YMM25 | YMM26 | YMM27 | YMM28 | YMM29 | YMM30 | YMM31 => 32,
            K0 | K1 | K2 | K3 | K4 | K5 | K6 | K7 => 8,
            RAX | RBX | RCX | RDX | RSI | RDI | RBP | RSP | R8 | R9 | R10 | R11 | R12 | R13
            | R14 | R15 | RIP | RFLAGS => 8,
            EAX | EBX | ECX | EDX | ESI | EDI | EBP | ESP | R8D | R9D | R10D | R11D | R12D
            | R13D | R14D | R15D => 4,
            AX | BX | CX | DX | SI | DI | BP | SP | CS | DS | ES | FS | GS | SS | R8W | R9W
            | R10W | R11W | R12W | R13W | R14W | R15W => 2,
            AL | BL | CL | DL | AH | BH | CH | DH | SIL | DIL | BPL | SPL | R8B | R9B | R10B
            | R11B | R12B | R13B | R14B | R15B => 1,
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
            R8 | R8D | R8W | R8B => Some(R8),
            R9 | R9D | R9W | R9B => Some(R9),
            R10 | R10D | R10W | R10B => Some(R10),
            R11 | R11D | R11W | R11B => Some(R11),
            R12 | R12D | R12W | R12B => Some(R12),
            R13 | R13D | R13W | R13B => Some(R13),
            R14 | R14D | R14W | R14B => Some(R14),
            R15 | R15D | R15W | R15B => Some(R15),
            RIP => Some(RIP),
            RFLAGS => Some(RFLAGS),
            _ => None,
        }
    }

    pub fn is_xmm(&self) -> bool {
        use Register::*;
        matches!(
            self,
            XMM0 | XMM1
                | XMM2
                | XMM3
                | XMM4
                | XMM5
                | XMM6
                | XMM7
                | XMM8
                | XMM9
                | XMM10
                | XMM11
                | XMM12
                | XMM13
                | XMM14
                | XMM15
                | XMM16
                | XMM17
                | XMM18
                | XMM19
                | XMM20
                | XMM21
                | XMM22
                | XMM23
                | XMM24
                | XMM25
                | XMM26
                | XMM27
                | XMM28
                | XMM29
                | XMM30
                | XMM31
        )
    }

    pub fn is_ymm(&self) -> bool {
        use Register::*;
        matches!(
            self,
            YMM0 | YMM1
                | YMM2
                | YMM3
                | YMM4
                | YMM5
                | YMM6
                | YMM7
                | YMM8
                | YMM9
                | YMM10
                | YMM11
                | YMM12
                | YMM13
                | YMM14
                | YMM15
                | YMM16
                | YMM17
                | YMM18
                | YMM19
                | YMM20
                | YMM21
                | YMM22
                | YMM23
                | YMM24
                | YMM25
                | YMM26
                | YMM27
                | YMM28
                | YMM29
                | YMM30
                | YMM31
        )
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
    pub ymm_regs: [[u128; 2]; 32], // YMM as two u128 parts: [low_128, high_128] - XMM is ymm_regs[i][0]
    pub k_regs: [u64; 8],          // Mask registers K0-K7
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
            cs: SegmentDescriptor {
                selector: 0x10,
                ..Default::default()
            },
            ds: Default::default(),
            es: Default::default(),
            fs: Default::default(),
            gs: Default::default(),
            ss: Default::default(),
        }
    }
}

impl Default for CpuState {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuState {
    pub fn new() -> Self {
        Self {
            regs: [0; 16],
            ymm_regs: [[0; 2]; 32],
            k_regs: [0; 8],
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
            R8D => self.regs[8] as u32 as u64,
            R9D => self.regs[9] as u32 as u64,
            R10D => self.regs[10] as u32 as u64,
            R11D => self.regs[11] as u32 as u64,
            R12D => self.regs[12] as u32 as u64,
            R13D => self.regs[13] as u32 as u64,
            R14D => self.regs[14] as u32 as u64,
            R15D => self.regs[15] as u32 as u64,
            AX => self.regs[0] as u16 as u64,
            BX => self.regs[3] as u16 as u64,
            CX => self.regs[1] as u16 as u64,
            DX => self.regs[2] as u16 as u64,
            SI => self.regs[6] as u16 as u64,
            DI => self.regs[7] as u16 as u64,
            BP => self.regs[5] as u16 as u64,
            SP => self.regs[4] as u16 as u64,
            R8W => self.regs[8] as u16 as u64,
            R9W => self.regs[9] as u16 as u64,
            R10W => self.regs[10] as u16 as u64,
            R11W => self.regs[11] as u16 as u64,
            R12W => self.regs[12] as u16 as u64,
            R13W => self.regs[13] as u16 as u64,
            R14W => self.regs[14] as u16 as u64,
            R15W => self.regs[15] as u16 as u64,
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
            R8B => self.regs[8] as u8 as u64,
            R9B => self.regs[9] as u8 as u64,
            R10B => self.regs[10] as u8 as u64,
            R11B => self.regs[11] as u8 as u64,
            R12B => self.regs[12] as u8 as u64,
            R13B => self.regs[13] as u8 as u64,
            R14B => self.regs[14] as u8 as u64,
            R15B => self.regs[15] as u8 as u64,
            CS => self.segments.cs.selector as u64,
            DS => self.segments.ds.selector as u64,
            ES => self.segments.es.selector as u64,
            FS => self.segments.fs.selector as u64,
            GS => self.segments.gs.selector as u64,
            SS => self.segments.ss.selector as u64,
            XMM0 | XMM1 | XMM2 | XMM3 | XMM4 | XMM5 | XMM6 | XMM7 | XMM8 | XMM9 | XMM10 | XMM11
            | XMM12 | XMM13 | XMM14 | XMM15 | XMM16 | XMM17 | XMM18 | XMM19 | XMM20 | XMM21
            | XMM22 | XMM23 | XMM24 | XMM25 | XMM26 | XMM27 | XMM28 | XMM29 | XMM30 | XMM31 => {
                panic!("Cannot read XMM register as u64, use read_xmm instead")
            }
            YMM0 | YMM1 | YMM2 | YMM3 | YMM4 | YMM5 | YMM6 | YMM7 | YMM8 | YMM9 | YMM10 | YMM11
            | YMM12 | YMM13 | YMM14 | YMM15 | YMM16 | YMM17 | YMM18 | YMM19 | YMM20 | YMM21
            | YMM22 | YMM23 | YMM24 | YMM25 | YMM26 | YMM27 | YMM28 | YMM29 | YMM30 | YMM31 => {
                panic!("Cannot read YMM register as u64, use read_ymm instead")
            }
            K0 => self.k_regs[0],
            K1 => self.k_regs[1],
            K2 => self.k_regs[2],
            K3 => self.k_regs[3],
            K4 => self.k_regs[4],
            K5 => self.k_regs[5],
            K6 => self.k_regs[6],
            K7 => self.k_regs[7],
        }
    }

    pub fn read_xmm(&self, reg: Register) -> u128 {
        use Register::*;
        match reg {
            XMM0 => self.ymm_regs[0][0],
            XMM1 => self.ymm_regs[1][0],
            XMM2 => self.ymm_regs[2][0],
            XMM3 => self.ymm_regs[3][0],
            XMM4 => self.ymm_regs[4][0],
            XMM5 => self.ymm_regs[5][0],
            XMM6 => self.ymm_regs[6][0],
            XMM7 => self.ymm_regs[7][0],
            XMM8 => self.ymm_regs[8][0],
            XMM9 => self.ymm_regs[9][0],
            XMM10 => self.ymm_regs[10][0],
            XMM11 => self.ymm_regs[11][0],
            XMM12 => self.ymm_regs[12][0],
            XMM13 => self.ymm_regs[13][0],
            XMM14 => self.ymm_regs[14][0],
            XMM15 => self.ymm_regs[15][0],
            XMM16 => self.ymm_regs[16][0],
            XMM17 => self.ymm_regs[17][0],
            XMM18 => self.ymm_regs[18][0],
            XMM19 => self.ymm_regs[19][0],
            XMM20 => self.ymm_regs[20][0],
            XMM21 => self.ymm_regs[21][0],
            XMM22 => self.ymm_regs[22][0],
            XMM23 => self.ymm_regs[23][0],
            XMM24 => self.ymm_regs[24][0],
            XMM25 => self.ymm_regs[25][0],
            XMM26 => self.ymm_regs[26][0],
            XMM27 => self.ymm_regs[27][0],
            XMM28 => self.ymm_regs[28][0],
            XMM29 => self.ymm_regs[29][0],
            XMM30 => self.ymm_regs[30][0],
            XMM31 => self.ymm_regs[31][0],
            _ => panic!("Not an XMM register"),
        }
    }

    pub fn read_ymm(&self, reg: Register) -> [u128; 2] {
        use Register::*;
        match reg {
            YMM0 => self.ymm_regs[0],
            YMM1 => self.ymm_regs[1],
            YMM2 => self.ymm_regs[2],
            YMM3 => self.ymm_regs[3],
            YMM4 => self.ymm_regs[4],
            YMM5 => self.ymm_regs[5],
            YMM6 => self.ymm_regs[6],
            YMM7 => self.ymm_regs[7],
            YMM8 => self.ymm_regs[8],
            YMM9 => self.ymm_regs[9],
            YMM10 => self.ymm_regs[10],
            YMM11 => self.ymm_regs[11],
            YMM12 => self.ymm_regs[12],
            YMM13 => self.ymm_regs[13],
            YMM14 => self.ymm_regs[14],
            YMM15 => self.ymm_regs[15],
            YMM16 => self.ymm_regs[16],
            YMM17 => self.ymm_regs[17],
            YMM18 => self.ymm_regs[18],
            YMM19 => self.ymm_regs[19],
            YMM20 => self.ymm_regs[20],
            YMM21 => self.ymm_regs[21],
            YMM22 => self.ymm_regs[22],
            YMM23 => self.ymm_regs[23],
            YMM24 => self.ymm_regs[24],
            YMM25 => self.ymm_regs[25],
            YMM26 => self.ymm_regs[26],
            YMM27 => self.ymm_regs[27],
            YMM28 => self.ymm_regs[28],
            YMM29 => self.ymm_regs[29],
            YMM30 => self.ymm_regs[30],
            YMM31 => self.ymm_regs[31],
            _ => panic!("Not a YMM register"),
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
            EAX => self.regs[0] = value & 0xFFFFFFFF, // In x86-64, writing to 32-bit reg zeros upper 32 bits
            EBX => self.regs[3] = value & 0xFFFFFFFF,
            ECX => self.regs[1] = value & 0xFFFFFFFF,
            EDX => self.regs[2] = value & 0xFFFFFFFF,
            ESI => self.regs[6] = value & 0xFFFFFFFF,
            EDI => self.regs[7] = value & 0xFFFFFFFF,
            EBP => self.regs[5] = value & 0xFFFFFFFF,
            ESP => self.regs[4] = value & 0xFFFFFFFF,
            R8D => self.regs[8] = value & 0xFFFFFFFF,
            R9D => self.regs[9] = value & 0xFFFFFFFF,
            R10D => self.regs[10] = value & 0xFFFFFFFF,
            R11D => self.regs[11] = value & 0xFFFFFFFF,
            R12D => self.regs[12] = value & 0xFFFFFFFF,
            R13D => self.regs[13] = value & 0xFFFFFFFF,
            R14D => self.regs[14] = value & 0xFFFFFFFF,
            R15D => self.regs[15] = value & 0xFFFFFFFF,
            AX => self.regs[0] = (self.regs[0] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            BX => self.regs[3] = (self.regs[3] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            CX => self.regs[1] = (self.regs[1] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            DX => self.regs[2] = (self.regs[2] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            SI => self.regs[6] = (self.regs[6] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            DI => self.regs[7] = (self.regs[7] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            BP => self.regs[5] = (self.regs[5] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            SP => self.regs[4] = (self.regs[4] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            R8W => self.regs[8] = (self.regs[8] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            R9W => self.regs[9] = (self.regs[9] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            R10W => self.regs[10] = (self.regs[10] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            R11W => self.regs[11] = (self.regs[11] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            R12W => self.regs[12] = (self.regs[12] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            R13W => self.regs[13] = (self.regs[13] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            R14W => self.regs[14] = (self.regs[14] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
            R15W => self.regs[15] = (self.regs[15] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF),
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
            R8B => self.regs[8] = (self.regs[8] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            R9B => self.regs[9] = (self.regs[9] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            R10B => self.regs[10] = (self.regs[10] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            R11B => self.regs[11] = (self.regs[11] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            R12B => self.regs[12] = (self.regs[12] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            R13B => self.regs[13] = (self.regs[13] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            R14B => self.regs[14] = (self.regs[14] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            R15B => self.regs[15] = (self.regs[15] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF),
            CS => self.segments.cs.selector = value as u16,
            DS => self.segments.ds.selector = value as u16,
            ES => self.segments.es.selector = value as u16,
            FS => self.segments.fs.selector = value as u16,
            GS => self.segments.gs.selector = value as u16,
            SS => self.segments.ss.selector = value as u16,
            XMM0 | XMM1 | XMM2 | XMM3 | XMM4 | XMM5 | XMM6 | XMM7 | XMM8 | XMM9 | XMM10 | XMM11
            | XMM12 | XMM13 | XMM14 | XMM15 | XMM16 | XMM17 | XMM18 | XMM19 | XMM20 | XMM21
            | XMM22 | XMM23 | XMM24 | XMM25 | XMM26 | XMM27 | XMM28 | XMM29 | XMM30 | XMM31 => {
                panic!("Cannot write XMM register with u64, use write_xmm instead")
            }
            YMM0 | YMM1 | YMM2 | YMM3 | YMM4 | YMM5 | YMM6 | YMM7 | YMM8 | YMM9 | YMM10 | YMM11
            | YMM12 | YMM13 | YMM14 | YMM15 | YMM16 | YMM17 | YMM18 | YMM19 | YMM20 | YMM21
            | YMM22 | YMM23 | YMM24 | YMM25 | YMM26 | YMM27 | YMM28 | YMM29 | YMM30 | YMM31 => {
                panic!("Cannot write YMM register with u64, use write_ymm instead")
            }
            K0 => self.k_regs[0] = value,
            K1 => self.k_regs[1] = value,
            K2 => self.k_regs[2] = value,
            K3 => self.k_regs[3] = value,
            K4 => self.k_regs[4] = value,
            K5 => self.k_regs[5] = value,
            K6 => self.k_regs[6] = value,
            K7 => self.k_regs[7] = value,
        }
    }

    pub fn write_xmm(&mut self, reg: Register, value: u128) {
        use Register::*;
        match reg {
            XMM0 => {
                self.ymm_regs[0][0] = value;
                self.ymm_regs[0][1] = 0;
            }
            XMM1 => {
                self.ymm_regs[1][0] = value;
                self.ymm_regs[1][1] = 0;
            }
            XMM2 => {
                self.ymm_regs[2][0] = value;
                self.ymm_regs[2][1] = 0;
            }
            XMM3 => {
                self.ymm_regs[3][0] = value;
                self.ymm_regs[3][1] = 0;
            }
            XMM4 => {
                self.ymm_regs[4][0] = value;
                self.ymm_regs[4][1] = 0;
            }
            XMM5 => {
                self.ymm_regs[5][0] = value;
                self.ymm_regs[5][1] = 0;
            }
            XMM6 => {
                self.ymm_regs[6][0] = value;
                self.ymm_regs[6][1] = 0;
            }
            XMM7 => {
                self.ymm_regs[7][0] = value;
                self.ymm_regs[7][1] = 0;
            }
            XMM8 => {
                self.ymm_regs[8][0] = value;
                self.ymm_regs[8][1] = 0;
            }
            XMM9 => {
                self.ymm_regs[9][0] = value;
                self.ymm_regs[9][1] = 0;
            }
            XMM10 => {
                self.ymm_regs[10][0] = value;
                self.ymm_regs[10][1] = 0;
            }
            XMM11 => {
                self.ymm_regs[11][0] = value;
                self.ymm_regs[11][1] = 0;
            }
            XMM12 => {
                self.ymm_regs[12][0] = value;
                self.ymm_regs[12][1] = 0;
            }
            XMM13 => {
                self.ymm_regs[13][0] = value;
                self.ymm_regs[13][1] = 0;
            }
            XMM14 => {
                self.ymm_regs[14][0] = value;
                self.ymm_regs[14][1] = 0;
            }
            XMM15 => {
                self.ymm_regs[15][0] = value;
                self.ymm_regs[15][1] = 0;
            }
            XMM16 => {
                self.ymm_regs[16][0] = value;
                self.ymm_regs[16][1] = 0;
            }
            XMM17 => {
                self.ymm_regs[17][0] = value;
                self.ymm_regs[17][1] = 0;
            }
            XMM18 => {
                self.ymm_regs[18][0] = value;
                self.ymm_regs[18][1] = 0;
            }
            XMM19 => {
                self.ymm_regs[19][0] = value;
                self.ymm_regs[19][1] = 0;
            }
            XMM20 => {
                self.ymm_regs[20][0] = value;
                self.ymm_regs[20][1] = 0;
            }
            XMM21 => {
                self.ymm_regs[21][0] = value;
                self.ymm_regs[21][1] = 0;
            }
            XMM22 => {
                self.ymm_regs[22][0] = value;
                self.ymm_regs[22][1] = 0;
            }
            XMM23 => {
                self.ymm_regs[23][0] = value;
                self.ymm_regs[23][1] = 0;
            }
            XMM24 => {
                self.ymm_regs[24][0] = value;
                self.ymm_regs[24][1] = 0;
            }
            XMM25 => {
                self.ymm_regs[25][0] = value;
                self.ymm_regs[25][1] = 0;
            }
            XMM26 => {
                self.ymm_regs[26][0] = value;
                self.ymm_regs[26][1] = 0;
            }
            XMM27 => {
                self.ymm_regs[27][0] = value;
                self.ymm_regs[27][1] = 0;
            }
            XMM28 => {
                self.ymm_regs[28][0] = value;
                self.ymm_regs[28][1] = 0;
            }
            XMM29 => {
                self.ymm_regs[29][0] = value;
                self.ymm_regs[29][1] = 0;
            }
            XMM30 => {
                self.ymm_regs[30][0] = value;
                self.ymm_regs[30][1] = 0;
            }
            XMM31 => {
                self.ymm_regs[31][0] = value;
                self.ymm_regs[31][1] = 0;
            }
            _ => panic!("Not an XMM register"),
        }
    }

    pub fn write_ymm(&mut self, reg: Register, value: [u128; 2]) {
        use Register::*;
        match reg {
            YMM0 => self.ymm_regs[0] = value,
            YMM1 => self.ymm_regs[1] = value,
            YMM2 => self.ymm_regs[2] = value,
            YMM3 => self.ymm_regs[3] = value,
            YMM4 => self.ymm_regs[4] = value,
            YMM5 => self.ymm_regs[5] = value,
            YMM6 => self.ymm_regs[6] = value,
            YMM7 => self.ymm_regs[7] = value,
            YMM8 => self.ymm_regs[8] = value,
            YMM9 => self.ymm_regs[9] = value,
            YMM10 => self.ymm_regs[10] = value,
            YMM11 => self.ymm_regs[11] = value,
            YMM12 => self.ymm_regs[12] = value,
            YMM13 => self.ymm_regs[13] = value,
            YMM14 => self.ymm_regs[14] = value,
            YMM15 => self.ymm_regs[15] = value,
            YMM16 => self.ymm_regs[16] = value,
            YMM17 => self.ymm_regs[17] = value,
            YMM18 => self.ymm_regs[18] = value,
            YMM19 => self.ymm_regs[19] = value,
            YMM20 => self.ymm_regs[20] = value,
            YMM21 => self.ymm_regs[21] = value,
            YMM22 => self.ymm_regs[22] = value,
            YMM23 => self.ymm_regs[23] = value,
            YMM24 => self.ymm_regs[24] = value,
            YMM25 => self.ymm_regs[25] = value,
            YMM26 => self.ymm_regs[26] = value,
            YMM27 => self.ymm_regs[27] = value,
            YMM28 => self.ymm_regs[28] = value,
            YMM29 => self.ymm_regs[29] = value,
            YMM30 => self.ymm_regs[30] = value,
            YMM31 => self.ymm_regs[31] = value,
            _ => panic!("Not a YMM register"),
        }
    }
}

impl fmt::Display for CpuState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CPU State:")?;
        writeln!(
            f,
            "  RAX: {:#018x}  R8:  {:#018x}",
            self.regs[0], self.regs[8]
        )?;
        writeln!(
            f,
            "  RBX: {:#018x}  R9:  {:#018x}",
            self.regs[3], self.regs[9]
        )?;
        writeln!(
            f,
            "  RCX: {:#018x}  R10: {:#018x}",
            self.regs[1], self.regs[10]
        )?;
        writeln!(
            f,
            "  RDX: {:#018x}  R11: {:#018x}",
            self.regs[2], self.regs[11]
        )?;
        writeln!(
            f,
            "  RSI: {:#018x}  R12: {:#018x}",
            self.regs[6], self.regs[12]
        )?;
        writeln!(
            f,
            "  RDI: {:#018x}  R13: {:#018x}",
            self.regs[7], self.regs[13]
        )?;
        writeln!(
            f,
            "  RBP: {:#018x}  R14: {:#018x}",
            self.regs[5], self.regs[14]
        )?;
        writeln!(
            f,
            "  RSP: {:#018x}  R15: {:#018x}",
            self.regs[4], self.regs[15]
        )?;
        writeln!(f, "  RIP: {:#018x}", self.rip)?;
        writeln!(
            f,
            "  RFLAGS: {:#018x} {:?}",
            self.rflags.bits(),
            self.rflags
        )?;
        Ok(())
    }
}
