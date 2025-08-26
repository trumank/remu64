fn main() {
    let xmm0: u128 = 0x10203040_50607080_90A0B0C0_D0E0F000;
    let xmm1: u128 = 0x08182838_48586878_8898A8B8_C8D8E8F8;
    
    println!("XMM0 bytes:");
    for i in 0..16 {
        let shift = i * 8;
        let byte = ((xmm0 >> shift) & 0xFF) as u8;
        print!("{:02x} ", byte);
    }
    println!();
    
    println!("XMM1 bytes:");
    for i in 0..16 {
        let shift = i * 8;
        let byte = ((xmm1 >> shift) & 0xFF) as u8;
        print!("{:02x} ", byte);
    }
    println!();
    
    println!("\nMax of each pair:");
    let mut result = 0u128;
    for i in 0..16 {
        let shift = i * 8;
        let byte0 = ((xmm0 >> shift) & 0xFF) as u8;
        let byte1 = ((xmm1 >> shift) & 0xFF) as u8;
        let max_byte = std::cmp::max(byte0, byte1);
        print!("{:02x} ", max_byte);
        result |= (max_byte as u128) << shift;
    }
    println!();
    
    println!("\nExpected: 0x{:032x}", 0x10283840_50687880_98A8B8C8_D8E8F8F8u128);
    println!("Computed: 0x{:032x}", result);
}