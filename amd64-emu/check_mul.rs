fn main() {
    let val1: u16 = 0x6000;
    let val2: u16 = 0x200;
    
    let product = (val1 as u32) * (val2 as u32);
    let high_word = (product >> 16) as u16;
    
    println!("0x{:04x} * 0x{:04x} = 0x{:08x}", val1, val2, product);
    println!("High 16 bits: 0x{:04x} = {}", high_word, high_word);
    
    // Check signed multiplication for -16384 * 4
    let val3: i16 = -16384;
    let val4: i16 = 4;
    let signed_product = (val3 as i32) * (val4 as i32);
    let signed_high = ((signed_product >> 16) & 0xFFFF) as u16;
    println!("\n{} * {} = {}", val3, val4, signed_product);
    println!("High 16 bits: 0x{:04x}", signed_high);
}