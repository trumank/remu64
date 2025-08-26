fn main() {
    // Check unsigned multiplication for 0xC000 * 4
    let val1: u16 = 0xC000;
    let val2: u16 = 4;
    let product = (val1 as u32) * (val2 as u32);
    let high_word = (product >> 16) as u16;
    
    println!("0x{:04x} * {} = 0x{:08x}", val1, val2, product);
    println!("High 16 bits: 0x{:04x} = {}", high_word, high_word);
    
    // Also check 0xFFFF * 1
    let val3: u16 = 0xFFFF;
    let val4: u16 = 1;
    let product2 = (val3 as u32) * (val4 as u32);
    let high_word2 = (product2 >> 16) as u16;
    
    println!("\n0x{:04x} * {} = 0x{:08x}", val3, val4, product2);
    println!("High 16 bits: 0x{:04x} = {}", high_word2, high_word2);
}