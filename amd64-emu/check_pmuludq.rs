fn main() {
    // Check what the actual values are in little-endian
    let data1 = vec![0x00u8, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];
    let data2 = vec![0xFFu8, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
    
    let val1_low = u32::from_le_bytes([data1[0], data1[1], data1[2], data1[3]]);
    let val2_low = u32::from_le_bytes([data2[0], data2[1], data2[2], data2[3]]);
    
    println!("First qword low dword: 0x{:08x}", val1_low);
    println!("Second qword low dword: 0x{:08x}", val2_low);
    
    let mult1 = vec![0x00u8, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00];
    let mult2 = vec![0x00u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    
    let mul1_low = u32::from_le_bytes([mult1[0], mult1[1], mult1[2], mult1[3]]);
    let mul2_low = u32::from_le_bytes([mult2[0], mult2[1], mult2[2], mult2[3]]);
    
    println!("\nFirst multiplier low dword: 0x{:08x}", mul1_low);
    println!("Second multiplier low dword: 0x{:08x}", mul2_low);
    
    // Calculate expected results
    let result1 = (val1_low as u64) * (mul1_low as u64);
    let result2 = (val2_low as u64) * (mul2_low as u64);
    
    println!("\nExpected results:");
    println!("0x{:08x} * 0x{:08x} = 0x{:016x}", val1_low, mul1_low, result1);
    println!("0x{:08x} * 0x{:08x} = 0x{:016x}", val2_low, mul2_low, result2);
}