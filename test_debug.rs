fn main() {
    let expected: u128 = 0x0008_0007_0006_0005_0001_0002_0003_0004;
    let got: u128 = 41538929472669868031141181829283841;
    println!("Expected: {:#034x}", expected);
    println!("Got:      {:#034x}", got);
    
    // Also show PSHUFHW
    let expected2: u128 = 0x0005_0006_0007_0008_0004_0003_0002_0001;
    println!("PSHUFHW Expected: {:#034x}", expected2);
}