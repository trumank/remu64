use amd64_emu::decoder::{Decoder, DecoderMode};

fn main() {
    let decoder = Decoder::new(DecoderMode::Mode64);
    
    let code = [
        0x0F, 0x28, 0xC1,  // movaps xmm0, xmm1
    ];
    
    let result = decoder.decode(&code, 0x1000);
    println!("Decode result: {:?}", result);
}