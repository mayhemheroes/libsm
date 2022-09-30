#![no_main]
use libfuzzer_sys::fuzz_target;
use libsm::sm2::signature::SigCtx;
use libsm::sm3::hash::Sm3Hash;
use libsm::sm4::{Mode, Cipher};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 {
        let opt1 = data[0] % 3;

        let new_data = &data[1..];

        match opt1 {
            0=>{
                let ctx = SigCtx::new();
                let (pk, sk) = ctx.new_keypair().expect("Bad Keypair SM2");
                let signature = ctx.sign(&new_data, &sk, &pk).expect("Bad Signature SM2");
                let _ = ctx.verify(&new_data, &pk, &signature).expect("Bad Verify SM2");
            },
            1=>{
                let mut hash = Sm3Hash::new(new_data);
                let _: [u8;32] = hash.get_hash();
            },
            2=>{
                if new_data.len() > 2 {
                    let opt2 = new_data[0] % 4;
                    let sm4_data = &new_data[1..];
                    if sm4_data.len() > 16 + 16 + 16 {
                        let mut mode: Mode = Mode::Cfb;
                        match opt2 {
                            0=>{
                                mode = Mode::Cfb;
                            },
                            1=>{
                                mode = Mode::Ofb;
                            },
                            2=>{
                                mode = Mode::Ctr;
                            },
                            3=>{
                                mode = Mode::Cbc;
                            },
                            _=>()
                        }
                        let key = &sm4_data[0..16];
                        let iv = &sm4_data[16..32];
                        let cipher = Cipher::new(&key, mode).expect("Bad SM4");
                        cipher.encrypt(&sm4_data[32..], &iv).expect("Bad SM4 Encrypt");
                    }
                }
            },
            _=>()
        }
    }
});
