#![no_main]
#![no_std]

extern crate alloc;
extern crate lang_items;

use alloc::format;
use alloc::vec::Vec;
use bbs::{generate_proof, BBSCommitmentBlindFactor, BBSPublicKey, BBSSignature, LinkSecret};
use ctap2::env::tock::TockRng;
use libtock_console::Console;
use libtock_runtime::{set_main, stack_size, TockSyscalls};

stack_size! {0x4000}
set_main! {main}

type Syscalls = TockSyscalls;

#[no_mangle]
pub fn main() {
    write_str("Starting BBS Proof Generation\n");

    let mut rng = TockRng::<Syscalls>::default();

    // Link Secret
    let link_secret_hex = "c222824642ae0fb0a0f2b4e1edeab0181357110b48ae378099141397362427ef";
    let link_secret = LinkSecret::from_bytes(hex_to_bytes_constant_size::<32>(link_secret_hex));

    // Signer's key pair
    let pk_hex = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5";
    let pk = BBSPublicKey::from_bytes(&hex_to_bytes(pk_hex)).unwrap();

    // Header and messages
    let header = b"";
    let presentation_header = b"";
    let messages = alloc::vec![b"Hello, World!".to_vec()];
    let disclosed_indexes = alloc::vec![];

    // Signature
    let signature_hex = "86848aa3d2ec9b2f9a5712a6c776c22aff095a4e222f052932f22bb22e4559f190c125af7510231c12b22d4f80708de96295d4eabfdf4e62c2874c325d0a22916ccf536c3a760b9542422d5a6093924a";
    let signature =
        BBSSignature::from_bytes(&hex_to_bytes_constant_size::<80>(signature_hex)).unwrap();

    let secret_prover_blind_hex =
        "43cb7a2b5dde058ae7af7b9fe2fe776ed9fdfc33431f02422515db4dc6837012";
    let secret_prover_blind = BBSCommitmentBlindFactor::from_bytes(
        &hex_to_bytes_constant_size::<32>(secret_prover_blind_hex),
    )
    .unwrap();

    // Generate proof
    let proof_response = generate_proof(
        &mut rng,
        &pk,
        &messages,
        &link_secret,
        &signature,
        Some(header),
        Some(presentation_header),
        &disclosed_indexes,
        Some(&secret_prover_blind),
    )
    .unwrap();

    write_str("Proof: ");
    write_hex(&proof_response.proof.to_bytes());
    write_str("\n");
    // Note: We can't easily print complex types in no_std environment
    // So we'll skip printing disclosed_messages and disclosed_indexes
}

fn write_str(s: &str) {
    Console::<Syscalls>::write(s.as_bytes()).unwrap();
}

fn write_hex(bytes: &[u8]) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut buf = [0; 64];
    for chunk in bytes.chunks(32) {
        for (i, &byte) in chunk.iter().enumerate() {
            buf[i * 2] = HEX_CHARS[(byte >> 4) as usize];
            buf[i * 2 + 1] = HEX_CHARS[(byte & 0xf) as usize];
        }
        Console::<Syscalls>::write(&buf[..chunk.len() * 2]).unwrap();
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut iter = hex.chars();
    while let (Some(h), Some(l)) = (iter.next(), iter.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", h, l), 16).unwrap();
        bytes.push(byte);
    }
    bytes
}

fn hex_to_bytes_constant_size<const N: usize>(hex: &str) -> [u8; N] {
    let mut bytes = [0u8; N];
    let mut iter = hex.chars();
    for i in 0..N {
        let h = iter.next().unwrap();
        let l = iter.next().unwrap();
        bytes[i] = u8::from_str_radix(&format!("{}{}", h, l), 16).unwrap();
    }
    bytes
}
