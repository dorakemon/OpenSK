#![no_main]
#![no_std]

extern crate alloc;
extern crate lang_items;

use bbs::{generate_link_secret_commitment, LinkSecret};
use ctap2::env::tock::TockRng;
use libtock_console::Console;
use libtock_runtime::{set_main, stack_size, TockSyscalls};

stack_size! {0x2000}
set_main! {main}

type Syscalls = TockSyscalls;

fn main() {
    Console::<Syscalls>::write(b"Hellowwwwwww\n").unwrap();

    let mut rng = TockRng::<Syscalls>::default();
    let link_secret = LinkSecret::random(&mut rng);
    let buf = link_secret.to_bytes();
    Console::<Syscalls>::write(b"Link Secret: ").unwrap();
    write_hex(&buf);
    Console::<Syscalls>::write(b"\n").unwrap();

    let commitment = generate_link_secret_commitment(&mut rng, &link_secret).unwrap();
    Console::<Syscalls>::write(b"Commitment: ").unwrap();
    write_hex(&commitment.0);
    Console::<Syscalls>::write(b"\n").unwrap();

    Console::<Syscalls>::write(b"Blinding Factor: ").unwrap();
    write_hex(&commitment.1[..]);
    Console::<Syscalls>::write(b"\n").unwrap();
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
