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
