use rand_core::RngCore;

pub struct LinkSecret([u8; 32]);

impl LinkSecret {
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        LinkSecret(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::LinkSecret;

    #[test]
    fn test_link_secret_random_with_osrng() {
        let mut rng = OsRng;
        let secret1 = LinkSecret::random(&mut rng);
        let secret2 = LinkSecret::random(&mut rng);

        assert_ne!(secret1.to_bytes(), secret2.to_bytes());
        assert_eq!(secret1.to_bytes().len(), 32);
    }
}
