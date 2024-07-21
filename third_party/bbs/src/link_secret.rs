use rand_core::RngCore;
use zeroize::Zeroize;

#[derive(Debug, Eq, PartialEq, Zeroize)]
pub struct LinkSecret([u8; LinkSecret::SIZE]);

impl LinkSecret {
    pub const SIZE: usize = 32;

    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        LinkSecret(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        LinkSecret(bytes)
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
        assert_eq!(secret1.to_bytes().len(), LinkSecret::SIZE);
    }
}
