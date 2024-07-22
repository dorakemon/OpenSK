use zkryptium::bbsplus::ciphersuites::Bls12381Shake256;
use zkryptium::bbsplus::commitment::BlindFactor;
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BBSplus;
use zkryptium::schemes::generics::{Commitment, PoKSignature, Signature};

pub type BBSCiphersuite = Bls12381Shake256;
pub type BBS = BBSplus<BBSCiphersuite>;
pub type BBSSecretKey = BBSplusSecretKey;
pub type BBSPublicKey = BBSplusPublicKey;
pub type BBSKeyPair = KeyPair<BBS>;
pub type BBSCommitment = Commitment<BBS>;
pub type BBSCommitmentBlindFactor = BlindFactor;
pub type BBSSignature = Signature<BBS>;
pub type BBSPoK = PoKSignature<BBS>;
