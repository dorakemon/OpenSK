use zkryptium::bbsplus::ciphersuites::Bls12381Shake256;
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BBSplus;
use zkryptium::schemes::generics::Commitment;

pub type BBSCiphersuite = Bls12381Shake256;
pub type BBS = BBSplus<BBSCiphersuite>;
pub type BBSSecretKey = BBSplusSecretKey;
pub type BBSPublicKey = BBSplusPublicKey;
pub type BBSKeyPair = KeyPair<BBS>;
pub type BBSCommitment = Commitment<BBSplus<BBSCiphersuite>>;
