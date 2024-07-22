use alloc::boxed::Box;
use rand_core::RngCore;
use zkryptium::bbsplus::ciphersuites::BbsCiphersuite;
use zkryptium::bbsplus::generators::Generators;

use crate::{BBSCiphersuite, BBSCommitment, BBSError, LinkSecret};

// Is it okay that there's no Signer (Issuer) challenge as input here?
// If we don't include a nonce prepared by the Signer, someone who intercepts this Commitment could reuse it,
// and create something arbitrarily linked to the authenticator,
// but without the authenticator, they can't create a VP anyway, so does it matter?
pub fn generate_link_secret_commitment<R: RngCore>(
    rng: &mut R,
    link_secret: &LinkSecret,
) -> Result<(Box<[u8]>, Box<[u8; 32]>), BBSError> {
    let secret_messages = [link_secret.to_bytes().to_vec()];

    let (commitment_with_proof, secret_prover_blind) =
        BBSCommitment::commit(rng, Some(&secret_messages)).unwrap();

    Ok((
        commitment_with_proof.to_bytes().into_boxed_slice(),
        Box::new(secret_prover_blind.to_bytes()),
    ))
}

pub fn verify_link_secret_commitment(commitment_with_proof: &[u8]) -> Result<bool, BBSError> {
    // Only the link_secret is committed, so the length is 1
    const COMMITTED_MESSAGE_LEN: usize = 1;
    let generators = Generators::create::<BBSCiphersuite>(
        COMMITTED_MESSAGE_LEN + 2,
        Some(BBSCiphersuite::API_ID_BLIND),
    );

    let result = BBSCommitment::deserialize_and_validate_commit(
        Some(&commitment_with_proof),
        &generators,
        Some(BBSCiphersuite::API_ID_BLIND),
    )
    .is_ok();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::{generate_link_secret_commitment, verify_link_secret_commitment, LinkSecret};

    #[test]
    fn test_generate_link_secret_commitment() {
        let mut rng = OsRng;

        let link_secret = LinkSecret::random(&mut rng);

        let result = generate_link_secret_commitment(&mut rng, &link_secret);

        assert!(result.is_ok(), "Function should return Ok");

        if let Ok((commitment, secret_blind)) = &result {
            assert!(!commitment.is_empty(), "Commitment should not be empty");
            assert!(!secret_blind.is_empty(), "Secret blind should not be empty");

            let result = verify_link_secret_commitment(commitment).unwrap();
            assert!(result, "Commitment should be valid");
        }
    }
}
