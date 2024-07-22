use rand_core::RngCore;
use zkryptium::errors::Error;

use alloc::vec;
use alloc::vec::Vec;

use crate::{BBSCommitmentBlindFactor, BBSPoK, BBSPublicKey, BBSSignature, LinkSecret};

// LinkSecretProof構造体の定義
#[derive(Debug, Eq, PartialEq)]
pub struct BBSProofResponse {
    pub proof: BBSPoK,
    pub disclosed_messages: Vec<Vec<u8>>,
    pub disclosed_indexes: Vec<usize>,
}

pub fn generate_proof<R: RngCore>(
    rng: &mut R,
    public_key: &BBSPublicKey,
    messages: &[Vec<u8>],
    link_secret: &LinkSecret,
    signature: &BBSSignature,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    disclosed_indexes: &[usize],
    secret_prover_blind: Option<&BBSCommitmentBlindFactor>,
) -> Result<BBSProofResponse, Error> {
    // Only the link secret is committed
    let committed_messages = vec![link_secret.to_bytes().to_vec()];
    // Never disclose the link secret, so no indexes are disclosed
    let disclosed_commitment_indexes: Option<Vec<usize>> = None;

    // PoKSignatureを生成
    let (proof, disclosed_msgs, disclosed_idxs) = BBSPoK::blind_proof_gen(
        rng,
        public_key,
        &signature.to_bytes(),
        header,
        presentation_header,
        Some(messages),
        Some(&committed_messages),
        Some(&disclosed_indexes),
        disclosed_commitment_indexes.as_deref(),
        secret_prover_blind,
        None, // signer_blindはNone
    )?;

    // LinkSecretProofを構築して返す
    Ok(BBSProofResponse {
        proof,
        disclosed_messages: disclosed_msgs,
        disclosed_indexes: disclosed_idxs,
    })
}
