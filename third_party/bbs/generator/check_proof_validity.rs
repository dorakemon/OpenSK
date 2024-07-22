extern crate std;

use bbs::{verify_link_secret_commitment, BBSPoK};
use serde_json::Value;
use std::{fs, io};
use zkryptium::bbsplus::keys::BBSplusPublicKey;

fn main() -> io::Result<()> {
    let file_path = "fixtures/proof.json";
    let contents = fs::read_to_string(file_path)?;
    let json: Value = serde_json::from_str(&contents)?;

    let pk_hex = json["signerKeyPair"]["publicKey"].as_str().unwrap();
    let pk = BBSplusPublicKey::from_bytes(&hex::decode(pk_hex).unwrap()).unwrap();

    // check the commitment validity
    let commitment_with_proof_hex = json["commitmentWithProof"].as_str().unwrap();
    let result =
        verify_link_secret_commitment(&hex::decode(commitment_with_proof_hex).unwrap()).unwrap();
    assert!(result, "Commitment should be valid.");
    println!("Commitment is valid.");

    // header
    let header = json["header"].as_str().unwrap().as_bytes().to_vec();
    let presentation_header = json["presentationHeader"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();

    // proof
    let proof_bytes = hex::decode(json["proof"].as_str().unwrap()).unwrap();
    let proof = BBSPoK::from_bytes(&proof_bytes).unwrap();
    let disclosed_messages: Vec<Vec<u8>> = json["outputDisclosedMessages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| hex::decode(s.as_str().unwrap()).unwrap())
        .collect();
    // The reason why the indexes are incremented by 2 is because the first two indexes
    // are reserved for `secret_prover_blind + signer_blind` and `link_secret`
    // https://github.com/Cybersecurity-LINKS/zkryptium/blob/0e21c20f4c84473e7eb69a1aef136159c9d085b8/src/utils/util.rs#L403-L453
    // let disclosed_indexes: Vec<usize> = disclosed_indexes.iter().map(|&i| i + 2).collect();
    // let disclosed_indexes: &[usize] = disclosed_indexes.as_slice();
    let disclosed_indexes: Vec<usize> = json["disclosedIndexes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v.as_u64().unwrap() as usize) + 2)
        .collect();
    let disclosed_messages: Option<Vec<Vec<u8>>> = Some(disclosed_messages);
    let disclosed_indexes: Option<Vec<usize>> = Some(disclosed_indexes);

    let result = proof
        .blind_proof_verify(
            &pk,
            disclosed_messages.as_ref().map(|v| v.as_slice()),
            disclosed_indexes.as_ref().map(|v| v.as_slice()),
            Some(&header),
            Some(&presentation_header),
        )
        .is_ok();
    assert!(result, "Proof should be valid");
    println!("Proof is valid.");

    Ok(())
}
