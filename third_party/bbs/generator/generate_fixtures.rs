extern crate std;

use bbs::{
    generate_link_secret_commitment, generate_proof, BBSCommitmentBlindFactor, BBSPublicKey,
    BBSSecretKey, BBSSignature, LinkSecret, BBS,
};
use rand_core::OsRng;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Write};
use zkryptium::schemes::generics::BlindSignature;

fn main() -> io::Result<()> {
    let file_path = "fixtures/proof.json";
    let contents = fs::read_to_string(file_path)?;
    let mut json: Value = serde_json::from_str(&contents)?;

    let mut rng = OsRng;
    let link_secret = LinkSecret::random(&mut rng);
    json["linkSecret"] = json!(hex::encode(link_secret.to_bytes()));

    // signer's key pair
    let sk_hex = json["signerKeyPair"]["secretKey"].as_str().unwrap();
    let pk_hex = json["signerKeyPair"]["publicKey"].as_str().unwrap();
    let sk = BBSSecretKey::from_bytes(&hex::decode(sk_hex).unwrap()).unwrap();
    let pk = BBSPublicKey::from_bytes(&hex::decode(pk_hex).unwrap()).unwrap();

    // header and messages and disclosed indexes
    let header = json["header"].as_str().unwrap().as_bytes().to_vec();
    let presentation_header = json["presentationHeader"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    let messages: Vec<Vec<u8>> = json["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap().as_bytes().to_vec())
        .collect();
    let disclosed_indexes: Vec<usize> = json["disclosedIndexes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as usize)
        .collect();

    // commitment
    let (commitment_with_proof, secret_prover_blind) =
        generate_link_secret_commitment(&mut rng, &link_secret)
            .expect("Failed to generate commitment");
    json["proverBlindFactor"] = json!(hex::encode(&*secret_prover_blind));
    json["commitmentWithProof"] = json!(hex::encode(&*commitment_with_proof));

    // signature
    let blind_sig = BlindSignature::<BBS>::blind_sign(
        &sk,
        &pk,
        Some(&commitment_with_proof),
        Some(&header),
        Some(&messages),
        None,
    )
    .expect("Failed to generate blind signature");
    let hex_sig = hex::encode(blind_sig.to_bytes());
    json["signature"] = json!(hex_sig);

    let proof_response = generate_proof(
        &mut rng,
        &pk,
        &messages,
        &link_secret,
        &BBSSignature::from_bytes(&blind_sig.to_bytes()).unwrap(),
        Some(&header),
        Some(&presentation_header),
        &disclosed_indexes,
        Some(&BBSCommitmentBlindFactor::from_bytes(&secret_prover_blind).unwrap()),
    )
    .expect("Failed to generate proof");
    let proof_bytes = proof_response.proof.to_bytes();
    let disclosed_messages = proof_response.disclosed_messages;
    let disclosed_indexes = proof_response.disclosed_indexes;
    json["proof"] = json!(hex::encode(proof_bytes));
    let disclosed_messages: Vec<String> =
        disclosed_messages.iter().map(|m| hex::encode(m)).collect();
    json["outputDisclosedMessages"] = json!(disclosed_messages);
    json["outputDisclosedIndexes"] = json!(disclosed_indexes);

    // ファイルに書き戻す
    let mut file = fs::File::create(file_path)?;
    file.write_all(serde_json::to_string_pretty(&json)?.as_bytes())?;

    println!("\nJSON file has been updated.");

    Ok(())
}
