use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, ProvingKey as G16ProvingKey, VerifyingKey as G16VerifierKey};
use ark_grumpkin::Projective as G2;
use ark_poly_commit::kzg10::VerifierKey as KZGVerifierKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use folding_schemes::{
    commitment::{
        kzg::{ProverKey as KZGProverKey, KZG},
        pedersen::{Params as PedersenParams, Pedersen},
        CommitmentScheme,
    },
    folding::nova::{
        decider_eth_circuit::DeciderEthCircuit, get_r1cs, Nova, ProverParams, VerifierParams,
    },
    frontend::{circom::CircomFCircuit, FCircuit},
    transcript::poseidon::poseidon_canonical_config,
    FoldingScheme,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn full_prove(
    r1cs_raw: Vec<u8>,
    wasm_bytes: Vec<u8>,
    init_state: Vec<String>,
    external_inputs: Vec<String>,
    cs_params: Vec<u8>,
    cf_cs_params: Vec<u8>,
    g16_pk: Vec<u8>,
) {
    let f_circuit = CircomFCircuit::<Fr>::new((
        r1cs_raw,
        wasm_bytes,
        init_state.len(),
        external_inputs.len(),
    ));
    let cs_params = KZGProverKey::<G1>::deserialize_compressed(&cs_params[..])
        .expect("Failed to read cs_params");
    let cf_cs_params = PedersenParams::<G2>::deserialize_compressed(&cf_cs_params[..])
        .expect("Failed to read cf_cs_params");
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let fs_prover_params = ProverParams::<G1, G2, KZG<Bn254>, Pedersen<G2>> {
        poseidon_config,
        cs_params,
        cf_cs_params,
    };
    let g16_pk =
        G16ProvingKey::<Bn254>::deserialize_compressed(&g16_pk[..]).expect("Failed to read g16_pk");
}
