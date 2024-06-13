use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, ProvingKey as G16ProvingKey, VerifyingKey as G16VerifierKey};
use ark_grumpkin::{constraints::GVar as GVar2, Projective as G2};
use ark_poly_commit::kzg10::VerifierKey as KZGVerifierKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use folding_schemes::{
    commitment::{
        kzg::{ProverKey as KZGProverKey, KZG},
        pedersen::{Params as PedersenParams, Pedersen},
        CommitmentScheme,
    },
    folding::nova::{
        decider_eth::{prepare_calldata, Decider as DeciderEth},
        decider_eth_circuit::DeciderEthCircuit,
        get_r1cs, Nova, ProverParams, VerifierParams,
    },
    frontend::{circom::CircomFCircuit, FCircuit},
    transcript::poseidon::poseidon_canonical_config,
    Decider, FoldingScheme,
};
use rand;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

type NOVA = Nova<G1, GVar, G2, GVar2, CircomFCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>>;
pub type DECIDERETH_FCircuit = DeciderEth<
    G1,
    GVar,
    G2,
    GVar2,
    CircomFCircuit<Fr>,
    KZG<'static, Bn254>,
    Pedersen<G2>,
    Groth16<Bn254>,
    NOVA,
>;

#[wasm_bindgen]
pub fn full_prove(
    r1cs_raw: Vec<u8>,
    wasm_bytes: Vec<u8>,
    cs_params: Vec<u8>,
    cf_cs_params: Vec<u8>,
    g16_pk: Vec<u8>,
    init_state: Vec<String>,
    external_inputs: Vec<String>,
    n_steps: usize,
) {
    assert!(external_inputs.len() % n_steps == 0);
    let external_input_len = external_inputs.len() / n_steps;
    let f_circuit =
        CircomFCircuit::<Fr>::new((r1cs_raw, wasm_bytes, init_state.len(), external_input_len))
            .unwrap();
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
    let init_state = init_state
        .iter()
        .map(|s| Fr::from_str(s).unwrap())
        .collect::<Vec<Fr>>();
    let mut nova = NOVA::init(&fs_prover_params, f_circuit, init_state).unwrap();
    for external_input in external_inputs.chunks(external_input_len) {
        let external_input = external_input
            .iter()
            .map(|s| Fr::from_str(s).unwrap())
            .collect::<Vec<Fr>>();
        nova.prove_step(external_input).unwrap();
    }
    let rng = rand::rngs::OsRng;
    let proof = DECIDERETH_FCircuit::prove(
        (g16_pk, fs_prover_params.cs_params.clone()),
        rng,
        nova.clone(),
    )
    .unwrap();
}
