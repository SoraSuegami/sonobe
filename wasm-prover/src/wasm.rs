use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::CurveGroup;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey as G16ProvingKey, VerifyingKey as G16VerifierKey};
use ark_grumpkin::{constraints::GVar as GVar2, Projective as G2};
use ark_poly_commit::kzg10::VerifierKey as KZGVerifierKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use console_error_panic_hook;
use folding_schemes::{
    commitment::{
        kzg::{ProverKey as KZGProverKey, KZG},
        pedersen::{Params as PedersenParams, Pedersen},
        CommitmentScheme,
    },
    folding::nova::{
        decider_eth::{
            point2_to_eth_format, point_to_eth_format, prepare_calldata, Decider as DeciderEth,
            Proof,
        },
        decider_eth_circuit::DeciderEthCircuit,
        get_r1cs, CommittedInstance, Nova, ProverParams, VerifierParams,
    },
    frontend::{circom::CircomFCircuit, FCircuit},
    transcript::poseidon::poseidon_canonical_config,
    Decider, FoldingScheme,
};
use hex;
use js_sys;
use js_sys::Array as JsArray;
use js_sys::Uint8Array;
use rand;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen;
use std::io::BufReader;
use std::io::Read;
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use web_sys::console;

pub use wasm_bindgen_rayon::init_thread_pool;

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

#[derive(Serialize, Deserialize)]
pub struct NovaProofJson {
    pub i_z0_zi: Vec<String>,         // [i, z0, zi] where |z0| == |zi|
    pub U_i_cmW_U_i_cmE: [String; 4], // [U_i_cmW[2], U_i_cmE[2]]
    pub U_i_u_u_i_u_r: [String; 3],   // [U_i_u, u_i_u, r]
    pub U_i_x_u_i_cmW: [String; 4],   // [U_i_x[2], u_i_cmW[2]]
    pub u_i_x_cmT: [String; 4],       // [u_i_x[2], cmT[2]]
    pub pA: [String; 2],              // groth16
    pub pB: [[String; 2]; 2],         // groth16
    pub pC: [String; 2],              // groth16
    pub challenge_W_challenge_E_kzg_evals: [String; 4], // [challenge_W, challenge_E, eval_W, eval_E]
    pub kzg_proof: [[String; 2]; 2],                    // [proof_W, proof_E]
}

impl NovaProofJson {
    pub fn new(
        i: ark_bn254::Fr,
        z_0: &[ark_bn254::Fr],
        z_i: &[ark_bn254::Fr],
        running_instance: &CommittedInstance<ark_bn254::G1Projective>,
        incoming_instance: &CommittedInstance<ark_bn254::G1Projective>,
        proof: &Proof<ark_bn254::G1Projective, KZG<'static, Bn254>, Groth16<Bn254>>,
    ) -> Self {
        let mut i_z0_zi = vec![fr_to_hex(&i)];
        for z in z_0.iter().chain(z_i.iter()) {
            i_z0_zi.push(fr_to_hex(z));
        }
        for z in z_i.iter() {
            i_z0_zi.push(fr_to_hex(z));
        }
        let cmW = point_to_hexes(running_instance.cmW.into_affine());
        let cmE = point_to_hexes(running_instance.cmE.into_affine());
        let U_i_cmW_U_i_cmE = [
            cmW[0].clone(),
            cmW[1].clone(),
            cmE[0].clone(),
            cmE[1].clone(),
        ];
        let U_i_u_u_i_u_r = [
            fr_to_hex(&running_instance.u),
            fr_to_hex(&incoming_instance.u),
            fr_to_hex(&proof.r),
        ];
        let u_i_cmW = point_to_hexes(incoming_instance.cmW.into_affine());
        let U_i_x_u_i_cmW = [
            fr_to_hex(&running_instance.x[0]),
            fr_to_hex(&running_instance.x[1]),
            u_i_cmW[0].clone(),
            u_i_cmW[1].clone(),
        ];
        let cmT = point_to_hexes(proof.cmT.into_affine());
        let u_i_x_cmT = [
            fr_to_hex(&incoming_instance.x[0]),
            fr_to_hex(&incoming_instance.x[1]),
            cmT[0].clone(),
            cmT[1].clone(),
        ];
        let pA = point_to_hexes(proof.snark_proof.a);
        let pB = point2_to_hexes(proof.snark_proof.b);
        let pC = point_to_hexes(proof.snark_proof.c);
        let challenge_W_challenge_E_kzg_evals = [
            fr_to_hex(&proof.kzg_challenges[0]),
            fr_to_hex(&proof.kzg_challenges[1]),
            fr_to_hex(&proof.kzg_proofs[0].eval),
            fr_to_hex(&proof.kzg_proofs[1].eval),
        ];
        let kzg_proof = [
            point_to_hexes(proof.kzg_proofs[0].proof.into_affine()),
            point_to_hexes(proof.kzg_proofs[1].proof.into_affine()),
        ];
        Self {
            i_z0_zi,
            U_i_cmW_U_i_cmE,
            U_i_u_u_i_u_r,
            U_i_x_u_i_cmW,
            u_i_x_cmT,
            pA,
            pB,
            pC,
            challenge_W_challenge_E_kzg_evals,
            kzg_proof,
        }
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn full_prove(
    r1cs_raw: Vec<u8>,
    wasm_bytes: Vec<u8>,
    cs_params: Vec<u8>,
    cf_cs_params: Vec<u8>,
    g16_pk_chunks: JsArray,
    // g16_pk: Vec<u8>,
    init_state: Vec<String>,
    external_inputs: Vec<String>,
    n_steps: usize,
) -> JsValue {
    console::log_1(&"0".into());
    assert!(external_inputs.len() % n_steps == 0);
    console::log_1(&"1".into());
    let external_input_len = external_inputs.len() / n_steps;
    console::log_1(&"2".into());
    let f_circuit =
        CircomFCircuit::<Fr>::new((r1cs_raw, wasm_bytes, init_state.len(), external_input_len))
            .unwrap();
    console::log_1(&"3".into());
    let cs_params = KZGProverKey::<G1>::deserialize_compressed(BufReader::new(&cs_params[..]))
        .expect("Failed to read cs_params");
    console::log_1(&"4".into());
    let cf_cs_params =
        PedersenParams::<G2>::deserialize_compressed(BufReader::new(&cf_cs_params[..]))
            .expect("Failed to read cf_cs_params");
    console::log_1(&"5".into());
    let poseidon_config = poseidon_canonical_config::<Fr>();
    console::log_1(&"6".into());
    let fs_prover_params = ProverParams::<G1, G2, KZG<Bn254>, Pedersen<G2>> {
        poseidon_config,
        cs_params,
        cf_cs_params,
    };
    console::log_1(&"7".into());
    let g16_pk_reader = JsArrayReader::new(g16_pk_chunks);
    let g16_pk = G16ProvingKey::<Bn254>::deserialize_compressed(BufReader::new(g16_pk_reader))
        .expect("Failed to read g16_pk");
    console::log_1(&"8".into());
    let init_state = init_state
        .iter()
        .map(|s| Fr::from_str(s).unwrap())
        .collect::<Vec<Fr>>();
    console::log_1(&"9".into());
    let mut nova = NOVA::init(&fs_prover_params, f_circuit, init_state).unwrap();
    console::log_1(&"10".into());
    for external_input in external_inputs.chunks(external_input_len) {
        let external_input = external_input
            .iter()
            .map(|s| Fr::from_str(s).unwrap())
            .collect::<Vec<Fr>>();
        nova.prove_step(external_input).unwrap();
    }
    console::log_1(&"11".into());
    let rng = rand::rngs::OsRng;
    let proof = DECIDERETH_FCircuit::prove(
        (g16_pk, fs_prover_params.cs_params.clone()),
        rng,
        nova.clone(),
    )
    .unwrap();
    console::log_1(&"12".into());
    let proof_json = NovaProofJson::new(nova.i, &nova.z_0, &nova.z_i, &nova.U_i, &nova.u_i, &proof);
    console::log_1(&"13".into());
    serde_wasm_bindgen::to_value(&proof_json).unwrap()
    // JsValue::null()
}

fn fr_to_hex(fr: &Fr) -> String {
    "0x".to_string() + hex::encode(fr.into_bigint().to_bytes_be()).as_str()
}

fn point_to_hexes(point: ark_bn254::G1Affine) -> [String; 2] {
    let bytes = point_to_eth_format(point).expect("Failed to convert point to eth format");
    [
        "0x".to_string() + hex::encode(&bytes[0..32]).as_str(),
        "0x".to_string() + hex::encode(&bytes[32..64]).as_str(),
    ]
}

fn point2_to_hexes(point: ark_bn254::G2Affine) -> [[String; 2]; 2] {
    let bytes = point2_to_eth_format(point).expect("Failed to convert point to eth format");
    [
        [
            "0x".to_string() + hex::encode(&bytes[0..32]).as_str(),
            "0x".to_string() + hex::encode(&bytes[32..64]).as_str(),
        ],
        [
            "0x".to_string() + hex::encode(&bytes[64..96]).as_str(),
            "0x".to_string() + hex::encode(&bytes[96..128]).as_str(),
        ],
    ]
}

struct JsArrayReader {
    array: JsArray,
    consumed: (usize, usize),
}
impl Read for JsArrayReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let n = buf.len();
        if n == 0 {
            return Ok(0);
        }
        let mut remaining = n;
        while (remaining > 0) {
            if self.consumed.0 >= self.array.length() as usize {
                return Ok(n - remaining);
            }
            let chunk = Uint8Array::new(&self.array.get(self.consumed.0 as u32)).to_vec();
            let read_bytes = std::cmp::min(chunk.len() - self.consumed.1, remaining);
            buf[n - remaining..n - remaining + read_bytes]
                .copy_from_slice(&chunk[self.consumed.1..self.consumed.1 + read_bytes]);
            remaining -= read_bytes;
            self.consumed.1 += read_bytes;
            if self.consumed.1 >= chunk.len() {
                self.consumed.0 += 1;
                self.consumed.1 = 0;
            }
        }
        Ok(n - remaining)
    }
}

impl JsArrayReader {
    fn new(array: JsArray) -> Self {
        Self {
            array,
            consumed: (0, 0),
        }
    }
}
