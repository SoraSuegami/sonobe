#[cfg(not(target_arch = "wasm32"))]
pub mod evm;
#[cfg(not(target_arch = "wasm32"))]
pub mod utils;
#[cfg(not(target_arch = "wasm32"))]
pub mod verifiers;

#[cfg(not(target_arch = "wasm32"))]
pub use verifiers::*;
#[cfg(not(target_arch = "wasm32"))]
pub use verifiers::{
    get_decider_template_for_cyclefold_decider, Groth16VerifierKey, KZG10VerifierKey,
    NovaCycleFoldVerifierKey, ProtocolVerifierKey,
};
