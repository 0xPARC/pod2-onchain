#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::{c_char, c_int, c_uchar, c_uint, CStr, CString};
use std::ptr;

use anyhow::Result;
use plonky2::{
    plonk::config::GenericConfig,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierOnlyCircuitData,
        },
        proof::ProofWithPublicInputs,
    },
};
use pod2::backends::plonky2::basetypes::{Proof, C, D, F};

use pod2_onchain::poseidon_bn128::config::PoseidonBN128GoldilocksConfig;

pub fn init(input_path: &str, output_path: &str) -> String {
    let input_path = CString::new(input_path).unwrap();
    let output_path = CString::new(output_path).unwrap();

    unsafe {
        let cstr = CStr::from_ptr(Init(
            input_path.as_ptr() as *mut c_char,
            output_path.as_ptr() as *mut c_char,
        ));
        let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
        GoFree(cstr.as_ptr() as *mut c_uchar);
        s
    }
}

pub fn check_init() -> String {
    unsafe {
        let cstr = CStr::from_ptr(CheckInit());
        let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
        GoFree(cstr.as_ptr() as *mut c_uchar);
        s
    }
}

pub fn groth16_prove(
    proof_with_pis: ProofWithPublicInputs<F, PoseidonBN128GoldilocksConfig, D>,
) -> Result<Vec<u8>> {
    let json: String = serde_json::to_string_pretty(&proof_with_pis)?;
    let input: Vec<u8> = json.into_bytes();
    let mut out_len: c_int = 0;
    let out_ptr = unsafe {
        Groth16Proof(
            input.as_ptr() as *mut u8,
            input.len() as c_int,
            &mut out_len as *mut c_int,
        )
    };

    let output: Vec<u8> = if out_len > 0 && !out_ptr.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(out_ptr, out_len as usize) };
        let vec = slice.to_vec();
        unsafe { GoFree(out_ptr) };
        vec
    } else {
        vec![]
    };
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    use pod2::{
        backends::plonky2::{basetypes::DEFAULT_VD_SET, mainpod::Prover},
        frontend::{MainPodBuilder, Operation},
        middleware::{containers::Set, Params},
    };

    // returns a MainPod, example adapted from pod2/examples/main_pod_points.rs
    pub fn compute_pod_proof() -> Result<pod2::frontend::MainPod> {
        let params = Params::default();

        let mut builder = MainPodBuilder::new(&params, &DEFAULT_VD_SET);
        let set_entries = ["somestring", "2", "3"]
            .into_iter()
            .map(|n| n.into())
            .collect();
        let set = Set::new(10, set_entries)?;

        builder.pub_op(Operation::set_contains(set, "3"))?;

        let prover = Prover {};
        let pod = builder.prove(&prover).unwrap();
        Ok(pod)
    }

    #[test]
    fn test_ffi_bindings() -> Result<()> {
        let result = init("../tmp/plonky2-proof", "../tmp/groth-artifacts");
        println!("init result: {}", result);

        let result = check_init();
        println!("check_init result: {}", result);

        let pod = compute_pod_proof()?;
        let (_, _, proof_with_pis) = pod2_onchain::prove_pod(pod)?;

        println!("calling groth16_prove");
        let g16_proof_bytes = groth16_prove(proof_with_pis);
        println!("g16 proof: {:?}", g16_proof_bytes);

        Ok(())
    }
}
