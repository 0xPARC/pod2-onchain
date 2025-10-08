//! This file offers methods for the Groth16 proofs which internally call the Go
//! methods through FFI.

use std::ffi::{c_char, c_int, c_uchar, CStr, CString};

use anyhow::{anyhow, Result};
use plonky2::plonk::proof::ProofWithPublicInputs;
use pod2::backends::plonky2::basetypes::{D, F};

use crate::poseidon_bn128::config::PoseidonBN128GoldilocksConfig;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// computes the Groth16 trusted setup. Method only for tests, do not use in
/// production.
pub fn trusted_setup(input_path: &str, output_path: &str) -> String {
    let input_path = CString::new(input_path).unwrap();
    let output_path = CString::new(output_path).unwrap();

    unsafe {
        let cstr = CStr::from_ptr(TrustedSetup(
            input_path.as_ptr() as *mut c_char,
            output_path.as_ptr() as *mut c_char,
        ));
        let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
        GoFree(cstr.as_ptr() as *mut c_uchar);
        s
    }
}

/// Loads into memory the
///   - Groth16's R1CS, ProvingKey and VerifierKey
///   - Plonky2's VerifierOnlyCircuitData, CommonCircuitData
/// so that they can be used by later calls to `groth16_prove` and `groth16_verify`.
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

/// compute a Groth16 proof out of the given Plonky2's ProofWithPublicInputs
pub fn groth16_prove(
    proof_with_pis: ProofWithPublicInputs<F, PoseidonBN128GoldilocksConfig, D>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let json: String = serde_json::to_string_pretty(&proof_with_pis)?;
    let input: Vec<u8> = json.into_bytes();
    let mut proof_out_len: c_int = 0;
    let mut wit_out_len: c_int = 0;
    let res = unsafe {
        Groth16Proof(
            input.as_ptr() as *mut u8,
            input.len() as c_int,
            &mut proof_out_len as *mut c_int,
            &mut wit_out_len as *mut c_int,
        )
    };
    let (proof_out_ptr, wit_out_ptr) = (res.r0, res.r1);

    let proof_bytes: Vec<u8> = if proof_out_len > 0 && !proof_out_ptr.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(proof_out_ptr, proof_out_len as usize) };
        let vec = slice.to_vec();
        unsafe { GoFree(proof_out_ptr) };
        vec
    } else {
        return Err(anyhow!("groth16_prove: null pointer of proof_out"));
    };
    let pub_inp_bytes: Vec<u8> = if wit_out_len > 0 && !wit_out_ptr.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(wit_out_ptr, wit_out_len as usize) };
        let vec = slice.to_vec();
        unsafe { GoFree(wit_out_ptr) };
        vec
    } else {
        return Err(anyhow!("groth16_prove: null pointer of wit_out"));
    };
    Ok((proof_bytes, pub_inp_bytes))
}

/// verify the given Groth16 proof with the given public inputs
pub fn groth16_verify(proof: Vec<u8>, public_inputs: Vec<u8>) -> Result<()> {
    let res_string = unsafe {
        let ptr = Groth16Verify(
            proof.as_ptr() as *mut u8,
            proof.len() as c_int,
            public_inputs.as_ptr() as *mut u8,
            public_inputs.len() as c_int,
        );

        let cstr = CStr::from_ptr(ptr);
        let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
        GoFree(cstr.as_ptr() as *mut c_uchar);
        s
    };
    if res_string != "ok" {
        return Err(anyhow!(res_string));
    }
    Ok(())
}
