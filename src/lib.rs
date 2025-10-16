#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod groth;
pub mod pod;
pub mod poseidon_bn128;

// expose directly the main methods
pub use groth::{groth16_prove, groth16_verify, init, load_vk, trusted_setup};
pub use pod::{encode_public_inputs_gnark, prepare_public_inputs, prove_pod};

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::path::Path;
    use std::time::Instant;

    use pod::{sample_main_pod, sample_plonky2_g16_friendly_proof};

    #[test]
    fn test_groth_full_flow() -> Result<()> {
        let input_path = "./tmp/plonky2-proof";
        let output_path = "./tmp/groth-artifacts";

        // if plonky2 groth16-friendly proof does not exist yet, generate it
        if !Path::new(input_path).is_dir() {
            println!("generating plonky2 groth16-friendly proof");
            sample_plonky2_g16_friendly_proof(input_path)?;
        }

        // if trusted setup does not exist yet, generate it
        if !Path::new(output_path).is_dir() {
            println!("generating groth16's trusted setup");
            let result = trusted_setup(input_path, output_path);
            println!("trusted_setup result: {}", result);
        }

        let result = init(input_path, output_path)?;
        println!("init result: {}", result);

        let result = groth::check_init();
        println!("check_init result: {}", result);

        let pod = sample_main_pod()?;
        let (_, _, proof_with_pis) = crate::pod::prove_pod(pod)?;

        println!("calling groth16_prove");
        let start = Instant::now();
        let (g16_proof, g16_pub_inp) = groth16_prove(proof_with_pis.clone())?;
        println!("[TIME] groth16_prove took: {:?}", start.elapsed());

        groth16_verify(g16_proof, g16_pub_inp.clone())?;

        // check that the `encode_public_inputs_gnark` method works as expected
        assert_eq!(
            g16_pub_inp,
            encode_public_inputs_gnark(proof_with_pis.public_inputs)
        );

        Ok(())
    }
}
