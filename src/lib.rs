use anyhow::Result;
use itertools::Itertools;
use std::fs;
use std::io::Write;
use std::ops::Deref;
use std::path::Path;
use std::time::Instant;

use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
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

use pod2::{
    backends::plonky2::basetypes::{Proof, C, D, F},
    middleware::ToFields,
};

use crate::poseidon_bn128::config::PoseidonBN128GoldilocksConfig;

pub mod poseidon_bn128;

/// generates a Groth16-friendly plonky2 proof
pub fn prove_pod(
    pod: pod2::frontend::MainPod,
) -> Result<(
    VerifierCircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    CircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    ProofWithPublicInputs<F, PoseidonBN128GoldilocksConfig, D>,
)> {
    // get POD's circuit related data (verifier_data, circuit_data, proof_with_pis)
    let pod_verifier_data: VerifierOnlyCircuitData<C, D> = pod.pod.verifier_data();

    let rec_main_pod_verifier_circuit_data =
        &*pod2::backends::plonky2::mainpod::cache_get_rec_main_pod_verifier_circuit_data(
            &pod.pod.params(),
        );
    let pod_common_circuit_data: CommonCircuitData<F, D> =
        rec_main_pod_verifier_circuit_data.deref().common.clone();

    let pod_proof: Proof = pod.pod.proof();
    let public_inputs = pod
        .id()
        .to_fields(&pod.params)
        .iter()
        .chain(pod.pod.vd_set().root().0.iter())
        .cloned()
        .collect_vec();
    let pod_proof_with_pis = pod2::middleware::ProofWithPublicInputs {
        proof: pod_proof.clone(),
        public_inputs,
    };

    // generate new plonky2 proof from POD's proof
    let start = Instant::now();
    let (verifier_data, common_circuit_data, proof_with_pis) = wrap_bn128(
        pod_verifier_data,
        pod_common_circuit_data,
        pod_proof_with_pis,
    )?;
    println!("[TIME] encapsulation proof took: {:?}", start.elapsed());

    // sanity check: verify proof
    verifier_data.verify(proof_with_pis.clone())?;

    // return
    Ok((verifier_data, common_circuit_data, proof_with_pis))
}

pub fn wrap_bn128(
    verifier_only_data: VerifierOnlyCircuitData<C, D>,
    common_circuit_data: CommonCircuitData<F, D>,
    proof_with_public_inputs: ProofWithPublicInputs<F, C, D>,
) -> Result<(
    VerifierCircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    CircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    ProofWithPublicInputs<F, PoseidonBN128GoldilocksConfig, D>,
)> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder: CircuitBuilder<<PoseidonBN128GoldilocksConfig as GenericConfig<D>>::F, D> =
        CircuitBuilder::new(config);

    // create circuit logic
    let proof_with_pis_target = builder.add_virtual_proof_with_pis(&common_circuit_data);
    let verifier_circuit_target = builder.constant_verifier_data(&verifier_only_data);
    builder.verify_proof::<C>(
        &proof_with_pis_target,
        &verifier_circuit_target,
        &common_circuit_data,
    );

    builder.register_public_inputs(&proof_with_pis_target.public_inputs);

    let circuit_data = builder.build::<PoseidonBN128GoldilocksConfig>();

    // set targets
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&verifier_circuit_target, &verifier_only_data)?;
    pw.set_proof_with_pis_target(&proof_with_pis_target, &proof_with_public_inputs)?;

    let vd = circuit_data.verifier_data();
    let proof = circuit_data.prove(pw)?;

    Ok((vd, circuit_data, proof))
}

pub fn store_files(
    dir: &Path,
    verifier_only_data: VerifierOnlyCircuitData<PoseidonBN128GoldilocksConfig, D>,
    common_circuit_data: CircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    proof_with_pis: ProofWithPublicInputs<F, PoseidonBN128GoldilocksConfig, D>,
) -> Result<()> {
    // create directory
    fs::create_dir_all(dir)?;

    let json = serde_json::to_string_pretty(&verifier_only_data)?;
    let mut file = fs::File::create(&dir.join("verifier_only_circuit_data.json"))?;
    file.write_all(&json.into_bytes())?;

    let json = serde_json::to_string_pretty(&proof_with_pis)?;
    let mut file = fs::File::create(&dir.join("proof_with_public_inputs.json"))?;
    file.write_all(&json.into_bytes())?;

    let json = serde_json::to_string_pretty(&common_circuit_data.common)?;
    let mut file = fs::File::create(&dir.join("common_circuit_data.json"))?;
    file.write_all(&json.into_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use plonky2::field::types::Field;
    use pod2::{
        backends::plonky2::{basetypes::DEFAULT_VD_SET, mainpod::Prover},
        frontend::MainPodBuilder,
        middleware::{containers::Set, Params},
        op,
    };

    // returns a MainPod, example adapted from pod2/examples/main_pod_points.rs
    pub fn compute_pod_proof() -> Result<pod2::frontend::MainPod> {
        let params = Params {
            max_input_signed_pods: 0,
            ..Default::default()
        };

        let mut builder = MainPodBuilder::new(&params, &DEFAULT_VD_SET);
        let set = [1, 2, 3].into_iter().map(|n| n.into()).collect();
        let st = builder
            .pub_op(op!(
                new_entry,
                "entry",
                Set::new(params.max_merkle_proofs_containers, set).unwrap()
            ))
            .unwrap();

        builder.pub_op(op!(set_contains, st, 1))?;

        let prover = Prover {};
        let pod = builder.prove(&prover, &params).unwrap();
        Ok(pod)
    }

    // simple circuit that computes few iterations of the Fibonacci sequence
    pub fn simple_circuit() -> Result<(
        VerifierCircuitData<F, C, D>,
        CommonCircuitData<F, D>,
        ProofWithPublicInputs<F, C, D>,
    )> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // The arithmetic circuit.
        let initial_a = builder.add_virtual_target();
        let initial_b = builder.add_virtual_target();
        let mut prev_target = initial_a;
        let mut cur_target = initial_b;
        for _ in 0..99 {
            let temp = builder.add(prev_target, cur_target);
            prev_target = cur_target;
            cur_target = temp;
        }

        // Public inputs are the two initial values (provided below) and the
        // result (which is generated).
        builder.register_public_input(initial_a);
        builder.register_public_input(initial_b);
        builder.register_public_input(cur_target);

        // Provide initial values.
        let mut pw = PartialWitness::new();
        pw.set_target(initial_a, F::ZERO)?;
        pw.set_target(initial_b, F::ONE)?;

        let data = builder.build::<C>();

        let proof = data.prove(pw)?;
        let vd = data.verifier_data();
        let cd = vd.common.clone();

        Ok((vd, cd, proof))
    }

    // this test exists to be able to generate a quick proof (<1s) instead of
    // the full POD proof.
    #[test]
    fn test_simple_proof_flow() -> Result<()> {
        // fibonacci proof
        let start = Instant::now();
        let (base_verifier_data, base_common_circuit_data, base_proof_with_pis) = simple_circuit()?;
        println!("[TIME] base proof took: {:?}", start.elapsed());

        // generate new plonky2 proof
        let start = Instant::now();
        let (verifier_data, common_circuit_data, proof_with_pis) = wrap_bn128(
            base_verifier_data.verifier_only,
            base_common_circuit_data,
            base_proof_with_pis,
        )?;
        println!(
            "[TIME] encapsulation proof (groth16-friendly) took: {:?}",
            start.elapsed()
        );

        // sanity check: verify proof
        verifier_data.verify(proof_with_pis.clone())?;

        // store the files
        store_files(
            Path::new("testdata/simple_proof"),
            verifier_data.verifier_only,
            common_circuit_data,
            proof_with_pis,
        )?;

        Ok(())
    }

    #[test]
    fn test_pod_flow() -> Result<()> {
        // step 1) obtain the pod to be proven
        let start = Instant::now();
        let pod = compute_pod_proof()?;
        println!(
            "[TIME] generate pod & compute pod proof took: {:?}",
            start.elapsed()
        );

        // step 2) generate new plonky2 proof from POD's proof
        let start = Instant::now();
        let (verifier_data, common_circuit_data, proof_with_pis) = prove_pod(pod)?;
        println!(
            "[TIME] plonky2 proof (groth16-friendly) took: {:?}",
            start.elapsed()
        );

        // step 3) store the files
        store_files(
            Path::new("testdata/pod"),
            verifier_data.verifier_only,
            common_circuit_data,
            proof_with_pis,
        )?;

        Ok(())
    }
}
