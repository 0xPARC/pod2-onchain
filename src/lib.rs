use anyhow::Result;
use itertools::Itertools;
use std::fs;
use std::io::Write;
use std::ops::Deref;
use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};

use plonky2::{
    field::types::{Field, PrimeField64},
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        ext_target::{unflatten_target, ExtensionTarget},
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
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
    backends::plonky2::{
        basetypes::{Proof, C, D, F},
        circuits::{
            common::{CircuitBuilderPod, Flattenable, StatementTarget},
            mainpod::calculate_statements_hash_circuit,
        },
        mainpod::{pad_statement, statement::Statement as bStatement},
    },
    middleware::{Params, Statement, ToFields},
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
        .statements_hash()
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
        &pod.public_statements,
        &pod.params,
    )?;
    println!("[TIME] encapsulation proof took: {:?}", start.elapsed());

    // sanity check: verify proof
    verifier_data.verify(proof_with_pis.clone())?;

    Ok((verifier_data, common_circuit_data, proof_with_pis))
}

// alternative calculate_id version, which instead of using Goldilocks Poseidon,
// it uses sha256
pub fn calculate_statements_hash_sha256(
    statements: &[bStatement],
    params: &Params,
) -> pod2::middleware::Hash {
    assert!(statements.len() <= params.num_public_statements_hash);
    assert!(params.max_public_statements <= params.num_public_statements_hash);

    let mut none_st: bStatement = pod2::middleware::Statement::None.into();
    pad_statement(params, &mut none_st);
    let statements_back_padded = statements
        .iter()
        .chain(std::iter::repeat(&none_st))
        .take(params.num_public_statements_hash)
        .collect_vec();
    let field_elems: Vec<F> = statements_back_padded
        .iter()
        .rev()
        .flat_map(|statement| statement.to_fields(params))
        .collect::<Vec<_>>();

    let b: Vec<u8> = field_elems
        .iter()
        .flat_map(|e| e.to_canonical_u64().to_le_bytes())
        .collect();
    let h: Vec<u8> = Sha256::digest(&b).to_vec();
    bytes_to_hash(h)
}

fn bytes_to_hash(b: Vec<u8>) -> pod2::middleware::Hash {
    assert_eq!(b.len(), 32);
    // make explicit (to the reader of this code) that we only use the first 28
    // bytes, in chunks of 7 bytes, so that we can fit them into 4 field
    // elements (a pod2's Hash type)
    let b: Vec<u8> = b[..28].to_vec();
    let v: [F; 4] = std::array::from_fn(|i| {
        F::from_canonical_u64(u64::from_le_bytes(
            vec![&[0_u8], &b[i * 7..i * 7 + 7]]
                .concat()
                .try_into()
                .unwrap(),
        ))
    });
    pod2::middleware::Hash(v)
}

pub fn wrap_bn128(
    verifier_only_data: VerifierOnlyCircuitData<C, D>,
    common_circuit_data: CommonCircuitData<F, D>,
    proof_with_public_inputs: ProofWithPublicInputs<F, C, D>,
    pub_statements: &[Statement],
    pod_params: &Params,
) -> Result<(
    VerifierCircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    CircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    ProofWithPublicInputs<F, PoseidonBN128GoldilocksConfig, D>,
)> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder: CircuitBuilder<<PoseidonBN128GoldilocksConfig as GenericConfig<D>>::F, D> =
        CircuitBuilder::new(config);

    // 1. create circuit logic, composed of:
    // 1.a. verify pod proof
    // 1.b. hash public statements with Poseidon and check that poseidon output
    //   matches the proof_with_pis.public_inputs first elements
    //
    //   For the hashing of the public inputs, we use the approach described at
    //   https://eprint.iacr.org/2025/1500 and and https://eprint.iacr.org/2024/2099 section 4.2.1.

    // 1.a
    let proof_with_pis_target = builder.add_virtual_proof_with_pis(&common_circuit_data);
    let verifier_circuit_target = builder.constant_verifier_data(&verifier_only_data);
    builder.verify_proof::<C>(
        &proof_with_pis_target,
        &verifier_circuit_target,
        &common_circuit_data,
    );
    // 1.b
    let pub_statements_target: Vec<StatementTarget> = (0..pub_statements.len())
        .map(|_| builder.add_virtual_statement(pod_params))
        .collect();
    // compute beta = poseidon(statements)
    let statements_poseidon_target =
        calculate_statements_hash_circuit(pod_params, &mut builder, &pub_statements_target);

    // ensure that `statements_poseidon_target` matches the given `proof_with_pis_target.public_inputs[0]`
    builder.connect_hashes(
        statements_poseidon_target,
        HashOutTarget::from_vec(proof_with_pis_target.public_inputs[0..4].to_vec()),
    );

    let statements_sha256_target = builder.add_virtual_hash();
    // set alpha & beta to the sum of the elements of original alptha & beta respectively
    let alpha_ext_target: ExtensionTarget<D> =
        ExtensionTarget::<D>::try_from(statements_sha256_target.elements[0..2].to_vec()).unwrap();
    let beta_ext_target: ExtensionTarget<D> =
        ExtensionTarget::<D>::try_from(statements_poseidon_target.elements[0..2].to_vec()).unwrap();
    let sigma_ext_target: ExtensionTarget<D> =
        builder.add_extension(alpha_ext_target, beta_ext_target);

    // NOTE: the statement.flatten() is already computed in the pod2's
    // `calculate_statements_hash_circuit` gadget. Maybe we can modify pod2's
    // lib to return it avoiding recomputing it here.
    let statements_rev_flattened: Vec<Target> = pub_statements_target
        .iter()
        .rev()
        .flat_map(|s| s.flatten())
        .collect();
    let statements_extension = unflatten_target::<D>(&statements_rev_flattened);
    // compute gamma = UHF(sigma, statements) = \sum st_i * sigma^i
    let mut gamma_ext_target: ExtensionTarget<D> =
        statements_extension[statements_extension.len() - 1];
    for st_e in statements_extension.iter().rev().skip(1) {
        gamma_ext_target = builder.mul_add_extension(gamma_ext_target, sigma_ext_target, *st_e);
    }

    // 2. register public inputs, layout:
    //     0..4: poseidon hash (original pod2's pub statements hash)
    //     4..8: vdset.root
    //     8..12: sha256 hash
    //     12..14: gamma

    // register as public inputs the proof's public inputs
    builder.register_public_inputs(&proof_with_pis_target.public_inputs);
    // register as public inputs the sha256 hash of the pub statements, and the gamma
    builder.register_public_inputs(&statements_sha256_target.elements);
    builder.register_public_inputs(&gamma_ext_target.0);
    // Note: statements_poseidon_target is already registered as a public input
    // inside the proof_with_pis_target.public_inputs[0..4]

    let circuit_data = builder.build::<PoseidonBN128GoldilocksConfig>();

    // 3. set targets
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&verifier_circuit_target, &verifier_only_data)?;
    pw.set_proof_with_pis_target(&proof_with_pis_target, &proof_with_public_inputs)?;
    // set the targets for the pub_statements_target
    for (i, st) in pub_statements.iter().enumerate() {
        pub_statements_target[i].set_targets(&mut pw, pod_params, &bStatement::from(st.clone()))?;
    }
    // hash pub_statements using sha256
    let pub_st: Vec<bStatement> = pub_statements
        .iter()
        .map(|st| bStatement::from(st.clone()))
        .collect();
    let statements_sha256 = calculate_statements_hash_sha256(&pub_st, &pod_params);
    // assign the sha256 hash value to the target
    pw.set_hash_target(
        statements_sha256_target,
        HashOut::from_vec(statements_sha256.0.to_vec()),
    )?;
    // get poseidon's output from the pod's proof public inputs
    let statements_poseidon: Vec<F> = proof_with_public_inputs.public_inputs[0..4].to_vec();
    // assign the posedion hash value to the respective target
    pw.set_hash_target(
        statements_poseidon_target,
        HashOut::from_vec(statements_poseidon),
    )?;

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

    let compressed_proof = proof_with_pis.compress(
        &verifier_only_data.circuit_digest,
        &common_circuit_data.common,
    )?;
    let mut file = fs::File::create(&dir.join("proof_with_public_inputs.bin"))?;
    file.write_all(&compressed_proof.to_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use plonky2::field::types::Field;
    use pod2::{
        backends::plonky2::{basetypes::DEFAULT_VD_SET, mainpod::Prover},
        frontend::{MainPodBuilder, Operation},
        middleware::{containers::Set, Params},
    };

    // returns a MainPod, example adapted from pod2/examples/main_pod_points.rs
    pub fn compute_pod_proof() -> Result<pod2::frontend::MainPod> {
        let params = Params {
            max_input_pods: 0,
            ..Default::default()
        };

        let mut builder = MainPodBuilder::new(&params, &DEFAULT_VD_SET);
        let set_entries = [1, 2, 3].into_iter().map(|n| n.into()).collect();
        let set = Set::new(10, set_entries)?;

        builder.pub_op(Operation::set_contains(set, 1))?;

        let prover = Prover {};
        let pod = builder.prove(&prover).unwrap();
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

        // the arithmetic circuit.
        let initial_a = builder.add_virtual_target();
        let initial_b = builder.add_virtual_target();
        let mut prev_target = initial_a;
        let mut cur_target = initial_b;
        for _ in 0..99 {
            let temp = builder.add(prev_target, cur_target);
            prev_target = cur_target;
            cur_target = temp;
        }

        // public inputs are the two initial values (provided below) and the
        // result (which is generated).
        builder.register_public_input(initial_a);
        builder.register_public_input(initial_b);
        builder.register_public_input(cur_target);

        // provide initial values.
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
            &[], // not used in this test
            &Params::default(),
        )?;
        println!(
            "[TIME] encapsulation proof (groth16-friendly) took: {:?}",
            start.elapsed()
        );

        // sanity check: verify proof
        verifier_data.verify(proof_with_pis.clone())?;

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
        assert_eq!(proof_with_pis.public_inputs.len(), 14); // poseidon + vdset_root + sha256 + gamma

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
