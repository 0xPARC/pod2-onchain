use anyhow::Result;
use itertools::Itertools;
use std::fs;
use std::io::Write;
use std::iter;
use std::ops::Deref;
use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};

use plonky2::{
    field::types::{Field, PrimeField64},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::PlonkyPermutation,
        poseidon::PoseidonHash,
        poseidon::PoseidonPermutation,
    },
    iop::{
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
        config::AlgebraicHasher,
        proof::ProofWithPublicInputs,
    },
};

use pod2::{
    backends::plonky2::{
        basetypes::{Proof, C, D, F},
        circuits::common::{Flattenable, StatementTarget},
        mainpod,
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
        &pod.public_statements,
        pod.params,
    )?;
    println!("[TIME] encapsulation proof took: {:?}", start.elapsed());

    // sanity check: verify proof
    verifier_data.verify(proof_with_pis.clone())?;

    // return
    Ok((verifier_data, common_circuit_data, proof_with_pis))
}

// alternative calculate_id version, which instead of using Goldilocks Poseidon,
// it uses sha256
pub fn calculate_id_alt(statements: &[bStatement], params: &Params) -> pod2::middleware::Hash {
    assert!(statements.len() <= params.num_public_statements_id);
    assert!(params.max_public_statements <= params.num_public_statements_id);

    let mut none_st: bStatement = pod2::middleware::Statement::None.into();
    pod2::backends::plonky2::mainpod::pad_statement(params, &mut none_st);
    let statements_back_padded = statements
        .iter()
        .chain(std::iter::repeat(&none_st))
        .take(params.num_public_statements_id)
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
    // let v: Vec<F> = b
    //     .chunks(7)
    //     .map(|bytes| {
    //         let u = u64::from_le_bytes(vec![&[0u8], bytes].concat().try_into().unwrap());
    //         F::from_canonical_u64(u)
    //     })
    //     .collect();
    // pod2::middleware::Hash(v.try_into().unwrap())
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

// TODO, NOTE: the calculate_id methods will need to be adapted to the latest pod2 version after
// the PRs are merged:
// - https://github.com/0xPARC/pod2/pull/397
// - https://github.com/0xPARC/pod2/pull/394

// TODO this method should be removed and just exposed in the pod2 library
fn precompute_hash_state<F: RichField, P: PlonkyPermutation<F>>(inputs: &[F]) -> (P, &[F]) {
    let (inputs, inputs_rem) = inputs.split_at((inputs.len() / P::RATE) * P::RATE);
    let mut perm = P::new(core::iter::repeat(F::ZERO));

    // Absorb all inputs up to the biggest multiple of RATE.
    for input_chunk in inputs.chunks(P::RATE) {
        perm.set_from_slice(input_chunk, 0);
        perm.permute();
    }

    (perm, inputs_rem)
}
// TODO this method should be removed and just exposed in the pod2 library
fn hash_from_state_circuit<H: AlgebraicHasher<F>, P: PlonkyPermutation<F>>(
    builder: &mut CircuitBuilder<F, D>,
    perm: P,
    inputs: &[Target],
) -> HashOutTarget {
    let mut state =
        H::AlgebraicPermutation::new(perm.as_ref().iter().map(|v| builder.constant(*v)));

    // Absorb all input chunks.
    for input_chunk in inputs.chunks(H::AlgebraicPermutation::RATE) {
        // Overwrite the first r elements with the inputs. This differs from a standard sponge,
        // where we would xor or add in the inputs. This is a well-known variant, though,
        // sometimes called "overwrite mode".
        state.set_from_slice(input_chunk, 0);
        state = builder.permute::<H>(state);
    }

    let num_outputs = NUM_HASH_OUT_ELTS;
    // Squeeze until we have the desired number of outputs.
    let mut outputs = Vec::with_capacity(num_outputs);
    loop {
        for &s in state.squeeze() {
            outputs.push(s);
            if outputs.len() == num_outputs {
                return HashOutTarget::from_vec(outputs);
            }
        }
        state = builder.permute::<H>(state);
    }
}

// alternative calculate_id_circuit version, which instead of using Goldilocks Poseidon,
// it uses sha256
fn calculate_id_circuit_alt(
    params: &Params,
    builder: &mut CircuitBuilder<F, D>,
    // These statements will be padded to reach `num_statements`
    statements: &[StatementTarget],
) -> HashOutTarget {
    assert!(statements.len() <= params.num_public_statements_id);

    let statements_rev_flattened = statements.iter().rev().flat_map(|s| s.flatten());
    let mut none_st = mainpod::Statement::from(Statement::None);
    pad_statement(params, &mut none_st);
    let front_pad_elts = iter::repeat(&none_st)
        .take(params.num_public_statements_id - statements.len())
        .flat_map(|s| s.to_fields(params))
        .collect_vec();
    let (perm, front_pad_elts_rem) =
        precompute_hash_state::<F, PoseidonPermutation<F>>(&front_pad_elts);

    // WIP: instead of precompute poseidon & using poseidon, use sha256
    // Precompute the Poseidon state for the initial padding chunks
    let inputs = front_pad_elts_rem
        .iter()
        .map(|v| builder.constant(*v))
        .chain(statements_rev_flattened)
        .collect_vec();
    let id =
        hash_from_state_circuit::<PoseidonHash, PoseidonPermutation<F>>(builder, perm, &inputs);

    id
}

pub fn wrap_bn128(
    verifier_only_data: VerifierOnlyCircuitData<C, D>,
    common_circuit_data: CommonCircuitData<F, D>,
    proof_with_public_inputs: ProofWithPublicInputs<F, C, D>,
    pub_statements: &[Statement],
    pod_params: Params,
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

    // register as public inputs the podid's sha256 hash version
    let podid_sha256_target = builder.add_virtual_hash();
    builder.register_public_inputs(&podid_sha256_target.elements);

    let circuit_data = builder.build::<PoseidonBN128GoldilocksConfig>();

    // set targets
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&verifier_circuit_target, &verifier_only_data)?;
    pw.set_proof_with_pis_target(&proof_with_pis_target, &proof_with_public_inputs)?;
    // hash pub_statements using sha256
    let pub_st: Vec<bStatement> = pub_statements
        .iter()
        .map(|st| bStatement::from(st.clone()))
        .collect();
    let podid_sha256 = calculate_id_alt(&pub_st, &pod_params);
    // assign the hash value to the target
    pw.set_hash_target(
        podid_sha256_target,
        HashOut::from_vec(podid_sha256.0.to_vec()),
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
            &[], // TODO WIP
            Params::default(),
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
