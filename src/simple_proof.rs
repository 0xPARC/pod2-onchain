use anyhow::Result;
use plonky2::{
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitData},
        proof::ProofWithPublicInputs,
    },
};
use std::time::Instant;

use pod2::backends::plonky2::basetypes::{C, D, F};

use crate::{store_files, wrap_bn128};

// this method exists to be able to generate a quick proof (<1s) instead of the
// full POD proof.
// pub(crate) fn prove_simple_proof() -> Result<(), Box<dyn std::error::Error>> {
pub(crate) fn prove_simple_proof() -> Result<()> {
    // fibonacci proof
    let start = Instant::now();
    let (base_verifier_data, base_common_circuit_data, base_proof_with_pis) = simple_circuit()?;
    println!("[TIME] base proof took: {:?}", start.elapsed());

    // -------------------------------------------
    // generate new plonky2 proof
    let start = Instant::now();
    let (verifier_data, common_circuit_data, proof_with_pis) = wrap_bn128(
        base_verifier_data.verifier_only,
        base_common_circuit_data,
        base_proof_with_pis,
    )?;
    println!("[TIME] encapsulation proof took: {:?}", start.elapsed());

    // sanity check: verify proof
    verifier_data.verify(proof_with_pis.clone())?;

    // ---------------
    // store the files
    store_files(
        verifier_data.verifier_only,
        common_circuit_data,
        proof_with_pis,
    )?;

    Ok(())
}

fn simple_circuit() -> Result<(
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

    // Public inputs are the two initial values (provided below) and the result (which is generated).
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
