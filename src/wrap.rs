use anyhow::Result;
use itertools::Itertools;
use plonky2::{
    gates::noop::NoopGate,
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::GenericConfig,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
        proof::{Proof, ProofWithPublicInputs},
    },
};

use pod2::backends::plonky2::basetypes::{C, D, F};

use crate::poseidon_bn128::config::PoseidonBN128GoldilocksConfig;

pub fn wrap_bn128(
    inner_circuit_data: &VerifierCircuitData<F, C, D>,
    proof_with_public_inputs: ProofWithPublicInputs<F, C, D>,
) -> Result<(
    VerifierCircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    CircuitData<F, PoseidonBN128GoldilocksConfig, D>,
    ProofWithPublicInputs<F, PoseidonBN128GoldilocksConfig, D>,
)> {
    // let config = CircuitConfig::standard_ecc_config(); // to match the 136 wires in gnark samples
    let config = CircuitConfig::standard_recursion_config();
    // let mut builder: CircuitBuilder<F, D> = CircuitBuilder::new(config);
    let mut builder: CircuitBuilder<<PoseidonBN128GoldilocksConfig as GenericConfig<D>>::F, D> =
        CircuitBuilder::new(config);

    // create circuit logic
    let proof_with_pis_target = builder.add_virtual_proof_with_pis(&inner_circuit_data.common);
    let verifier_circuit_target = builder.constant_verifier_data(&inner_circuit_data.verifier_only);
    builder.verify_proof::<C>(
        &proof_with_pis_target,
        &verifier_circuit_target,
        &inner_circuit_data.common,
    );

    builder.register_public_inputs(&proof_with_pis_target.public_inputs);

    let circuit_data = builder.build::<PoseidonBN128GoldilocksConfig>();

    // set targets
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&verifier_circuit_target, &inner_circuit_data.verifier_only)?;
    pw.set_proof_with_pis_target(&proof_with_pis_target, &proof_with_public_inputs)?;

    let vd = circuit_data.verifier_data();
    // let cd = vd.common.clone();
    let proof = circuit_data.prove(pw)?;

    Ok((vd, circuit_data, proof))
    // let proof = circuit_data.prove(pw).unwrap();
    // (proof, circuit_data)
}
