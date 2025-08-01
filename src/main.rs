//! example adapted from pod2/examples/main_pod_points.rs

use clap::Parser;
use itertools::Itertools;
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use std::fs;
use std::io::Write;
use std::ops::Deref;
use std::time::Instant;

use pod2::{
    backends::plonky2::{
        basetypes::DEFAULT_VD_SET,
        basetypes::{Proof, ProofWithPublicInputs, C, D, F},
        mainpod::Prover,
    },
    frontend::MainPodBuilder,
    middleware::{
        containers::Set, CommonCircuitData, Params, ToFields, VerifierCircuitData,
        VerifierOnlyCircuitData,
    },
    op,
};

mod simple_proof;

#[derive(Parser)]
struct Cli {
    #[arg(
        short,
        long,
        default_value = "pod",
        help = "set which proof to use ('pod' or 'simple')"
    )]
    prove: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    if args.prove == "pod" {
        prove_pod()?;
    } else if args.prove == "simple" {
        simple_proof::prove_simple_proof()?;
    } else {
        println!("flag 'prove={}' not supported", args.prove);
    }

    Ok(())
}

fn prove_pod() -> Result<(), Box<dyn std::error::Error>> {
    // ---------------------------
    // obtain the pod to be proven
    let start = Instant::now();
    let pod = compute_pod_proof()?;
    println!(
        "[TIME] generate pod & compute pod proof took: {:?}",
        start.elapsed()
    );

    // get POD's circuit related data (verifier_data, circuit_data, proof_with_pis)
    let pod_verifier_data: VerifierOnlyCircuitData = pod.pod.verifier_data();

    let rec_main_pod_verifier_circuit_data =
        &*pod2::backends::plonky2::mainpod::cache_get_rec_main_pod_verifier_circuit_data(
            &pod.pod.params(),
        );
    let pod_common_circuit_data: CommonCircuitData =
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

    // -------------------------------------------
    // generate new plonky2 proof from POD's proof
    let start = Instant::now();
    let (verifier_data, common_circuit_data, proof_with_pis) = encapsulate_proof(
        pod_verifier_data,
        pod_common_circuit_data,
        pod_proof_with_pis,
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

/// encapsulates the POD's plonky2 proof into a new plonky2 proof
fn encapsulate_proof(
    verifier_data: VerifierOnlyCircuitData,
    common_circuit_data: CommonCircuitData,
    proof_with_pis: ProofWithPublicInputs,
) -> Result<
    (
        VerifierCircuitData,
        CommonCircuitData,
        ProofWithPublicInputs,
    ),
    Box<dyn std::error::Error>,
> {
    // build targets
    // let config = common_circuit_data.config.clone();
    // let config = CircuitConfig::standard_recursion_config();
    let config = CircuitConfig::standard_ecc_config(); // to match the 136 wires in gnark samples
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let verifier_data_targ = builder.constant_verifier_data(&verifier_data);
    let proof_targ = builder.add_virtual_proof_with_pis(&common_circuit_data);
    builder.verify_proof::<C>(&proof_targ, &verifier_data_targ, &common_circuit_data);

    // WIP
    builder.add_gate(
        plonky2::gates::constant::ConstantGate::new(config.num_constants),
        vec![],
    );

    let data = builder.build::<C>();

    // set targets
    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&proof_targ, &proof_with_pis)?;

    let vd = data.verifier_data();
    let cd = vd.common.clone();
    let proof = data.prove(pw)?;

    Ok((vd, cd, proof))
}

fn compute_pod_proof() -> Result<pod2::frontend::MainPod, Box<dyn std::error::Error>> {
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

fn store_files(
    verifier_only_data: VerifierOnlyCircuitData,
    common_circuit_data: CommonCircuitData,
    proof_with_pis: ProofWithPublicInputs,
) -> Result<(), Box<dyn std::error::Error>> {
    // create directory
    fs::create_dir_all("testdata/pod")?;

    let json = serde_json::to_string_pretty(&verifier_only_data)?;
    let mut file = fs::File::create(&"testdata/pod/verifier_only_circuit_data.json")?;
    file.write_all(&json.into_bytes())?;

    let json = serde_json::to_string_pretty(&proof_with_pis)?;
    let mut file = fs::File::create(&"testdata/pod/proof_with_public_inputs.json")?;
    file.write_all(&json.into_bytes())?;

    let json = serde_json::to_string_pretty(&common_circuit_data)?;
    let mut file = fs::File::create(&"testdata/pod/common_circuit_data.json")?;
    file.write_all(&json.into_bytes())?;

    Ok(())
}
