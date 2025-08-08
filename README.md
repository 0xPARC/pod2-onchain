# pod2-onchain

## Usage
- Run: `bash full-flow.sh`
  - alternatively:
    - generate the pod proof: `cargo test --release test_pod_flow -- --nocapture`
      - to use the non-pod plonky2 circuit (faster to run) run the test `test_simple_proof_flow`
    - generate the groth16 proof: `go run main.go`


For an example on how to use the rust lib, check the test [`test_pod_flow`](https://github.com/0xPARC/pod2-onchain/blob/main/src/lib.rs)

![](pod2-onchain-diagram.png)


## Acknowledgements
This repo relies on the following projects:
- Plonky2: https://github.com/0xPolygonZero/plonky2
- Pod2: https://github.com/0xPARC/pod2
- Gnark plonky2 verifier: https://github.com/succinctlabs/gnark-plonky2-verifier
