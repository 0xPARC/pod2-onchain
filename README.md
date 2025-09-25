# pod2-onchain
Prove POD2s onchain in Ethereum.

## Usage
- Run: `bash full-flow.sh`
  - alternatively:
    - generate the pod proof: `cargo test --release test_pod_flow -- --nocapture`
      - to use the non-pod plonky2 circuit (faster to run) run the test `test_simple_proof_flow`
    - generate the groth16 proof: `go run main.go`
      - this will also generate the Solidity smart contract, located at
        `outputs/Verifier.sol`, ready to be deployed


For an example on how to use the rust lib, check the test [`test_pod_flow`](https://github.com/0xPARC/pod2-onchain/blob/main/src/lib.rs)

![](pod2-onchain-diagram.png)


## Benchmarks

In an AMD Ryzen 9 5900XT 16cores linux server:
- plonky2 encapsulation proof: `3.08s`
- groth16 proof: `5.2M` r1cs constraints, `10s`

Wrapper circuit proving times for different pod circuit sizes:

| pod circuit size | pod proving time | wrapper circuit size | wrapper proving time |
|------------------|------------------|----------------------|----------------------|
| 2^16             | 15.8s            | 4784                 | 3.09s                |
| 2^17             | 33.3s            | 5175                 | 3.09s                |
| 2^18             | 73.5s            | 5411                 | 3.09s                |
| 2^19             | 153.8s           | 5646                 | 3.09s                |


## Acknowledgements
This repo relies on the following projects:
- Plonky2: https://github.com/0xPolygonZero/plonky2
- Pod2: https://github.com/0xPARC/pod2
- Gnark: https://github.com/Consensys/gnark
- Gnark plonky2 verifier: https://github.com/succinctlabs/gnark-plonky2-verifier
- For the public inputs onchain verification, we use the approach described at https://eprint.iacr.org/2025/1500 and https://eprint.iacr.org/2024/2099 section 4.2.1.
