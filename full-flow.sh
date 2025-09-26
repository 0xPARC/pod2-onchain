#!/bin/bash

echo "================================================="
echo "- [generating plonky2 proof]: cargo test --release test_pod_flow -- --nocapture"
cargo test --release test_pod_flow -- --nocapture

echo -e "\n================================================================"
echo "- [generating groth16 trusted setup]: go run main.go -t"
go run main.go -t

echo -e "\n================================================================"
echo "- [generating groth16 proof & solidity contract]: go run main.go -p -s"
go run main.go -p -s

echo -e "\n================================================================"
echo "- proof, verifying key and the Solidity smart contract to verify the proofs can be found at 'outputs' directory"
