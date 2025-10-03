#!/bin/bash

echo "================================================="
echo "- [generating plonky2 proof]: cargo test --release test_pod_flow -- --nocapture"
cargo test --release test_pod_flow -- --nocapture

# if the trusted setup does not exist, create it
if [ ! -d "tmp/groth-artifacts" ]; then
	echo -e "\n================================================================"
	echo "- [generating groth16 trusted setup]: go run main.go -t"
	go run main.go -t
fi

echo -e "\n================================================================"
echo "- [generating groth16 proof & solidity contract]: go run main.go -p -s"
go run main.go -p -s
# go run -tags=debug main.go -m # to test the r1cs (faster) without generating a proof

echo -e "\n================================================================"
echo "- proof, verifying key and the Solidity smart contract to verify the proofs can be found at 'outputs' directory"
