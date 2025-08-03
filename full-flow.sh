#!/bin/bash

echo "================================================="
echo "- [generating plonky2 proof]: cargo run --release"
cargo run --release

echo -e "\n================================================================"
echo "- [generating groth16 proof & solidity contract]: go run main.go"
go run main.go

echo -e "\n================================================================"
echo "- proof, verifying key and the Solidity smart contract to verify the proofs can be found at 'outputs' directory"
