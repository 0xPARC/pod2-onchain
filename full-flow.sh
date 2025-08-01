#!/bin/bash

echo "- [generating plonky2 proof]: cargo run --release"
cargo run --release

echo "- [generating groth16 proof & solidity contract]: go run main.go"
go run main.go

echo "- proof, verifying key and the Solidity smart contract to verify the proofs can be found at 'outputs' directory"
