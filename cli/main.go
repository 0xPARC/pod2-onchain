package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pod2onchain "github.com/0xPARC/pod2-onchain"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"golang.org/x/crypto/sha3"
)

func checkErr(err error, msg ...string) {
	if err != nil {
		fmt.Println(err, msg)
		os.Exit(1)
	}
}

func main() {
	ts := flag.Bool("t", false, "enable the generation of a new Trusted Setup (includes generating the R1CS and the Solidity verifier)")
	prove := flag.Bool("p", false, "enable the generation a Groth16 proof")
	witnessCheck := flag.Bool("w", false, "check the witness generation of the circuit against the R1CS")
	solidityCheck := flag.Bool("s", false, "enable solidity verification check")
	verifyProof := flag.Bool("v", false, "run a proof verification")

	inputsPath := flag.String("i", "tmp/plonky2-proof", "dir of the plonky2 circuit to use")
	outputsPath := flag.String("o", "tmp/groth-artifacts", "dir of the artifacts (trusted setup, r1cs, solidity)")

	flag.Parse()

	if *verifyProof {
		fmt.Println("verifying proof")
		// load proof
		proof := groth16.NewProof(bn254.ID)
		proofBuf, err := os.ReadFile(filepath.Join(*outputsPath, "proof.proof"))
		checkErr(err)
		_, err = proof.ReadFrom(bytes.NewBuffer(proofBuf))
		checkErr(err)

		// load public inputs (public witness)
		witnessPublic, err := witness.New(ecc.BN254.ScalarField())
		checkErr(err)
		witnessPublicBuf, err := os.ReadFile(filepath.Join(*outputsPath, "witness.public"))
		checkErr(err)
		_, err = witnessPublic.ReadFrom(bytes.NewBuffer(witnessPublicBuf))
		checkErr(err)
		fmt.Println("public inputs:", witnessPublic)

		// load vk
		fmt.Println("load vk")
		start := time.Now()
		vk := groth16.NewVerifyingKey(bn254.ID)
		vkBuf, err := os.ReadFile(filepath.Join(*outputsPath, "verifying.key"))
		checkErr(err)
		_, err = vk.ReadFrom(bytes.NewBuffer(vkBuf))
		checkErr(err)
		fmt.Println("[DBG] loading pk & vk took:", time.Since(start).Milliseconds())

		err = groth16.Verify(proof, vk, witnessPublic, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
		checkErr(err)

		fmt.Println("verification success!")
		os.Exit(0)
	}

	fmt.Println("\n=====\npod2-onchain prover\n=====")
	fmt.Printf("Usage: 'go run main.go -h' for complete list of flags.\n\n")
	fmt.Printf("outputs path: %s\n", *outputsPath)
	fmt.Println("Trusted Setup generation:", *ts)
	fmt.Println("Groth16 proof generation:", *prove)
	fmt.Println("Groth16 circuit r1cs check:", *witnessCheck)
	fmt.Println("Solidity verification check:", *solidityCheck)

	commonCircuitData := types.ReadCommonCircuitData(filepath.Join(*inputsPath, "common_circuit_data.json"))

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(filepath.Join(*inputsPath, "proof_with_public_inputs.json")))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(*inputsPath, "verifier_only_circuit_data.json")))

	_ = os.Mkdir(*outputsPath, os.ModePerm)

	if *ts {
		fmt.Println("build r1cs circuit")
		r1cs := pod2onchain.R1csCircuit(proofWithPis, verifierOnlyCircuitData, commonCircuitData, *outputsPath)

		fmt.Println("gen ts")
		_, _ = pod2onchain.TrustedSetup(r1cs, *outputsPath)
	}
	if *prove {
		fmt.Println("load R1CS")
		r1cs := groth16.NewCS(bn254.ID)
		r1csBuf, err := os.ReadFile(filepath.Join(*outputsPath, "r1cs"))
		checkErr(err)
		_, err = r1cs.ReadFrom(bytes.NewBuffer(r1csBuf))
		checkErr(err)

		fmt.Println("load pk & vk")
		start := time.Now()
		pk := groth16.NewProvingKey(bn254.ID)
		vk := groth16.NewVerifyingKey(bn254.ID)
		pkBuf, err := os.ReadFile(filepath.Join(*outputsPath, "proving.key"))
		checkErr(err)
		_, err = pk.ReadFrom(bytes.NewBuffer(pkBuf))
		checkErr(err)
		vkBuf, err := os.ReadFile(filepath.Join(*outputsPath, "verifying.key"))
		checkErr(err)
		_, err = vk.ReadFrom(bytes.NewBuffer(vkBuf))
		checkErr(err)
		fmt.Println("[DBG] loading pk & vk took:", time.Since(start).Milliseconds())

		fmt.Println("generate Groth16 proof")
		start = time.Now()
		pod2onchain.Groth16Proof(r1cs, pk, vk, proofWithPis, verifierOnlyCircuitData, commonCircuitData, *outputsPath, *solidityCheck)
		fmt.Println("[DBG] generating Groth16 proof took:", time.Since(start).Milliseconds())
	}
	if *witnessCheck {
		fmt.Println("check witness generation and circuit constraints")
		fmt.Println("load R1CS")
		r1cs := groth16.NewCS(bn254.ID)
		r1csBuf, err := os.ReadFile(filepath.Join(*outputsPath, "r1cs"))
		checkErr(err)
		_, err = r1cs.ReadFrom(bytes.NewBuffer(r1csBuf))
		checkErr(err)

		start := time.Now()
		pod2onchain.CheckR1CS(r1cs, proofWithPis, verifierOnlyCircuitData, commonCircuitData)
		fmt.Println("[DBG] testing circuit took:", time.Since(start).Milliseconds())
	}
}
