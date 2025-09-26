package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
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
	solidityCheck := flag.Bool("s", false, "enable solidity verification check")

	tsPath := flag.String("a", "outputs", "dir of the artifacts (trusted setup, r1cs, solidity)")
	plonky2Circuit := flag.String("c", "pod", "dir of the plonky2 circuit to use")

	flag.Parse()

	fmt.Println("\n=====\npod2-onchain prover\n=====")
	fmt.Printf("Usage: 'go run main.go -h' for complete list of flags.\n\n")
	fmt.Printf("trusted setup path: %s\n", *tsPath)
	fmt.Println("Trusted Setup generation:", *ts)
	fmt.Println("Groth16 proof generation:", *prove)
	fmt.Println("Solidity verification check:", *solidityCheck)

	commonCircuitData := types.ReadCommonCircuitData("testdata/" + *plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + *plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + *plonky2Circuit + "/verifier_only_circuit_data.json"))

	_ = os.Mkdir("outputs", os.ModePerm)

	if *ts {
		fmt.Println("build r1cs circuit")
		r1cs := r1csCircuit(proofWithPis, verifierOnlyCircuitData, commonCircuitData)

		fmt.Println("gen ts")
		_, _ = trustedSetup(r1cs)
	}
	if *prove {
		fmt.Println("load R1CS")
		r1cs := groth16.NewCS(bn254.ID)
		r1csBuf, err := os.ReadFile("outputs/r1cs")
		checkErr(err)
		_, err = r1cs.ReadFrom(bytes.NewBuffer(r1csBuf))
		checkErr(err)

		fmt.Println("load pk & vk")
		pk := groth16.NewProvingKey(bn254.ID)
		vk := groth16.NewVerifyingKey(bn254.ID)
		pkBuf, err := os.ReadFile("outputs/proving.key")
		checkErr(err)
		_, err = pk.ReadFrom(bytes.NewBuffer(pkBuf))
		checkErr(err)
		vkBuf, err := os.ReadFile("outputs/verifying.key")
		checkErr(err)
		_, err = vk.ReadFrom(bytes.NewBuffer(vkBuf))
		checkErr(err)
		groth16Proof(r1cs, *plonky2Circuit, pk, vk, *solidityCheck)
	}
}

func r1csCircuit(proofWithPis variables.ProofWithPublicInputs, verifierOnlyCircuitData variables.VerifierOnlyCircuitData, commonCircuitData types.CommonCircuitData) constraint.ConstraintSystem {
	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	var p *profile.Profile
	p = profile.Start()

	var builder frontend.NewBuilder
	builder = r1cs.NewBuilder

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	checkErr(err, "error in building circuit")

	p.Stop()
	p.Top()
	println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
	println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
	println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
	println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
	println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())

	// store r1cs into a file
	fR1CS, err := os.Create("outputs/r1cs")
	checkErr(err)
	r1cs.WriteTo(fR1CS)
	fR1CS.Close()

	return r1cs
}

func trustedSetup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey) {
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	fmt.Println("Running circuit setup", time.Now())
	pk, vk, err = groth16.Setup(r1cs)
	checkErr(err)

	fPK, err := os.Create("outputs/proving.key")
	checkErr(err)
	pk.WriteTo(fPK)
	fPK.Close()

	if vk != nil {
		fVK, err := os.Create("outputs/verifying.key")
		checkErr(err)
		vk.WriteTo(fVK)
		fVK.Close()
	}

	// write solidity smart contract into a file
	fSolidity, err := os.Create("outputs/Verifier.sol")
	checkErr(err)
	// use keccak256 (ethereum version) as hashtofield
	err = vk.ExportSolidity(fSolidity, solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256()))
	checkErr(err)
	fSolidity.Close()

	return pk, vk
}

func groth16Proof(r1cs constraint.ConstraintSystem, circuitName string, pk groth16.ProvingKey, vk groth16.VerifyingKey, solidityCheck bool) {
	var err error

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + circuitName + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + circuitName + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	fmt.Println("Generating witness", time.Now())
	start := time.Now()
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	checkErr(err)

	// print the public witness (public inputs)
	witnessPublic, err := witness.Public()
	checkErr(err)
	witnessSchema, err := frontend.NewSchema(ecc.BN254.ScalarField(), &assignment)
	checkErr(err)
	witnessPublicJSON, err := witnessPublic.ToJSON(witnessSchema)
	checkErr(err)
	fmt.Println("[public witness]:", string(witnessPublicJSON))

	fWitness, err := os.Create("outputs/witness")
	checkErr(err)
	witness.WriteTo(fWitness)
	fWitness.Close()
	fmt.Println("[DBG] witness gen", time.Since(start).Milliseconds())

	fmt.Println("Creating proof", time.Now())
	start = time.Now()
	proof, err := groth16.Prove(r1cs, pk, witness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	checkErr(err)
	fmt.Println("[DBG] proof gen", time.Since(start).Milliseconds())
	fProof, err := os.Create("outputs/proof.proof")
	checkErr(err)
	proof.WriteTo(fProof)
	fProof.Close()

	if vk == nil {
		panic("vk is nil")
	}

	fmt.Println("Verifying proof", time.Now())
	err = groth16.Verify(proof, vk, witnessPublic, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	checkErr(err)

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// convert public inputs
	inputBytes, err := witnessPublic.MarshalBinary()
	checkErr(err)

	nbInputs := len(inputBytes) / fr.Bytes
	var input []*big.Int
	for i := 0; i < nbInputs; i++ {
		var e fr.Element
		e.SetBytes(inputBytes[fr.Bytes*i : fr.Bytes*(i+1)])
		input = append(input, new(big.Int))
		e.BigInt(input[i])
	}
	fmt.Println("[solidity] inputs", input)

	// solidity contract inputs
	var proofSol [8]*big.Int
	for i := 0; i < 8; i++ {
		proofSol[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}
	fmt.Println("[solidity] proof", proof)

	// prepare commitments
	commitmentsBI := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(commitmentsBI.Int64())

	commitments := []*big.Int{}
	var commitmentPok [2]*big.Int

	// commitments
	for i := 0; i < 2*commitmentCount; i++ {
		commitments = append(commitments, new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize:fpSize*8+4+(i+1)*fpSize]))
	}
	fmt.Println("[solidity] commitments", commitments)

	// commitmentPok
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])
	fmt.Println("[solidity] commitmentPok", commitmentPok)

	// check that the proof can be verified in the Solidity smart contract
	// through gnark-solidity-checker
	if solidityCheck {
		if _vk, ok := vk.(solidity.VerifyingKey); ok {
			fmt.Println("VERIFY solidity")
			solidityVerification(_vk, proof, witnessPublic, []solidity.ExportOption{solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256())})
		}
	}
}

// function from gnark/test/assert_solidity.go
func solidityVerification(vk solidity.VerifyingKey,
	proof any,
	validPublicWitness witness.Witness,
	opts []solidity.ExportOption,
) {
	// make dir
	_ = os.Mkdir("outputs/solidity", os.ModePerm)

	// export solidity contract
	fSolidity, err := os.Create("outputs/solidity/gnark_verifier.sol")
	checkErr(err)

	err = vk.ExportSolidity(fSolidity, opts...)
	checkErr(err)

	err = fSolidity.Close()
	checkErr(err)

	// generate assets
	// gnark-solidity-checker generate --dir tmpdir --solidity contract_g16.sol
	cmd := exec.Command("gnark-solidity-checker", "generate", "--dir", "outputs/solidity", "--solidity", "gnark_verifier.sol")
	fmt.Println("running ", cmd.String())
	out, err := cmd.CombinedOutput()
	checkErr(err, string(out))

	// len(vk.K) - 1 == len(publicWitness) + len(commitments)
	numOfCommitments := vk.NbPublicWitness() - len(validPublicWitness.Vector().(fr_bn254.Vector))

	checkerOpts := []string{"verify"}
	checkerOpts = append(checkerOpts, "--groth16")

	// proof to hex
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}

	proofStr := hex.EncodeToString(_proof.MarshalSolidity())

	if numOfCommitments > 0 {
		checkerOpts = append(checkerOpts, "--commitment", strconv.Itoa(numOfCommitments))
	}

	// public witness to hex
	bPublicWitness, err := validPublicWitness.MarshalBinary()
	checkErr(err)
	// first 4 bytes -> nbPublic
	// next 4 bytes -> nbSecret
	// next 4 bytes -> nb elements in the vector (== nbPublic + nbSecret)
	bPublicWitness = bPublicWitness[12:]
	publicWitnessStr := hex.EncodeToString(bPublicWitness)

	checkerOpts = append(checkerOpts, "--dir", "outputs/solidity")
	checkerOpts = append(checkerOpts, "--nb-public-inputs", strconv.Itoa(len(validPublicWitness.Vector().(fr_bn254.Vector))))
	checkerOpts = append(checkerOpts, "--proof", proofStr)
	checkerOpts = append(checkerOpts, "--public-inputs", publicWitnessStr)

	// verify proof
	// gnark-solidity-checker verify --dir tmdir --groth16 --nb-public-inputs 1 --proof 1234 --public-inputs dead
	cmd = exec.Command("gnark-solidity-checker", checkerOpts...)
	fmt.Println("running ", cmd.String())
	out, err = cmd.CombinedOutput()
	checkErr(err, string(out))

}
