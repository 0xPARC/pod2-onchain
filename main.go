package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	fmt.Println("\n=====\npod2-onchain prover\n=====")

	plonky2Circuit := flag.String("plonky2-circuit", "pod", "name of the plonky2 circuit to benchmark")
	profileCircuit := flag.Bool("profile", true, "profile the circuit")
	dummySetup := flag.Bool("dummy", false, "use dummy setup")
	flag.Parse()

	commonCircuitData := types.ReadCommonCircuitData("testdata/" + *plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + *plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + *plonky2Circuit + "/verifier_only_circuit_data.json"))

	_ = os.Mkdir("outputs", os.ModePerm)

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	var p *profile.Profile
	if *profileCircuit {
		p = profile.Start()
	}

	var builder frontend.NewBuilder
	builder = r1cs.NewBuilder

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	if *profileCircuit {
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}

	saveArtifacts := true
	groth16Proof(r1cs, *plonky2Circuit, *dummySetup, saveArtifacts)
}

func groth16Proof(r1cs constraint.ConstraintSystem, circuitName string, dummy bool, saveArtifacts bool) {
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + circuitName + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + circuitName + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}
	// Don't serialize the circuit for now, since it takes up too much memory
	// if saveArtifacts {
	// 	fR1CS, err := os.Create("outputs/circuit")
	//	checkErr(err)
	// 	r1cs.WriteTo(fR1CS)
	// 	fR1CS.Close()
	// }

	fmt.Println("Running circuit setup", time.Now())
	if dummy {
		fmt.Println("Using dummy setup")
		pk, err = groth16.DummySetup(r1cs)
	} else {
		fmt.Println("Using real setup")
		pk, vk, err = groth16.Setup(r1cs)
	}
	checkErr(err)

	if saveArtifacts {
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
		// use sha256 as hashtofield
		err = vk.ExportSolidity(fSolidity, solidity.WithHashToFieldFunction(sha256.New()))
		checkErr(err)
		fSolidity.Close()
	}

	fmt.Println("Generating witness", time.Now())
	start := time.Now()
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	checkErr(err)
	witnessPublic, err := witness.Public()
	checkErr(err)
	fmt.Println("[WITNESS]", witnessPublic)
	publicWitness, err := witness.Public()
	checkErr(err)
	if saveArtifacts {
		fWitness, err := os.Create("outputs/witness")
		checkErr(err)
		witness.WriteTo(fWitness)
		fWitness.Close()
	}
	fmt.Println("[DBG] witness gen", time.Since(start).Milliseconds())

	fmt.Println("Creating proof", time.Now())
	start = time.Now()
	proof, err := groth16.Prove(r1cs, pk, witness)
	checkErr(err)
	fmt.Println("[DBG] proof gen", time.Since(start).Milliseconds())
	if saveArtifacts {
		fProof, err := os.Create("outputs/proof.proof")
		checkErr(err)
		proof.WriteTo(fProof)
		fProof.Close()
	}

	if vk == nil {
		fmt.Println("vk is nil, means you're using dummy setup and we skip verification of proof")
		return
	}

	fmt.Println("Verifying proof", time.Now())
	err = groth16.Verify(proof, vk, publicWitness)
	checkErr(err)

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var (
		a [2]*big.Int
		b [2][2]*big.Int
		c [2]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	println("a[0] is ", a[0].String())
	println("a[1] is ", a[1].String())

	println("b[0][0] is ", b[0][0].String())
	println("b[0][1] is ", b[0][1].String())
	println("b[1][0] is ", b[1][0].String())
	println("b[1][1] is ", b[1][1].String())

	println("c[0] is ", c[0].String())
	println("c[1] is ", c[1].String())

}
