package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	pod2onchain "github.com/0xPARC/pod2-onchain"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"golang.org/x/crypto/sha3"
)

var r1cs constraint.ConstraintSystem
var pk groth16.ProvingKey
var vk groth16.VerifyingKey

var verifierOnlyCircuitData variables.VerifierOnlyCircuitData
var commonCircuitData types.CommonCircuitData

func checkErr(err error, msg ...string) {
	if err != nil {
		fmt.Println(err, msg)
		os.Exit(1)
	}
}

//export TrustedSetup
func TrustedSetup(inputsPathChar *C.char, outputsPathChar *C.char) *C.char {
	inputsPath := C.GoString(inputsPathChar)
	outputsPath := C.GoString(outputsPathChar)

	_ = os.Mkdir(outputsPath, os.ModePerm)

	commonCircuitData = types.ReadCommonCircuitData(filepath.Join(inputsPath, "common_circuit_data.json"))
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(filepath.Join(inputsPath, "proof_with_public_inputs.json")))
	verifierOnlyCircuitData = variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(inputsPath, "verifier_only_circuit_data.json")))
	fmt.Println("(go) plonky2's common_circuit_data & proof_with_pis & verifier_only_circuit_data loaded")

	fmt.Println("(go) build r1cs circuit")
	r1cs := pod2onchain.R1csCircuit(proofWithPis, verifierOnlyCircuitData, commonCircuitData, outputsPath)

	fmt.Println("(go) start to generate trusted setup")
	_, _ = pod2onchain.TrustedSetup(r1cs, outputsPath)
	fmt.Println("(go) trusted setup generated")

	return C.CString("trusted setup generated")
}

//export Init
func Init(inputsPathChar *C.char, outputsPathChar *C.char) *C.char {
	inputsPath := C.GoString(inputsPathChar)
	outputsPath := C.GoString(outputsPathChar)

	r1cs = groth16.NewCS(bn254.ID)
	r1csBuf, err := os.ReadFile(filepath.Join(outputsPath, "r1cs"))
	checkErr(err)
	_, err = r1cs.ReadFrom(bytes.NewBuffer(r1csBuf))
	checkErr(err)
	fmt.Println("(go) r1cs loaded")

	fmt.Println("(go) start to load pk & vk")
	start := time.Now()
	pk = groth16.NewProvingKey(bn254.ID)
	vk = groth16.NewVerifyingKey(bn254.ID)
	pkBuf, err := os.ReadFile(filepath.Join(outputsPath, "proving.key"))
	checkErr(err)
	_, err = pk.ReadFrom(bytes.NewBuffer(pkBuf))
	checkErr(err)
	vkBuf, err := os.ReadFile(filepath.Join(outputsPath, "verifying.key"))
	checkErr(err)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkBuf))
	checkErr(err)
	fmt.Println("(go) [DBG] loading pk & vk took:", time.Since(start).Milliseconds())

	commonCircuitData = types.ReadCommonCircuitData(filepath.Join(inputsPath, "common_circuit_data.json"))
	verifierOnlyCircuitData = variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(filepath.Join(inputsPath, "verifier_only_circuit_data.json")))
	fmt.Println("(go) plonky2's common_circuit_data & verifier_only_circuit_data loaded")

	return C.CString("r1cs, pk, vk loaded")
}

//export CheckInit
func CheckInit() *C.char {
	// TODO (not only in this method) before doing any logic, ensure that
	// the global variables are initialized

	internal, secret, public := r1cs.GetNbVariables()
	return C.CString(fmt.Sprintf("internal: %d, secret: %d, public: %d", internal, secret, public))
}

//export Groth16Proof
func Groth16Proof(ptr *C.uchar, inLen C.int, outProofLen *C.int, outWitLen *C.int) (*C.uchar, *C.uchar) {
	proofWithPisBytes := C.GoBytes(unsafe.Pointer(ptr), inLen)

	var proofWithPisRaw types.ProofWithPublicInputsRaw
	err := json.Unmarshal(proofWithPisBytes, &proofWithPisRaw)
	checkErr(err)
	proofWithPis := variables.DeserializeProofWithPublicInputs(proofWithPisRaw)
	fmt.Println("(go) proofWithPis parsed")

	fmt.Println("(go) generate Groth16 proof")
	start := time.Now()
	g16Proof, witnessPublic, err := pod2onchain.Groth16Proof(r1cs, pk, vk, proofWithPis, verifierOnlyCircuitData, commonCircuitData)
	checkErr(err)
	fmt.Println("(go) [DBG] generating Groth16 proof took:", time.Since(start).Milliseconds())

	var buf bytes.Buffer
	g16Proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var bufW bytes.Buffer
	witnessPublic.WriteTo(&bufW)
	witBytes := bufW.Bytes()

	// allocate C memory for the proof output and copy
	if len(proofBytes) == 0 {
		*outProofLen = 0
		return nil, nil
	}
	outPtr := C.malloc(C.size_t(len(proofBytes)))
	out := unsafe.Slice((*byte)(outPtr), len(proofBytes))
	copy(out, proofBytes)
	*outProofLen = C.int(len(proofBytes))

	// allocate C memory for the witness output and copy
	if len(witBytes) == 0 {
		*outWitLen = 0
		return nil, nil
	}
	outWitPtr := C.malloc(C.size_t(len(witBytes)))
	outWit := unsafe.Slice((*byte)(outWitPtr), len(witBytes))
	copy(outWit, witBytes)
	*outWitLen = C.int(len(witBytes))

	return (*C.uchar)(outPtr), (*C.uchar)(outWitPtr)
}

//export Groth16Verify
func Groth16Verify(proofPtr *C.uchar, proofInLen C.int, witPtr *C.uchar, witInLen C.int) *C.char {
	proofBytes := C.GoBytes(unsafe.Pointer(proofPtr), proofInLen)
	witnessPublicBytes := C.GoBytes(unsafe.Pointer(witPtr), witInLen)

	proof := groth16.NewProof(bn254.ID)
	_, err := proof.ReadFrom(bytes.NewBuffer(proofBytes))
	checkErr(err)

	fmt.Println("(go) going to parse pubinp")
	witnessPublic, err := witness.New(ecc.BN254.ScalarField())
	checkErr(err)
	_, err = witnessPublic.ReadFrom(bytes.NewBuffer(witnessPublicBytes))
	checkErr(err)
	fmt.Println("(go) public inputs:", witnessPublic)

	err = groth16.Verify(proof, vk, witnessPublic, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return C.CString(fmt.Sprintf("err: %s", err))
	}
	return C.CString("ok")
}

//export GoFree
func GoFree(ptr *C.uchar) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

func main() {}
