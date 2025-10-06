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
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

var r1cs constraint.ConstraintSystem
var pk groth16.ProvingKey
var vk groth16.VerifyingKey

// var proofWithPis variables.ProofWithPublicInputs
var verifierOnlyCircuitData variables.VerifierOnlyCircuitData
var commonCircuitData types.CommonCircuitData

func checkErr(err error, msg ...string) {
	if err != nil {
		fmt.Println(err, msg)
		os.Exit(1)
	}
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
func Groth16Proof(ptr *C.uchar, inLen C.int, outLen *C.int) *C.uchar {
	proofWithPisBytes := C.GoBytes(unsafe.Pointer(ptr), inLen)

	var proofWithPisRaw types.ProofWithPublicInputsRaw
	err := json.Unmarshal(proofWithPisBytes, &proofWithPisRaw)
	checkErr(err)
	proofWithPis := variables.DeserializeProofWithPublicInputs(proofWithPisRaw)
	fmt.Println("(go) proofWithPis parsed")

	fmt.Println("(go) generate Groth16 proof")
	start := time.Now()
	g16Proof, err := pod2onchain.Groth16Proof(r1cs, pk, vk, proofWithPis, verifierOnlyCircuitData, commonCircuitData)
	checkErr(err)
	fmt.Println("(go) [DBG] generating Groth16 proof took:", time.Since(start).Milliseconds())

	var buf bytes.Buffer
	g16Proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// allocate C memory for the output and copy
	if len(proofBytes) == 0 {
		*outLen = 0
		return nil
	}
	outPtr := C.malloc(C.size_t(len(proofBytes)))
	out := unsafe.Slice((*byte)(outPtr), len(proofBytes))
	copy(out, proofBytes)

	*outLen = C.int(len(proofBytes))
	return (*C.uchar)(outPtr)
}

//export GoFree
func GoFree(ptr *C.uchar) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

func main() {}
