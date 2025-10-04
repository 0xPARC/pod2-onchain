module github.com/0xPARC/pod2-onchain

go 1.24.4

require (
	github.com/consensys/gnark v0.13.0
	github.com/consensys/gnark-crypto v0.18.0
	github.com/succinctlabs/gnark-plonky2-verifier v0.1.0
	golang.org/x/crypto v0.39.0
)

require (
	github.com/bits-and-blooms/bitset v1.22.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.8.0 // indirect
	github.com/google/pprof v0.0.0-20250607225305-033d6d78b36a // indirect
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/exp v0.0.0-20250606033433-dcc06ee1d476 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// replace gnark-plonky2-verifier by the fork that updates it to be compatible
// with latest plonky2 version
replace github.com/succinctlabs/gnark-plonky2-verifier => github.com/arnaucube/gnark-plonky2-verifier v0.0.0-20251003080955-8fe52b5161d8
