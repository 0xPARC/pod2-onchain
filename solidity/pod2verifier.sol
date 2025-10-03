
pragma solidity ^0.8.0;

import '../outputs/Verifier.sol';

contract Pod2Verifier${N} is Verifier {
	  DepositVerifier    dVerifier;

    function verifyPodProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[14] calldata proofInput
        uint256[N] calldata pubStatements
    ) public view {

	// verify snark proof
	this.verifyProof(proof, commitments, commitmentPok, proofInput);

	// public inputs layout:
	// 0..4: poseidon hash (original pod2's pub statements hash), ie. beta
	// 4..8: vdset.root
	// 8..12: sha256 hash, ie. alpha
	// 12..14: gamma
	uint256[2] memory alpha;
	uint256[2] memory beta;
	for (uint i=0; i<2; i++) {
		beta[i] = proofInput[0+i];
		alpha[i] = proofInput[8+i];
		gamma[i] = proofInput[12+i];
	}

	// 1. compute alpha := keccak256(statements))
	// 2.
    }
}
