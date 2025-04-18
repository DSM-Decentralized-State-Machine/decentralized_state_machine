// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @dev Interface for the DSMVerifier contract or library
 * that verifies DSM proofs on Ethereum (outbound bridging).
 */
interface IDSMVerifier {
    function verify(bytes calldata proof, bytes32 commitmentHash) external view returns (bool);
}

/**
 * @title DSMBridge
 * @notice Minimal example for bridging DSM states into Ethereum
 */
contract DSMBridge {
    // Store whether a given commitment hash has been accepted to prevent replays
    mapping(bytes32 => bool) public acceptedCommitments;

    IDSMVerifier public verifier;

    event CommitmentSubmitted(address indexed submitter, bytes32 indexed commitmentHash);

    constructor(address _verifier) {
        require(_verifier != address(0), "Verifier cannot be zero address");
        verifier = IDSMVerifier(_verifier);
    }

    /**
     * @notice Submit a DSM commitment with a proof
     */
    function submitCommitment(bytes calldata proof, bytes32 commitmentHash) external {
        require(!acceptedCommitments[commitmentHash], "Commitment already submitted");

        bool isValid = verifier.verify(proof, commitmentHash);
        require(isValid, "Invalid DSM proof");

        acceptedCommitments[commitmentHash] = true;
        emit CommitmentSubmitted(msg.sender, commitmentHash);

        // Additional logic: mint tokens, etc.
    }
}
