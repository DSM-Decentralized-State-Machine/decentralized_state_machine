#[cfg(test)]
mod tests {
    use crate::core::state_machine::transition;
    use crate::core::state_machine::transition_fix;
    use crate::types::operations::Operation;
    use crate::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};
    use crate::types::token_types::Balance;

    #[test]
    fn test_verify_transition_integrity_fixed() {
        // Create initial state (simulate benchmark state creation)
        let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
        let operation = Operation::Generic {
            operation_type: "test".to_string(),
            data: vec![],
            message: String::new(),
        };

        let state_params = StateParams::new(
            0,                // state_number
            vec![1, 2, 3, 4], // Entropy
            operation,
            device_info,
        )
        .with_encapsulated_entropy(vec![])
        .with_prev_state_hash(vec![])
        .with_sparse_index(SparseIndex::new(vec![]));

        let mut prev_state = State::new(state_params);

        // Explicitly mark as benchmark state
        prev_state.state_type = String::from("benchmark");

        // Add token balance
        prev_state
            .token_balances
            .insert("token_1".to_string(), Balance::new(1000));

        // Set hash
        let hash = prev_state.compute_hash().expect("Failed to compute hash");
        prev_state.hash = hash;

        // Create next state with Mint operation (typical benchmark operation)
        let mint_op = Operation::Mint {
            amount: Balance::new(100),
            token_id: "token_1".to_string(),
            message: "Minting token".to_string(),
            authorized_by: "benchmark".to_string(),
            proof_of_authorization: vec![1, 2, 3, 4],
        };

        // Apply transition to create a new state
        let _transition =
            transition::create_transition(&prev_state, mint_op.clone(), &vec![1, 2, 3, 4])
                .expect("Failed to create transition");

        let current_state = transition::apply_transition(&prev_state, &mint_op, &vec![1, 2, 3, 4])
            .expect("Failed to apply transition");

        // Verify the transition using our improved function
        let verification_result = transition_fix::verify_transition_integrity_fixed(
            &prev_state,
            &current_state,
            &current_state.operation,
        )
        .expect("Verification function failed");

        assert!(verification_result, "Transition verification failed");

        // For non-benchmark states, create a pair with standard state type
        let mut standard_prev = prev_state.clone();
        standard_prev.state_type = "standard".to_string();

        let transfer_op = Operation::Transfer {
            amount: Balance::new(50),
            to: "recipient".to_string(),
            to_address: "recipient".to_string(),
            recipient: "recipient-id".to_string(),
            token_id: "token_1".to_string(),
            message: String::new(),
            mode: crate::types::operations::TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4],
            verification: crate::types::operations::VerificationType::Standard,
            pre_commit: None,
        };

        // Apply transition
        let _standard_transition =
            transition::create_transition(&standard_prev, transfer_op.clone(), &vec![1, 2, 3, 4])
                .expect("Failed to create transition");

        let standard_current =
            transition::apply_transition(&standard_prev, &transfer_op, &vec![1, 2, 3, 4])
                .expect("Failed to apply transition");

        // Our fix should detect Transfer operations in benchmarks, even if the state is marked standard
        let verification_result_standard = transition_fix::verify_transition_integrity_fixed(
            &standard_prev,
            &standard_current,
            &standard_current.operation,
        )
        .expect("Verification function failed");

        assert!(
            verification_result_standard,
            "Transfer operation verification failed with standard state type"
        );
    }
}
