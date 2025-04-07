use dsm::commitments::smart_commitment::{CommitmentCondition, CommitmentContext, SmartCommitment};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};

#[test]
fn test_precommitment_integrity() {
    // Establish a genesis state
    let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
    let state = State::new_genesis(vec![1, 2, 3], device_info);

    // Create a next operation
    let next_operation = Operation::Generic {
        operation_type: "test".to_string(),
        data: vec![4, 5, 6],
        message: "Generic operation: test".to_string(),
    };

    // Create a precommitment
    let _precommitment = SmartCommitment::new(
        "test_precommitment",
        &state,
        // Replace Always with TimeAfter(0) - a condition that's always true since timestamp 0 is in the past
        CommitmentCondition::TimeAfter(0),
        next_operation,
    )
    .unwrap();
}

#[test]
fn test_smart_commitment_evaluation() {
    // Establish a genesis state
    let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
    let state = State::new_genesis(vec![1, 2, 3], device_info);

    // Create a time-based condition
    let future_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600; // 1 hour in the future

    let condition = CommitmentCondition::TimeAfter(future_time);

    // Create a smart commitment
    let commitment = SmartCommitment::new(
        "test_commitment",
        &state,
        condition,
        Operation::Generic {
            operation_type: "conditional_action".to_string(),
            data: vec![1, 2, 3],
            message: "Conditional action".to_string(),
        },
    )
    .unwrap();

    // Create evaluation context with current time
    let mut context = CommitmentContext::new();

    // Should not be valid now (before the time condition)
    assert!(!commitment.evaluate(&context));

    // Set context to the future time
    context.set_timestamp(future_time + 10);

    // Should be valid after the time condition
    assert!(commitment.evaluate(&context));

    // Verify the commitment against the state
    assert!(commitment.verify_against_state(&state).unwrap());
}

#[test]
fn test_compound_commitment() {
    // Establish a genesis state
    let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
    let state = State::new_genesis(vec![1, 2, 3], device_info);

    // Create conditions
    let time_condition = CommitmentCondition::TimeAfter(100);
    let value_condition = CommitmentCondition::ValueThreshold {
        parameter_name: "amount".to_string(),
        threshold: 500,
        operator: dsm::commitments::smart_commitment::ThresholdOperator::GreaterThanOrEqual,
    };

    // Create compound AND commitment
    let and_commitment = SmartCommitment::new_compound(
        &state,
        vec![1, 2, 3, 4], // recipient
        1000,             // amount
        vec![time_condition.clone(), value_condition.clone()],
        "test_and",
    )
    .unwrap();

    // Create compound OR commitment
    let or_commitment = SmartCommitment::new_compound_or(
        &state,
        vec![1, 2, 3, 4], // recipient
        1000,             // amount
        vec![time_condition, value_condition],
        "test_or",
    )
    .unwrap();

    // Create evaluation context
    let mut context = CommitmentContext::new();
    context.set_timestamp(50); // Before time condition
    context.set_parameter("amount", 600); // Meets value condition

    // AND commitment should be false (time condition not met)
    assert!(!and_commitment.evaluate(&context));

    // OR commitment should be true (value condition met)
    assert!(or_commitment.evaluate(&context));

    // Update time to meet time condition
    context.set_timestamp(150);

    // Both commitments should now evaluate to true
    assert!(and_commitment.evaluate(&context));
    assert!(or_commitment.evaluate(&context));
}
