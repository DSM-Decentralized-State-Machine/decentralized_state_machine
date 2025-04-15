# Security Policy

## Supported Versions

This alpha release is intended for development and testing purposes. No versions are currently receiving security updates as this is pre-production software.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.0-alpha.1 | ✅ (Development Only) |

## Security Model

The DSM project implements the following security primitives:

1. **Post-Quantum Cryptography**
   - SPHINCS+ for signatures (NIST Level 3)
   - Kyber512 for key encapsulation (NIST Level 3)
   - Blake3 for cryptographic hashing

2. **State Machine Security**
   - Deterministic state transitions
   - Bilateral state isolation
   - Hash chain verification
   - Pre-commitment verification
   - Forward-only state evolution

3. **Threat Model Assumptions**
   - The system assumes honest-but-curious participants
   - Local device storage is assumed to be secure
   - Side-channel attacks are considered out of scope for this alpha release
   - Quantum computing attacks are mitigated through post-quantum cryptographic primitives

## Known Limitations

1. The current implementation has not undergone formal security verification
2. Some error paths may have inconsistent handling
3. Secure key storage depends on platform-specific capabilities
4. Concurrent access patterns may reveal timing side-channels
5. Quantum-resistant cryptography implementations are subject to evolving standards

## Reporting a Vulnerability

For security issues related to the DSM implementation, please:

1. **DO NOT** disclose the vulnerability publicly
2. Email info@decentralizedstatemachine.com with detailed information
3. Allow up to 48 hours for initial response
4. Work with the development team to understand and address the issue
5. Follow coordinated disclosure practices once mitigation is available

## Security Assessment Status

The following components have undergone internal security review:
- Core cryptographic primitives (partial)
- State transition logic (partial)
- Hashchain verification (complete)

External security audit is planned for future beta releases.

## Secure Development Practices

The DSM project follows these security practices:
- Dependency scanning and vulnerability tracking
- Safe Rust programming practices
- Constant-time cryptographic operations where possible
- Comprehensive test suite for security-critical components
- Memory safety through Rust's ownership model
