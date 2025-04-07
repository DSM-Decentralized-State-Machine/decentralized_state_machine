# DSM Commercial Licensing Strategy

## Dual Licensing Framework

This document outlines the commercial licensing strategy for the Decentralized State Machine (DSM) cryptographic identification system, designed to ensure compliance with all dependency licenses while maintaining a viable commercial model.

### License Structure

The DSM codebase is available under a dual-licensing model:

1. **Open Source License**: Core cryptographic components available under MIT/Apache-2.0 dual license (see [../LICENSE.md](../LICENSE.md))
2. **Commercial License**: Extended functionality, enterprise features, and indemnification under proprietary terms

### Component Segmentation

The project is architecturally separated to enable clear licensing boundaries:

#### Open Source Core (MIT/Apache-2.0)
- Quantum-resistant cryptographic primitives (SPHINCS+, Kyber, Blake3)
- Core state transition mechanisms
- Forward-only hash chain implementation
- Sparse Merkle Tree verification
- Basic commitment schemes

#### Commercial Extensions (Proprietary)
- Enterprise integration layer
- Scaled deployment infrastructure
- Advanced monitoring and analytics
- Hardware security module integration
- Extended support and indemnification
- Performance optimizations for enterprise workloads
- Additional cryptographic key recovery mechanisms

### Dependency License Compliance

The DSM system incorporates several third-party dependencies with various licenses. For detailed information, see [LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md) and [LICENSE-COMPLIANCE.md](LICENSE-COMPLIANCE.md).

| License Type | Components | Compliance Strategy |
|--------------|------------|---------------------|
| MIT/Apache-2.0 | Most core dependencies | Fully compatible with dual-licensing |
| BSD-2-Clause | arrayref, cloudabi | Attribution in LICENSE-THIRD-PARTY.md |
| CC0-1.0 | bip39, bitcoin_hashes | No restrictions on commercial use |
| MPL-2.0 | option-ext | Source availability for MPL components |
| Unicode-3.0 | unicode-ident | Attribution in LICENSE-THIRD-PARTY.md |

Our licensing strategy ensures full compliance with all dependency licenses while preserving commercial viability through feature segmentation and dual-licensing.

### Commercial Terms Overview

Commercial customers receive:

1. Proprietary rights to use, modify, and distribute the commercial extensions
2. Indemnification against intellectual property claims
3. Service level agreements for security updates and bug fixes
4. Rights to deploy in closed enterprise environments
5. Technical support and implementation assistance
6. Custom integration development

### Legal Implementation

This dual licensing approach is implemented through:

1. Proper license headers in all source files indicating their license terms
2. Clear documentation of third-party dependencies and their licenses
3. Separate modules for open-source vs. commercial components
4. Commercial license agreement for enterprise customers

### Ongoing Compliance Strategy

To maintain license compliance over time:

1. The `cargo deny` tool enforces license boundaries during development
2. New dependencies are evaluated for license compatibility before inclusion
3. License compliance is verified before each release
4. Commercial extensions are developed in separate repositories with restricted access

## Contact Information

For commercial licensing inquiries, please contact:
- Email: [info@decentralizedstatemachine.com](mailto:info@decentralizedstatemachine.com)

---

© 2025 DSM Project Authors. All rights reserved.
