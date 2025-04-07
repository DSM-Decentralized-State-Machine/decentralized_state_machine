# License Compliance Documentation

This document details the third-party dependency licenses used in the DSM (Decentralized State Machine) quantum-resistant cryptographic identification system. All dependencies have been rigorously vetted for compliance with our dual-licensing strategy.

## License Strategy Overview

DSM employs a dual-licensing approach:

1. **Core Components**: Licensed under MIT OR Apache-2.0 (see [../LICENSE.md](../LICENSE.md))
2. **Commercial Extensions**: Available under proprietary licenses (see [LICENSE-Commercial.md](LICENSE-Commercial.md))

For license attributions of individual components, see [LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md).

## Third-Party License Inventory

### ISC Licensed Dependencies

#### webpki (v0.22.4)
- **License**: ISC
- **Copyright**: Copyright (c) The WebPKI authors
- **Usage**: Web PKI certificate processing and path validation

### MIT Licensed Dependencies

Many core dependencies employ the MIT license, a permissive free software license permitting reuse with minimal restrictions.

### Apache-2.0 Licensed Dependencies

Several dependencies utilize the Apache License 2.0, offering explicit patent grants that strengthen our intellectual property position.

### BSD-2-Clause Licensed Dependencies

#### arrayref (v0.3.9)
- **License**: BSD-2-Clause
- **Copyright**: Copyright (c) 2015 David Roundy <roundyd@physics.oregonstate.edu>
- **Usage**: Memory-efficient array references in critical cryptographic operations

#### cloudabi (v0.0.3)
- **License**: BSD-2-Clause
- **Copyright**: Copyright (c) 2016 Nuxi https://nuxi.nl/
- **Usage**: ABI compatibility layer

### CC0-1.0 Licensed Dependencies

#### bip39 (v2.1.0)
- **License**: CC0-1.0
- **Usage**: Mnemonic seed phrase generation and verification

#### bitcoin_hashes (v0.13.0)
- **License**: CC0-1.0
- **Usage**: Cryptographic hashing primitives

#### bitcoin-internals (v0.2.0)
- **License**: CC0-1.0
- **Usage**: Core cryptographic utilities

#### hex-conservative (v0.1.2)
- **License**: CC0-1.0
- **Usage**: Hexadecimal encoding/decoding

### MPL-2.0 Licensed Dependencies

#### option-ext (v0.2.0)
- **License**: MPL-2.0
- **Usage**: Extension traits for Option types

### Unicode-3.0 Licensed Dependencies

#### unicode-ident (v1.0.18)
- **License**: (MIT OR Apache-2.0) AND Unicode-3.0
- **Usage**: Unicode identifier handling

## Cryptographic Primitives

### Quantum-Resistant Algorithms

- **SPHINCS+**: Post-quantum stateless hash-based signature scheme
- **Kyber**: Post-quantum key encapsulation mechanism (KEM)
- **Blake3**: Cryptographically secure hash function

### Compliance Notice

All quantum-resistant primitives have been implemented with strict adherence to their respective specifications and license requirements. No modifications have been made that would impact the security guarantees or license compliance of these critical components.

## Commercial Distribution

When distributing DSM under commercial licenses, this compliance documentation must be included to satisfy attribution requirements for the underlying dependencies.

## Contact Information

For questions related to license compliance or commercial licensing, please contact:
- Email: [info@decentralizedstatemachine.com](mailto:info@decentralizedstatemachine.com)

---

© 2025 DSM Project Authors. All rights reserved.
