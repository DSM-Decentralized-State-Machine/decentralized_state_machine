# Decentralized State Machine (DSM) Architecture

This document provides an in-depth overview of the architecture of the Decentralized State Machine (DSM) project. It covers the core components, data flow, and design principles.

## Table of Contents
1. [Overview](#overview)
2. [Core Components](#core-components)
3. [Data Flow](#data-flow)
4. [Cryptographic Foundations](#cryptographic-foundations)
5. [Scalability and Fault Tolerance](#scalability-and-fault-tolerance)
6. [Key Design Principles](#key-design-principles)

## Overview

DSM is a decentralized framework designed to manage state transitions in a secure, deterministic, and tamper-proof manner. Its architecture is tailored for high performance and post-quantum cryptographic security.

Key objectives:
- Ensure deterministic state transitions using cryptographic proofs.
- Provide scalability for decentralized applications.
- Maintain security against adversarial attacks, including those leveraging quantum computing.

## Core Components

### 1. DSM Core Library (`dsm`)
- **Purpose**: Implements the core state machine logic.
- **Structure**:
  - `src/core/state_machine.rs`: Defines the state machine logic.
  - `src/types/operations.rs`: Contains operation types.
  - `src/identity/identity_builder.rs`: Manages identities.

### 2. DSM Ethereum Bridge (`dsm-ethereum-bridge`)
- **Purpose**: Synchronizes states between DSM and Ethereum (or any EVM-compatible blockchain).
- **Key Features**:
  - Bidirectional state anchoring.
  - Cross-chain state verification.
  - Quantum-resistant cryptographic primitives.

### 3. DSM Storage Node (`dsm-storage-node`)
- **Purpose**: Manages decentralized data storage with integrity verification.
- **Features**:
  - Sharded storage for scalability.
  - Data encryption and access control.

### 4. DSM SDK (`dsm-sdk`)
- **Purpose**: Provides client-side tools for interacting with DSM.
- **Structure**:
  - `src/sdk/client.rs`: Handles API interactions.
  - `src/sdk/utils.rs`: Provides helper functions for developers.

## Data Flow

The following diagram outlines the typical data flow in DSM:

![DSM Data Flow](./dsm-data-flow.png)

