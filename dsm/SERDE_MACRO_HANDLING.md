# Handling Serde Macro Expansion Errors in Rust Analyzer

This document provides guidance for addressing serde macro expansion errors in the DSM codebase.

## The Problem

Rust Analyzer may show errors like:

```
Cannot create expander for /path/to/libserde_derive-*.dylib: mismatched ABI 
expected: `rustc 1.87.0-nightly (00f245915 2025-02-26)`, 
got `rustc 1.87.0-nightly (85abb2763 2025-02-25)`
```

These errors occur when the Rust Analyzer's Rust toolchain version differs from the one used to build the crate's proc-macro crates. While these errors don't affect actual compilation, they can make development more difficult by producing false errors in the IDE.

## Solution Patterns

### Option 1: Conditional Attributes (Preferred)

Use the `rust_analyzer` cfg flag to provide alternative derive paths for the analyzer:

```rust
#[cfg_attr(rust_analyzer, derive(Default))]
#[derive(Clone, Serialize, Deserialize)]
struct MyStruct {
    // fields...
}
```

This tells rust-analyzer to use a simpler derive without trying to expand the serde macros.

### Option 2: Skip Attribute for Analyzer

For complex structures, you can tell the analyzer to skip the serde attributes:

```rust
#[cfg_attr(rust_analyzer, serde(skip))]
#[derive(Serialize, Deserialize)]
struct ComplexStruct {
    // complex fields...
}
```

### Option 3: Configure Rust Analyzer 

Add this to `.cargo/config.toml`:

```toml
[build]
rustflags = ["--cfg", "rust_analyzer"]
```

This defines the `rust_analyzer` compilation flag when the code is being analyzed.

## Implementation Strategy

1. For simple cases, use Option 1 to provide alternative, simpler derives for rust-analyzer
2. For complex structures, use Option 2 to skip serde expansion during analysis
3. For project-wide settings, implement Option 3

Remember that these are only IDE-time fixes - they don't affect the actual compiled code.

## Maintenance Considerations

When upgrading the Rust toolchain, these workarounds might need to be revisited, especially if newer versions of rust-analyzer or serde are adopted.
