fn main() {
    // No C code compilation needed - we've implemented SPHINCS+ in pure Rust
    // This is an empty build script that does nothing
    println!("cargo:rerun-if-changed=src/crypto/sphincs.rs");
}
