fn main() {
    println!("cargo:rerun-if-changed=../guest/src/main.rs");
    println!("cargo:rerun-if-changed=../guest/src/types.rs");
    println!("cargo:rerun-if-changed=../guest/Cargo.toml");
    println!("cargo:rerun-if-changed=../guest/Cargo.lock");
    sp1_build::build_program_with_args(
        "../guest",
        sp1_build::BuildArgs {
            locked: true,
            ..Default::default()
        },
    );
}
