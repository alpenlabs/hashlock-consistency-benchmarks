fn main() {
    for guest in ["a", "b", "c", "d"] {
        for file in ["src/main.rs", "src/types.rs", "Cargo.toml", "Cargo.lock"] {
            println!("cargo:rerun-if-changed=../guests/{guest}/{file}");
        }
        sp1_build::build_program_with_args(
            &format!("../guests/{guest}"),
            sp1_build::BuildArgs {
                locked: true,
                ..Default::default()
            },
        );
    }
}
