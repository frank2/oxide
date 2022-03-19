use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/trampoline-32.asm");
    println!("cargo:rerun-if-changed=src/trampoline-32.bin");
    println!("cargo:rerun-if-changed=src/trampoline-64.asm");
    println!("cargo:rerun-if-changed=src/trampoline-64.bin");
    
    let result_32 = Command::new("nasm")
        .current_dir(&Path::new("src/"))
        .args(&["-f", "bin", "-o", "trampoline-32.bin", "./trampoline-32.asm"])
        .status().unwrap().code().unwrap();

    if result_32 != 0 {
        panic!("compilation of 32-bit trampoline failed");
    }

    let result_64 = Command::new("nasm")
        .current_dir(&Path::new("src/"))
        .args(&["-f", "bin", "-o", "trampoline-64.bin", "./trampoline-64.asm"])
        .status().unwrap().code().unwrap();

    if result_64 != 0 {
        panic!("compilation of 64-bit trampoline failed");
    }
}
