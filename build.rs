use std::path::Path;
use std::process::Command;

fn build_tls_stub() {
    println!("cargo:rerun-if-changed=src/tls-stub-32.asm");
    println!("cargo:rerun-if-changed=src/tls-stub-32.bin");
    println!("cargo:rerun-if-changed=src/tls-stub-64.asm");
    println!("cargo:rerun-if-changed=src/tls-stub-64.bin");
    
    let result_32 = Command::new("nasm")
        .current_dir(&Path::new("src/"))
        .args(&["-f", "bin", "-o", "tls-stub-32.bin", "./tls-stub-32.asm"])
        .status().unwrap().code().unwrap();

    if result_32 != 0 {
        panic!("compilation of 32-bit TLS stub failed");
    }

    let result_64 = Command::new("nasm")
        .current_dir(&Path::new("src/"))
        .args(&["-f", "bin", "-o", "tls-stub-64.bin", "./tls-stub-64.asm"])
        .status().unwrap().code().unwrap();

    if result_64 != 0 {
        panic!("compilation of 64-bit TLS stub failed");
    }
}    

#[cfg(debug_assertions)]
fn build() {
    let result_32 = Command::new("cargo")
        .current_dir(&Path::new("stub/"))
        .args(&["build", "--target", "i686-pc-windows-msvc"])
        .status().unwrap()
        .code().unwrap();

    if result_32 != 0 {
        panic!("32-bit stub compilation failed");
    }
    
    let result_64 = Command::new("cargo")
        .current_dir(&Path::new("stub/"))
        .args(&["build", "--target", "x86_64-pc-windows-msvc"])
        .status().unwrap()
        .code().unwrap();

    if result_64 != 0 {
        panic!("64-bit stub compilation failed");
    }

    build_tls_stub();
}

#[cfg(not(debug_assertions))]
fn build() {
    let result_32 = Command::new("cargo")
        .current_dir(&Path::new("stub/"))
        .args(&["build", "--release", "--target", "i686-pc-windows-msvc"])
        .status().unwrap()
        .code().unwrap();

    if result_32 != 0 {
        panic!("32-bit stub compilation failed");
    }
    
    let result_64 = Command::new("cargo")
        .current_dir(&Path::new("stub/"))
        .args(&["build", "--release", "--target", "x86_64-pc-windows-msvc"])
        .status().unwrap()
        .code().unwrap();

    if result_64 != 0 {
        panic!("64-bit stub compilation failed");
    }

    build_tls_stub();
}
    
fn main() {
    println!("cargo:rerun-if-changed=stub/");
    build();
}
