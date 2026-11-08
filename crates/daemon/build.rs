//! Compiles the eBPF part with clang. Without clang the daemon is built without it and says so
//! at start.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let src = "bpf/wachposten.bpf.c";
    println!("cargo::rerun-if-changed={src}");
    println!("cargo::rustc-check-cfg=cfg(wachposten_bpf)");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("wachposten.bpf.o");
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    // Debian keeps asm/ below the multiarch include folder.
    let multiarch = format!(
        "/usr/include/{}-linux-gnu",
        env::var("CARGO_CFG_TARGET_ARCH").unwrap()
    );
    let status = Command::new(&clang)
        .args([
            "-target", "bpf", "-O2", "-g", "-Wall", "-Werror", "-c", src, "-o",
        ])
        .arg(&out)
        .arg(format!("-I{multiarch}"))
        .status();
    match status {
        Ok(s) if s.success() => println!("cargo::rustc-cfg=wachposten_bpf"),
        Ok(s) => println!("cargo::warning=clang failed ({s}); building without eBPF"),
        Err(e) => println!("cargo::warning=no clang ({e}); building without eBPF"),
    }
}
