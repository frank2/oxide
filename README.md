# OXiDE

OXiDE is a PoC Rust packer. It doesn't do much other than compress the target binary, but if you read the code,
you'll find that extending it to do more (e.g., obfuscation, anti-reversing) is very possible!

## Building

You need a copy of [NASM](https://www.nasm.us/) in your working directory. This is because OXiDE uses build-scripts
in order to accomplish various assembly tasks. Other than that, simply running `cargo build` on the root directory
should be enough to build the binary.

Originally, this was using Rust nightly builds, but now that the strip feature is included in the main binary,
this only requires the mainline. Minimum version to compile should be Rust 1.56.

## Contact

This is still an ongoing project and I plan on revamping it into more than just a PoC, so if you want to contribute,
feel free to issue a PR here on GitHub or contact me via Twitter at @[verixvogel](https://twitter.com/verixvogel).
