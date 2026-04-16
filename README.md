# ptcov

[![GHA Status]][GitHub Actions] [![Latest Version]][crates.io] [![Documentation]][docs.rs] ![License]

ptcov is a decoder library to compute AFL-style code coverage from Intel® Processor Trace (PT) traces.

This crate is based on Intel's SDM and takes inspiration from Intel's
[libipt](https://github.com/intel/libipt) and from [libxdc](https://github.com/nyx-fuzz/libxdc).

Since most of the optional PT packets are of limited use in fuzzing context, like power related info, they are not
supported.
CPUs erratas are not (yet) fully supported.

[GitHub Actions]: https://github.com/Marcondiro/ptcov/actions
[GHA Status]: https://github.com/Marcondiro/ptcov/workflows/Rust/badge.svg
[crates.io]: https://crates.io/crates/ptcov
[Latest Version]: https://img.shields.io/crates/v/ptcov.svg
[Documentation]: https://docs.rs/ptcov/badge.svg
[docs.rs]: https://docs.rs/ptcov
[License]: https://img.shields.io/crates/l/ptcov.svg
