#![cfg_attr(not(test), deny(unsafe_code))]
#![allow(clippy::just_underscores_and_digits)]

pub use coverage_decoder::{PtCoverageDecoder, PtCoverageDecoderBuilder, PtDecoderError};
pub use cpu::{PtCpu, PtCpuVendor};
pub use image::PtImage;

mod coverage_decoder;
mod cpu;
mod image;
mod packet;
mod utils;
