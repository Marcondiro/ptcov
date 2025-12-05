#![cfg_attr(not(test), deny(unsafe_code))]
#![allow(clippy::just_underscores_and_digits)]

use crate::packet::PtPacketParseError;

pub use coverage_decoder::{PtCoverageDecoder, PtCoverageDecoderBuilder};
pub use cpu::{PtCpu, PtCpuVendor};
pub use image::PtImage;

mod coverage_decoder;
mod cpu;
mod image;
mod packet;
mod utils;

#[derive(Debug, PartialEq)]
pub enum PtDecoderError {
    Eof,
    IncoherentState,
    IncoherentImage,
    InvalidPacketSequence,
    MalformedInstruction,
    MalformedPacket,
    MalformedPsbPlus,
    MissingImage { address: u64 },
    SyncFailed,
}

impl From<PtPacketParseError> for PtDecoderError {
    fn from(value: PtPacketParseError) -> Self {
        match value {
            PtPacketParseError::MalformedPacket => Self::MalformedPacket,
            PtPacketParseError::Eof => Self::Eof,
        }
    }
}
