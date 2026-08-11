use crate::packet::bbp::Bbp;
use crate::packet::cbr::Cbr;
use crate::packet::cfe::Cfe;
#[cfg(feature = "cyc")]
use crate::packet::cyc::Cyc;
use crate::packet::evd::Evd;
use crate::packet::mnt::Mnt;
use crate::packet::mode::{ModeExec, ModeTsx};
use crate::packet::mtc::Mtc;
use crate::packet::ovf::Ovf;
use crate::packet::pip::Pip;
use crate::packet::psb::{Psb, PsbEnd};
use crate::packet::tip::{Fup, Tip, TipPgd, TipPge};
use crate::packet::tma::Tma;
use crate::packet::tnt::{TntIter, TntLong, TntShort};
use crate::packet::trace_stop::TraceStop;
use crate::packet::trig::Trig;
use crate::packet::tsc::Tsc;
use crate::packet::vmcs::Vmcs;

use crate::packet::pad::Pad;
#[cfg(feature = "ptw")]
use crate::packet::ptw::Ptw;
use crate::packet::pwr::{Exstop, Mwait, Pwre, Pwrx};

pub mod bbp;
pub mod cbr;
mod cfe;
#[cfg(feature = "cyc")]
pub mod cyc;
pub mod decoder;
mod evd;
pub mod mnt;
pub mod mode;
mod mtc;
pub mod ovf;
mod pad;
pub mod pip;
pub mod psb;
#[cfg(feature = "ptw")]
mod ptw;
pub mod pwr;
pub mod tip;
mod tma;
pub mod tnt;
pub mod trace_stop;
pub mod trig;
pub mod tsc;
pub mod vmcs;

#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum PtPacket {
    /// Taken/Not-taken (TNT)
    Tnt(TntIter),
    /// Target IP (TIP) Packet
    Tip(Tip),
    /// Packet Generation Enable (TIP.PGE) Packet
    TipPge(TipPge),
    /// Packet Generation Disable (TIP.PGD) Packet
    TipPgd(TipPgd),
    /// Flow Update (FUP) Packet
    Fup(Fup),
    /// Paging Information (PIP) Packet
    Pip(Pip),
    /// Mode.Exec (MODE) Packet
    ModeExec(ModeExec),
    /// Mode.TSX (MODE) Packet
    ModeTsx(ModeTsx),
    /// Trace Stop (TRACESTOP) Packet
    TraceStop(TraceStop),
    /// VMCS Packet
    Vmcs(Vmcs),
    /// Overflow (OVF) Packet
    Ovf(Ovf),
    /// Packet Stream Boundary (PSB) Packet
    Psb(),
    /// PSB End (PSBEND) Packet, terminating a PSB+ block
    PsbEnd(),
}

/// Errors returned when parsing PT packets.
#[derive(Debug, Clone, PartialEq)]
pub enum PtPacketParseError {
    /// Unexpected end of buffer.
    Eof,
    /// Packet bytes do not form a valid PT packet.
    MalformedPacket,
}

impl PtPacket {
    #[inline(always)]
    fn parse(input: &[u8], pos: &mut usize) -> Result<Self, PtPacketParseError> {
        let mut b = input.get(*pos).ok_or(PtPacketParseError::Eof)?;

        // consume padding
        loop {
            if *b != Pad::B0 {
                break;
            }
            *pos += Pad::SIZE;
            b = input.get(*pos).ok_or(PtPacketParseError::Eof)?;
        }

        if (b & 0x01 == 0) && (*b >= 0x04) {
            // All tnt short packets have at least a bit set (that acts as payload
            // terminator) at bit 2 or higher. Therefore, tnt.8 packets raw value is
            // always >= 4. This check eliminates any ambiguity with other packet types.
            *pos += TntShort::SIZE;
            let mut tnt_iter = TntShort { raw: *b }.into_iter();

            while let Some(b) = input.get(*pos) {
                if (b & 0x01 == 0) && (*b >= 0x04) {
                    unsafe { tnt_iter.push(TntShort { raw: *b }) }
                    *pos += TntShort::SIZE;
                    if !tnt_iter.can_push_tnt_short() {
                        break;
                    }
                } else {
                    break;
                }
            }

            Ok(Self::Tnt(tnt_iter))
        } else {
            Self::parse_slow_path(input, pos)
        }
    }

    fn parse_slow_path(input: &[u8], pos: &mut usize) -> Result<Self, PtPacketParseError> {
        Ok(loop {
            let slice = input.get(*pos..).ok_or(PtPacketParseError::Eof)?;
            break match slice {
                [Pad::B0, ..] => {
                    // ignore padding
                    *pos += Pad::SIZE;
                    continue;
                }
                [b0, ..] if (b0 & 0x01 == 0) && (*b0 >= 0x04) => {
                    // All tnt short packets have at least a bit set (that acts as payload
                    // terminator) at bit 2 or higher. Therefore, tnt.8 packets raw value is
                    // always >= 4. This check eliminates any ambiguity with other packet types.
                    *pos += TntShort::SIZE;
                    Self::Tnt(TntShort { raw: *b0 }.into_iter())
                }
                #[cfg(feature = "cyc")]
                [b0, ..] if b0 & 0x03 == 0x03 => {
                    let packet = Cyc::try_from_payload(slice)?;
                    *pos += packet.original_size();
                    continue;
                }
                [b0, rest @ ..] if b0 & 0x1f == 0x01 => {
                    let packet = TipPgd::try_from_payload(b0, rest)?;
                    *pos += packet.original_size();
                    Self::TipPgd(packet)
                }
                [b0, rest @ ..] if b0 & 0x1f == 0x0d => {
                    let packet = Tip::try_from_payload(b0, rest)?;
                    *pos += packet.original_size();
                    Self::Tip(packet)
                }
                [b0, rest @ ..] if b0 & 0x1f == 0x11 => {
                    let packet = TipPge::try_from_payload(b0, rest)?;
                    *pos += packet.original_size();
                    Self::TipPge(packet)
                }
                [b0, rest @ ..] if b0 & 0x1f == 0x1d => {
                    let packet = Fup::try_from_payload(b0, rest)?;
                    *pos += packet.original_size();
                    Self::Fup(packet)
                }
                [mode::B0, b1, ..] if b1 & mode::B1_MASK == ModeExec::B1 => {
                    *pos += mode::SIZE;
                    Self::ModeExec(ModeExec::try_from_payload(*b1)?)
                }
                [mode::B0, b1, ..] if b1 & mode::B1_MASK == ModeTsx::B1 => {
                    *pos += mode::SIZE;
                    Self::ModeTsx(ModeTsx::try_from_payload(*b1)?)
                }
                [0x02, PsbEnd::B1, ..] => {
                    *pos += PsbEnd::SIZE;
                    Self::PsbEnd()
                }
                [0x02, Ovf::B1, ..] => {
                    *pos += Ovf::SIZE;
                    Self::Ovf(Ovf {})
                }
                [0x02, TraceStop::B1, ..] => {
                    *pos += TraceStop::SIZE;
                    Self::TraceStop(TraceStop {})
                }
                [0x02, Psb::B1, ..] => {
                    *pos += Psb::SIZE;
                    Self::Psb()
                }
                [0x02, Cbr::B1, _, _, ..] => {
                    // ignore CBRs
                    *pos += Cbr::SIZE;
                    continue;
                }
                [0x02, Vmcs::B1, b2, b3, b4, b5, b6, ..] => {
                    *pos += Vmcs::SIZE;
                    Self::Vmcs(Vmcs {
                        raw: [*b2, *b3, *b4, *b5, *b6],
                    })
                }
                [0x02, Pip::B1, b2, b3, b4, b5, b6, b7, ..] => {
                    *pos += Pip::SIZE;
                    Self::Pip(Pip {
                        raw: [*b2, *b3, *b4, *b5, *b6, *b7],
                    })
                }

                // TNTLong
                [0x02, TntLong::B1, 0, 0, 0, 0, 0, 0, ..] => {
                    // Tnt must contain a stop bit
                    return Err(PtPacketParseError::MalformedPacket);
                }
                [0x02, TntLong::B1, b2, b3, b4, b5, b6, b7, ..] => {
                    *pos += TntLong::SIZE;
                    Self::Tnt(
                        TntLong {
                            raw: [*b2, *b3, *b4, *b5, *b6, *b7],
                        }
                        .into_iter(),
                    )
                }

                [0x02, 0x73, ..] => {
                    *pos += Tma::SIZE;
                    continue;
                }
                [0x02, Mwait::B1, ..] => {
                    *pos += Mwait::SIZE;
                    continue;
                }
                [0x02, Pwre::B1, ..] => {
                    *pos += Pwre::SIZE;
                    continue;
                }
                [0x02, Pwrx::B1, ..] => {
                    *pos += Pwrx::SIZE;
                    continue;
                }
                [0x02, Cfe::B1, ..] => {
                    *pos += Cfe::SIZE;
                    continue;
                }
                [0x02, Evd::B1, ..] => {
                    *pos += Evd::SIZE;
                    continue;
                }
                #[cfg(feature = "ptw")]
                [0x02, b1, ..] if b1 & 0x1f == 0x12 => {
                    *pos += Ptw::size(*b1)?;
                    continue;
                }
                #[cfg(feature = "pebs")]
                [0x02, 0x33 | 0xb3, ..] => todo!(),
                [0x02, Bbp::B1, ..] => {
                    *pos += Bbp::SIZE;
                    continue;
                }
                [0x02, 0x62 | 0xe2, ..] => {
                    *pos += Exstop::SIZE;
                    continue;
                }
                [0x19, ..] => {
                    *pos += Tsc::SIZE;
                    continue;
                }
                [0x59, ..] => {
                    *pos += Mtc::SIZE;
                    continue;
                }
                [0xd9, _b1, _b2, ..] => {
                    *pos += Trig::SIZE;
                    continue;
                }
                [0x02, 0xc3, 0x88, _, _, _, _, _, _, _, _, ..] => {
                    *pos += Mnt::SIZE;
                    continue;
                }
                [_, ..] => return Err(PtPacketParseError::MalformedPacket),
                [] => return Err(PtPacketParseError::Eof),
            };
        })
    }
}
