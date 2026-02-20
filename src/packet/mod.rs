use crate::packet::cbr::Cbr;
#[cfg(feature = "cyc")]
use crate::packet::cyc::Cyc;
use crate::packet::mnt::Mnt;
use crate::packet::mode::{ModeExec, ModeTsx};
#[cfg(feature = "mtc")]
use crate::packet::mtc::Mtc;
use crate::packet::ovf::Ovf;
use crate::packet::pip::Pip;
use crate::packet::psb::{Psb, PsbEnd};
use crate::packet::tip::{Fup, Tip, TipPgd, TipPge};
#[cfg(all(feature = "tsc", feature = "mtc"))]
use crate::packet::tma::Tma;
use crate::packet::tnt::{TntIter, TntLong, TntShort};
use crate::packet::trace_stop::TraceStop;
use crate::packet::trig::Trig;
#[cfg(feature = "tsc")]
use crate::packet::tsc::Tsc;
use crate::packet::vmcs::Vmcs;

use crate::packet::pad::Pad;

#[cfg(feature = "pebs")]
pub mod bbp;
pub mod cbr;
#[cfg(feature = "event")]
mod cfe;
#[cfg(feature = "cyc")]
pub mod cyc;
pub mod decoder;
#[cfg(feature = "event")]
mod evd;
pub mod mnt;
pub mod mode;
#[cfg(feature = "mtc")]
mod mtc;
pub mod ovf;
mod pad;
pub mod pip;
pub mod psb;
#[cfg(feature = "ptw")]
mod ptw;
#[cfg(feature = "pwr")]
pub mod pwr;
pub mod tip;
#[cfg(all(feature = "tsc", feature = "mtc"))]
mod tma;
pub mod tnt;
pub mod trace_stop;
pub mod trig;
#[cfg(feature = "tsc")]
pub mod tsc;
pub mod vmcs;

pub trait SizedPtPacket {
    /// Size in bytes of the packet as it is in the original trace
    ///
    /// This includes header bytes
    fn original_size(&self) -> usize;
}

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
    ModeExec(ModeExec),
    ModeTsx(ModeTsx),
    TraceStop(TraceStop),
    // /// Timestamp Counter (TSC) Packet
    // #[cfg(feature = "tsc")]
    // Tsc(Tsc),
    // /// Mini Time Counter (MTC) Packet
    // #[cfg(feature = "mtc")]
    // Mtc(Mtc),
    // /// TSC/MTC Alignment (TMA) Packet
    // #[cfg(all(feature = "tsc", feature = "mtc"))]
    // Tma(Tma),
    // /// Cycle Count (CYC) Packet
    // #[cfg(feature = "cyc")]
    // Cyc(Cyc),
    /// VMCS Packet
    Vmcs(Vmcs),
    /// Overflow (OVF) Packet
    Ovf(Ovf),
    /// Packet Stream Boundary (PSB) Packet
    Psb(Psb),
    PsbEnd(PsbEnd),
    // /// Maintenance (MNT) Packet
    // Mnt(Mnt),
    // /// PTWRITE (PTW) Packet
    // #[cfg(feature = "ptw")]
    // Ptw(Ptw),
    // /// Execution Stop (EXSTOP) Packet
    // #[cfg(feature = "pwr")]
    // Exstop(Exstop),
    // #[cfg(feature = "pwr")]
    // Mwait(Mwait),
    // /// Power Entry (PWRE) Packet
    // #[cfg(feature = "pwr")]
    // Pwre(Pwre),
    // /// Power Exit (PWRX) Packet
    // #[cfg(feature = "pwr")]
    // Pwrx(Pwrx),
    // /// Block Begin Packet (BBP)
    // #[cfg(feature = "pebs")]
    // Bbp(Bbp),
    // /// Block Item Packet (BIP)
    // #[cfg(feature = "pebs")]
    // Bip(Bip),
    // /// Block End Packet (BEP)
    // #[cfg(feature = "pebs")]
    // Bep(Bep),
    // /// Control Flow Event (CFE) Packet
    // #[cfg(feature = "event")]
    // Cfe(Cfe),
    // /// Event Data (EVD) Packet
    // #[cfg(feature = "event")]
    // Evd(Evd),
    // // todo: not (yet?) documented in SDM
    // Trig(Trig),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PtPacketParseError {
    Eof,
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
                    Self::PsbEnd(PsbEnd {})
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
                    Self::Psb(Psb {})
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

                #[cfg(all(feature = "tsc", feature = "mtc"))]
                [0x02, 0x73, ..] => {
                    *pos += Tma::SIZE;
                    continue;
                }
                #[cfg(feature = "pwr")]
                [0x02, 0xc2, ..] => todo!(),
                #[cfg(feature = "pwr")]
                [0x02, 0x22, ..] => todo!(),
                #[cfg(feature = "pwr")]
                [0x02, 0xa2, ..] => todo!(),
                #[cfg(feature = "event")]
                [0x02, 0x13, ..] => todo!(),
                #[cfg(feature = "event")]
                [0x02, 0x53, ..] => todo!(),
                #[cfg(feature = "ptw")]
                [0x02, b1, ..] if b1 & 0x1f == 0x12 => todo!(),
                #[cfg(feature = "pebs")]
                [0x02, 0x33 | 0xb3, ..] => todo!(),
                #[cfg(feature = "pebs")]
                [0x02, 0x63, ..] => todo!(),
                #[cfg(feature = "pwr")]
                [0x02, 0x62 | 0xe2, ..] => todo!(),
                #[cfg(feature = "tsc")]
                [0x19, ..] => {
                    *pos += Tsc::SIZE;
                    continue;
                }
                #[cfg(feature = "mtc")]
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
// impl SizedPtPacket for PtPacket {
//     fn original_size(&self) -> usize {
//         match self {
//             PtPacket::TntShort(..) => TntShort::SIZE,
//             PtPacket::TntLong(..) => TntLong::SIZE,
//             PtPacket::Tip(inner) => inner.original_size(),
//             PtPacket::TipPge(inner) => inner.original_size(),
//             PtPacket::TipPgd(inner) => inner.original_size(),
//             PtPacket::Fup(inner) => inner.original_size(),
//             PtPacket::Pip(..) => Pip::SIZE,
//             PtPacket::ModeExec(..) => mode::SIZE,
//             PtPacket::ModeTsx(..) => mode::SIZE,
//             PtPacket::TraceStop(..) => TraceStop::SIZE,
//             // #[cfg(feature = "tsc")]
//             // PtPacket::Tsc(inner) => inner.original_size(),
//             // #[cfg(feature = "mtc")]
//             // PtPacket::Mtc(inner) => inner.original_size(),
//             // #[cfg(all(feature = "tsc", feature = "mtc"))]
//             // PtPacket::Tma(inner) => inner.original_size(),
//             // #[cfg(feature = "cyc")]
//             // PtPacket::Cyc(inner) => inner.original_size(),
//             PtPacket::Vmcs(..) => Vmcs::SIZE,
//             PtPacket::Ovf(..) => Ovf::SIZE,
//             PtPacket::Psb(..) => Psb::SIZE,
//             PtPacket::PsbEnd(..) => PsbEnd::SIZE,
//             // PtPacket::Mnt(..) => Mnt::SIZE,
//             // #[cfg(feature = "ptw")]
//             // PtPacket::Ptw(inner) => inner.original_size(),
//             // #[cfg(feature = "pwr")]
//             // PtPacket::Exstop(inner) => inner.original_size(),
//             // #[cfg(feature = "pwr")]
//             // PtPacket::Mwait(inner) => inner.original_size(),
//             // #[cfg(feature = "pwr")]
//             // PtPacket::Pwre(inner) => inner.original_size(),
//             // #[cfg(feature = "pwr")]
//             // PtPacket::Pwrx(inner) => inner.original_size(),
//             // #[cfg(feature = "pebs")]
//             // PtPacket::Bbp(inner) => inner.original_size(),
//             // #[cfg(feature = "pebs")]
//             // PtPacket::Bip(inner) => inner.original_size(),
//             // #[cfg(feature = "pebs")]
//             // PtPacket::Bep(inner) => inner.original_size(),
//             // #[cfg(feature = "event")]
//             // PtPacket::Cfe(inner) => inner.original_size(),
//             // #[cfg(feature = "event")]
//             // PtPacket::Evd(inner) => inner.original_size(),
//             // PtPacket::Trig(..) => Trig::SIZE,
//         }
//     }
// }
