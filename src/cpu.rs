#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PtCpu {
    vendor: PtCpuVendor,
    family: u16,
    model: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum PtCpuVendor {
    Intel,
}

#[derive(Debug)]
pub(crate) struct CpuErrata {
    /** BDM70: Intel(R) Processor Trace PSB+ Packets May Contain
     *         Unexpected Packets.
     *
     * Same as: SKD024, SKL021, KBL021.
     *
     * Some Intel Processor Trace packets should be issued only between
     * TIP.PGE and TIP.PGD packets.  Due to this erratum, when a TIP.PGE
     * packet is generated it may be preceded by a PSB+ that incorrectly
     * includes FUP and MODE.Exec packets.
     */
    pub bdm70: bool,

    /** BDM64: An Incorrect LBR or Intel(R) Processor Trace Packet May Be
     *         Recorded Following a Transactional Abort.
     *
     * Use of Intel(R) Transactional Synchronization Extensions (Intel(R)
     * TSX) may result in a transactional abort.  If an abort occurs
     * immediately following a branch instruction, an incorrect branch
     * target may be logged in an LBR (Last Branch Record) or in an Intel(R)
     * Processor Trace (Intel(R) PT) packet before the LBR or Intel PT
     * packet produced by the abort.
     */
    pub bdm64: bool,

    /** SKD007: Intel(R) PT Buffer Overflow May Result in Incorrect Packets.
     *
     * Same as: SKL049, KBL041.
     *
     * Under complex micro-architectural conditions, an Intel PT (Processor
     * Trace) OVF (Overflow) packet may be issued after the first byte of a
     * multi-byte CYC (Cycle Count) packet, instead of any remaining bytes
     * of the CYC.
     */
    pub skd007: bool,

    /** SKD022: VM Entry That Clears TraceEn May Generate a FUP.
     *
     * Same as: SKL024, KBL023.
     *
     * If VM entry clears Intel(R) PT (Intel Processor Trace)
     * IA32_RTIT_CTL.TraceEn (MSR 570H, bit 0) while PacketEn is 1 then a
     * FUP (Flow Update Packet) will precede the TIP.PGD (Target IP Packet,
     * Packet Generation Disable).  VM entry can clear TraceEn if the
     * VM-entry MSR-load area includes an entry for the IA32_RTIT_CTL MSR.
     */
    pub skd022: bool,

    /** SKD010: Intel(R) PT FUP May be Dropped After OVF.
     *
     * Same as: SKD014, SKL033, KBL030.
     *
     * Some Intel PT (Intel Processor Trace) OVF (Overflow) packets may not
     * be followed by a FUP (Flow Update Packet) or TIP.PGE (Target IP
     * Packet, Packet Generation Enable).
     */
    pub skd010: bool,

    /** SKL014: Intel(R) PT TIP.PGD May Not Have Target IP Payload.
     *
     * Same as: KBL014.
     *
     * When Intel PT (Intel Processor Trace) is enabled and a direct
     * unconditional branch clears IA32_RTIT_STATUS.FilterEn (MSR 571H, bit
     * 0), due to this erratum, the resulting TIP.PGD (Target IP Packet,
     * Packet Generation Disable) may not have an IP payload with the target
     * IP.
     */
    pub skl014: bool,

    /** APL12: Intel(R) PT OVF May Be Followed By An Unexpected FUP Packet.
     *
     * Certain Intel PT (Processor Trace) packets including FUPs (Flow
     * Update Packets), should be issued only between TIP.PGE (Target IP
     * Packet - Packet Generation Enable) and TIP.PGD (Target IP Packet -
     * Packet Generation Disable) packets.  When outside a TIP.PGE/TIP.PGD
     * pair, as a result of IA32_RTIT_STATUS.FilterEn[0] (MSR 571H) being
     * cleared, an OVF (Overflow) packet may be unexpectedly followed by a
     * FUP.
     */
    pub apl12: bool,

    /** APL11: Intel(R) PT OVF Packet May Be Followed by TIP.PGD Packet
     *
     * If Intel PT (Processor Trace) encounters an internal buffer overflow
     * and generates an OVF (Overflow) packet just as IA32_RTIT_CTL (MSR
     * 570H) bit 0 (TraceEn) is cleared, or during a far transfer that
     * causes IA32_RTIT_STATUS.ContextEn[1] (MSR 571H) to be cleared, the
     * OVF may be followed by a TIP.PGD (Target Instruction Pointer - Packet
     * Generation Disable) packet.
     */
    pub apl11: bool,

    /** SKL168: Intel(R) PT CYC Packets Can be Dropped When Immediately
     *          Preceding PSB
     *
     * Due to a rare microarchitectural condition, generation of an Intel
     * PT (Processor Trace) PSB (Packet Stream Boundary) packet can cause a
     * single CYC (Cycle Count) packet, possibly along with an associated
     * MTC (Mini Time Counter) packet, to be dropped.
     */
    pub skl168: bool,

    /** SKZ84: Use of VMX TSC Scaling or TSC Offsetting Will Result in
     *         Corrupted Intel PT Packets
     *
     * When Intel(R) PT (Processor Trace) is enabled within a VMX (Virtual
     * Machine Extensions) guest, and TSC (Time Stamp Counter) offsetting
     * or TSC scaling is enabled for that guest, by setting primary
     * processor-based execution control bit 3 or secondary processor-based
     * execution control bit 25, respectively, in the VMCS (Virtual Machine
     * Control Structure) for that guest, any TMA (TSC(MTC Alignment)
     * packet generated will have corrupted values in the CTC (Core Timer
     * Copy) and FastCounter fields.  Additionally, the corrupted TMA
     * packet will be followed by a bogus data byte.
     */
    pub skz84: bool,
}

impl PtCpu {
    pub const fn new(vendor: PtCpuVendor, family: u16, model: u8, _stepping: u8) -> Self {
        Self {
            vendor,
            family,
            model,
        }
    }

    pub(crate) const fn errata(&self) -> CpuErrata {
        let mut errata = CpuErrata {
            bdm70: false,
            bdm64: false,
            skd007: false,
            skd022: false,
            skd010: false,
            skl014: false,
            apl12: false,
            apl11: false,
            skl168: false,
            skz84: false,
        };

        if matches!(self.vendor, PtCpuVendor::Intel) {
            match self.family {
                0x6 => match self.model {
                    0x3d | 0x47 | 0x4f | 0x56 => {
                        errata.bdm70 = true;
                        errata.bdm64 = true;
                    }
                    0x4e | 0x5e | 0x8e | 0x9e | 0xa5 | 0xa6 => {
                        errata.bdm70 = true;
                        errata.skd007 = true;
                        errata.skd022 = true;
                        errata.skd010 = true;
                        errata.skl014 = true;
                        errata.skl168 = true;
                    }

                    0x55 | 0x6a | 0x6c => {
                        errata.bdm70 = true;
                        errata.skl014 = true;
                        errata.skd022 = true;
                        errata.skz84 = true;
                    }

                    0x8f | 0xcf | 0xad | 0xae => {
                        errata.bdm70 = true;
                        errata.skd022 = true;
                        errata.skz84 = true;
                    }

                    0x66 | 0x7d | 0x7e | 0x8c | 0x8d | 0xa7 | 0xa8 => {
                        errata.bdm70 = true;
                        errata.skl014 = true;
                        errata.skd022 = true;
                    }

                    0x97 | 0x9a | 0xba | 0xb7 | 0xbf | 0xc5 | 0xc6 | 0xb5 | 0xaa | 0xac | 0xbd
                    | 0xcc => {
                        errata.bdm70 = true;
                        errata.skd022 = true;
                        errata.apl11 = true;
                    }

                    0x5c | 0x5f => {
                        errata.apl12 = true;
                        errata.apl11 = true;
                    }

                    0x7a | 0x86 | 0x96 | 0x9c | 0xb6 | 0xaf | 0xdd => {
                        errata.apl11 = true;
                    }
                    _ => {}
                },
                0x13 if self.model == 0x01 => {
                    errata.bdm70 = true;
                    errata.skd022 = true;
                    errata.skz84 = true;
                }
                _ => {}
            }
        }
        errata
    }
}
