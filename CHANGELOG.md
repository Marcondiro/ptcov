# Changelog

## 0.2.0 - 2026-08-25

### Breaking

- Removed the `event`, `mtc`, `pwr` and `tsc` features. The packets they gated (TSC, MTC, TMA,
  MWAIT, PWRE, PWRX, EXSTOP, CFE, EVD) are now always skipped during decoding, so traces
  containing them decode instead of failing with `MalformedPacket`.
- `cyc` is now a default feature, so CYC packets no longer fail to decode by default.
- Coverage maps may differ from the ones produced by 0.1.x, the fixes below change which edges
  are recorded.

### Fixed

- Panic (index out of bounds) when parsing a CYC packet whose counter exceeds 15 bytes or is
  truncated by the end of the trace. Reachable by default now that `cyc` is enabled.
- Panic (`todo!`) on a VMCS or MODE.Exec packet bound to a FUP, and on an OVF packet inside PSB+.
  An OVF is now treated as terminating PSB+ (SDM 34.3.7).
- `filter_vmx_non_root` was reset by every PSB, recording VMX root execution until the next PIP.
- An IP falling exactly on the end of an image resolved to that image instead of the adjacent one.
- Out of bounds write when `coverage()` was called with a smaller map than a previous call.
- The TNT cache consumed one taken/not-taken decision too many on a hit, and replayed entries that
  restored the fall-through address of an indirect branch. Both corrupted coverage in builds
  without `retc`.
