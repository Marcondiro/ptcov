# Comparing the coverage produced by `ptcov` and `libxdc`

While comparing the performance of `ptcov` against
[`libxdc`](https://github.com/nyx-fuzz/libxdc/tree/7a7894a812db26d57d6215ae62501c439262a06a)
(the decoding library used in `Nyx`/`kAFL`) some differences  in the coverage produced emerged.
Specifically, the coverage produced by `libxdc` contained, in total, fewer entries.

While this could be simply caused by the wrapping addition used in `libxdc` instead of the saturating addition used in
`ptcov`, the magnitude of the difference suggested that the reason was possibly different.

## Comparison setup

The comparison was made using a sample trace provided in the
[`libxdc_experiments`](https://github.com/nyx-fuzz/libxdc_experiments/tree/73525984c8fca763aa428016ad0351107baa5f0f)
repo, namely `mruby`.

To perform the comparison, `libxdc` was modified:
- Added a function that writes the final coverage bitmap to file after decoding
- Modified the computation of the coverage map index, derived from the edge `from` and `to` instruction pointers.
Instead of hashing, the index is computed as `(from & 0xff) << 8 | (to & 0xff)`. This makes the debugging easier and
makes it possible to compare the coverage with the one captured by `ptcov` modified in the same way.

Also `ptcov` required some changes:
- When tracking edges, `ptcov` uses, as `from` instruction pointer, the address of the instruction following the jump,
while `libxdc` the address of the jump itself. Therefore, to obtain the same behaviur, `ptcov` was modified to save the
jump instruction length to then adjust the `from` ip when computing the coverage map index
- The computation of the coverage map index was modified in to reflect the one mentioned above in `libxdc` modifications

## Results

The coverage obtained with `ptcov` is consistently a superset of what `libxdc` produces.
The main reason is that `libxdc` retrieves coverage only from Intel PT `TNT` packets, ignoring edges that produce `TIP`
packets in Intel PT trace (at least in the `libxdc_experiment` setup with `libxdc` commit `7a7894a`).

Edges originating from instructions like `ret` and `call qword ptr [...]` are not tracked in `libxdc` while they are
tacked by ptcov.

Another minor factor is that `ptcov` uses a saturating add instead of a wrapping add when increasing the coverage map
entry value. This means that if an edge is taken 256 times, the corresponding coverage entry will be `0` in `libxdc` and
`0xff` in `ptcov`.
