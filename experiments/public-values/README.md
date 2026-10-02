# Public-values hashing in the SP1 soldering guest

SP1 5.2.2 binds a guest's public output through a digest the guest computes with `sp1-zkvm`'s crates.io `sha2`, in software. The soldering guest's 717,520-byte output is therefore hashed without the precompile. Four copies of the upstream guest differ only in how the output is committed:

| Variant | Change from upstream | Public output |
| --- | --- | --- |
| A | none | full |
| B | `[patch.crates-io] sha2` so `sp1-zkvm`'s hasher uses the precompile | full |
| C | commits SHA-256 of the output, via the precompile | 32 B |
| D | commits SHA-256 of the output, in software | 32 B |

`host/` is the soldering host with a variant selector; for C and D it checks the output against SHA-256 of the expected full output. M = 7, 12 threads.

Execution, guest instructions:

| Wires | A | B | C | D | SHA-256 calls (A / B) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 | 3,532,824 | 1,024,649 | 1,029,378 | 3,537,553 | 1,024 / 1,731 |
| 256 | 14,076,368 | 4,076,929 | 4,082,234 | 14,081,673 | 4,096 / 6,915 |
| 1,019 | 55,972,409 | 16,202,999 | 16,210,593 | 55,980,003 | 16,304 / 27,516 |

Core and compressed proofs (both verified):

| Wires | Variant | Shards | Core | Compress | Total |
| ---: | --- | ---: | ---: | ---: | ---: |
| 128 | A | 9 | 160.2 s | 80.3 s | 240.5 s |
| 128 | B | 9 | 85.9 s | 79.4 s | 165.3 s |
| 256 | A | 16 | 301.4 s | 140.1 s | 441.4 s |
| 256 | B | 14 | 152.6 s | 122.3 s | 274.9 s |

B removes 71% of the cycles at 1,019 wires (39.8M, about 55 per output byte) and adds one SHA-256 call per 64-byte block of output. C matches B and D matches A: committing a digest helps only if the digest itself uses the precompile. Proving time falls by about a third, less than the cycle count, because compression barely changes: the extra SHA-256 events need their own shards.
