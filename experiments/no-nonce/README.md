# Soldering without the nonce round

The upstream soldering guest also commits the base labels XORed with an evaluator-chosen nonce, SHA256(L ⊕ n). Those commitments back HASH160 hashlocks: without the nonce, a garbler who found a HASH160 collision (about 2^80 work) could open a hashlock with a value that is not the committed label. With SHA-256 hashlocks (`OP_SHA256` on the base commitment SHA256(L)) the collision bound is about 2^128 and the nonce round is unnecessary.

`guest/` is the upstream guest with only the nonce removed: no nonce input, no nonce-masked hashes, and no nonce fields in the output. Everything else, including SP1's software public-values hasher, is unchanged. `host/` is the soldering host with the matching input and oracle; it draws the same labels as the upstream benchmark.

Execution at 1,019 wires:

| M | Cycles, upstream | Cycles, no nonce | Change | SHA-256 calls | Public output |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 5 | 40,878,116 | 35,352,929 | −13.5% | 12,228 → 10,190 | 521,840 → 456,600 B |
| 6 | 48,425,269 | 42,845,066 | −11.5% | 14,266 → 12,228 | 619,680 → 554,440 B |
| 7 | 55,972,409 | 50,337,548 | −10.1% | 16,304 → 14,266 | 717,520 → 652,280 B |

Full proof at M = 7 (12 threads, Groth16 proof verified):

| Stage | Upstream | No nonce | Change |
| --- | ---: | ---: | ---: |
| Core | 1,121.7 s | 1,050.1 s | −6.4% |
| Compress | 523.1 s | 486.3 s | −7.0% |
| Shrink + BN254 wrap + Groth16 wrap | 152.2 s | 154.7 s | +1.6% |
| Proof generation | 1,797.1 s | 1,691.2 s | −5.9% |
| Core shards | 60 | 54 | |
| Peak RSS | 25.7 GiB | 24.5 GiB | |

Removing the nonce saves about 106 s (6%) at M = 7, less than the 10% cycle reduction because the Groth16 wrapping cost is fixed. One trial each.
