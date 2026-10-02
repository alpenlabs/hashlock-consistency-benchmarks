# SP1 soldering benchmark

`guest/` holds the four files of [`sp1-soldering-program`](https://github.com/BitVM/garbled-snark-verifier/tree/52b49127dc426f0c88ce7fc418116e67173c2f22/sp1-soldering-program) from `BitVM/garbled-snark-verifier` at commit `52b49127`, unchanged; [source.json](source.json) records their hashes, and `run.py` checks them before building.

For N wires and M retained instances (including the base), the guest computes 2N(M+1) SHA-256 label commitments and 2N(M−1) XOR deltas, and commits them with the nonce as its public output. `host/` generates the labels, checks the guest's output against an independent host computation, and runs SP1's CPU pipeline: core, compress, shrink, BN254 wrap and Groth16 wrap, with each stage timed and verified.

```sh
soldering/host/target/release/soldering-bench --mode execute|core|compressed|groth16 \
  --wires 1019 --instances 7 --out DIR [--artifacts ~/.sp1/circuits/groth16/v5.0.0]
```

SP1 5.2.2 needs the **v5.0.0** Groth16 artifacts (`groth16_pk.bin`, `groth16_circuit.bin`, `groth16_vk.bin`) from [SP1's artifact endpoint](https://sp1-circuits.s3-us-east-2.amazonaws.com/v5.0.0-groth16.tar.gz); the archive used here had SHA-256 `6cbc2c15…5b73104`. The host refuses a directory whose name is not the build's circuit version.
