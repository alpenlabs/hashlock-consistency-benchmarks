# gnark in-process scaling runs

Key generation and proof generation in one process at 8, 32 and 128 wires, `GOMAXPROCS=12`. `prove-w128-cap10` ran with `GOMEMLIMIT=10GiB` and `GODEBUG=gctrace=1`; its GC trace gives the live heap (peak 7.75 GiB in key generation, 6.6 GiB in proof generation) against a peak RSS of 14.25 GiB.
