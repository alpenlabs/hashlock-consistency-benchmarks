#!/bin/sh
# Phase 2, run detached so that no job time limit applies: gnark split smoke, full Baby Jubjub SP1, gnark bounded runs.
cd "$(dirname "$0")/.."
OUT=results/full-20261002
caffeinate -i python3 scripts/full_runs.py --out $OUT --memory-limit-gib 52 --gomemlimit 44GiB \
  --cases hashlock-gnark-w1-keygen hashlock-gnark-w1-prove
caffeinate -i python3 scripts/full_runs.py --out $OUT --memory-limit-gib 52 \
  --cases hashlock-sp1-babyjubjub
caffeinate -i python3 scripts/full_runs.py --out $OUT --memory-limit-gib 52 --gomemlimit 44GiB \
  --cases hashlock-gnark-w1019-compile hashlock-gnark-w256-keygen hashlock-gnark-w256-prove \
          hashlock-gnark-w512-keygen hashlock-gnark-w512-prove
echo "phase2 finished"
