// Command statement writes the public hashlock statement (digests and Baby Jubjub
// points from gnark-crypto) for a seed, as the oracle for the SP1 guest.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"hashlock-consistency-bench/circuit"
)

func run() error {
	wires := flag.Int("wires", 1, "number of bit wires (two rows per wire)")
	seed := flag.String("seed", "20261001", "deterministic synthetic witness seed")
	out := flag.String("out", "", "new output file (required)")
	flag.Parse()
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	_, rows, err := circuit.Assignment(*wires, *seed)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
