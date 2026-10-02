package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

func read(dir, name string, value io.ReaderFrom) error {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = value.ReadFrom(f); err != nil {
		return err
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("trailing bytes in %s", name)
	}
	return nil
}

func run() error {
	dir := flag.String("dir", "", "directory with proof, verification key and public witness")
	flag.Parse()
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}
	proof := groth16.NewProof(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	public, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	for _, item := range []struct {
		name  string
		value io.ReaderFrom
	}{
		{"proof.bin", proof}, {"verification-key.bin", vk}, {"public-witness.bin", public},
	} {
		if err := read(*dir, item.name, item.value); err != nil {
			return err
		}
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		return err
	}
	fmt.Println("Groth16 proof verified against the saved verification key and public witness.")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
