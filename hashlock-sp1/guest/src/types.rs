use bincode::{Decode, Encode};

/// EIP-2494 Baby Jubjub, reduced twisted Edwards form, same base point as the gnark circuit.
pub const CURVE_BABYJUBJUB: u8 = 0;
/// secp256k1 through SP1's curve precompiles.
pub const CURVE_SECP256K1: u8 = 1;

/// Private witness: one 32-byte preimage per (wire, value) row, interpreted as an
/// unsigned big-endian integer for the group operation, as in the gnark circuit.
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct HashlockInput {
    pub curve: u8,
    pub preimages: Vec<[u8; 32]>,
}

/// Public output: curve byte, row count (u32 little-endian), then per row the SHA-256
/// digest followed by the point's x and y coordinates as 32-byte big-endian integers.
pub const HEADER_BYTES: usize = 5;
pub const ROW_BYTES: usize = 96;
