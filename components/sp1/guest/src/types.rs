use bincode::{Decode, Encode};

pub const OP_NOOP: u8 = 0;
pub const OP_SHA256_PRECOMPILE: u8 = 1;
pub const OP_SHA256_SOFTWARE: u8 = 2;
pub const OP_XOR128: u8 = 3;
pub const OP_FR_MUL_PRECOMPILE: u8 = 4;
pub const OP_BJJ_FIXED_BASE_MUL: u8 = 5;
pub const OP_SECP256K1_FIXED_BASE_MUL: u8 = 6;
pub const OP_COMMIT_32B: u8 = 7;

/// One 32-byte input per repetition.
#[derive(Encode, Decode, Clone, Debug)]
pub struct ComponentInput {
    pub op: u8,
    pub items: Vec<[u8; 32]>,
}
