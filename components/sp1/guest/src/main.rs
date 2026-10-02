//! Component micro-benchmarks: one operation repeated over N inputs.
//! The Baby Jubjub and secp256k1 modules below are verbatim copies from
//! hashlock-sp1/guest/src/main.rs, so their costs match the full-size runs.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub mod types;
use types::*;

const WINDOWS: usize = 32;
const TABLE: usize = 256;

// BN254 scalar field r, for the bare field-multiplication component.
const R: [u32; 8] = [
    0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
];

fn fold(items: impl Iterator<Item = [u8; 32]>) -> Vec<u8> {
    let mut acc = [0u8; 32];
    for x in items {
        for i in 0..32 {
            acc[i] ^= x[i];
        }
    }
    acc.to_vec()
}

fn fold_points(points: &[([u8; 32], [u8; 32])]) -> Vec<u8> {
    let mut out = fold(points.iter().map(|p| p.0));
    out.extend(fold(points.iter().map(|p| p.1)));
    out
}

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let config = bincode::config::standard().with_fixed_int_encoding();
    let (input, _): (ComponentInput, usize) = bincode::decode_from_slice(&bytes, config).unwrap();
    let items = &input.items;
    println!("cycle-tracker-report-start: op");
    let out = match input.op {
        OP_NOOP => fold(items.iter().copied()),
        OP_SHA256_PRECOMPILE => fold(items.iter().map(|x| Sha256::digest(x).into())),
        OP_SHA256_SOFTWARE => fold(items.iter().map(|x| sha2_sw::Sha256::digest(x).into())),
        OP_XOR128 => {
            // Soldering's delta: label of one instance XOR the base instance's label.
            let mut acc = 0u128;
            for x in items {
                let a = u128::from_le_bytes(x[..16].try_into().unwrap());
                let b = u128::from_le_bytes(x[16..].try_into().unwrap());
                acc ^= a ^ b;
            }
            acc.to_le_bytes().to_vec()
        }
        OP_FR_MUL_PRECOMPILE => {
            let mut acc = [1u32, 0, 0, 0, 0, 0, 0, 0];
            for x in items {
                let mut y_and_modulus = [0u32; 16];
                for i in 0..8 {
                    y_and_modulus[i] = u32::from_le_bytes(x[4 * i..4 * i + 4].try_into().unwrap());
                }
                y_and_modulus[8..].copy_from_slice(&R);
                unsafe {
                    sp1_zkvm::lib::syscall_uint256_mulmod(&mut acc, y_and_modulus.as_ptr() as *const [u32; 8])
                };
            }
            acc.iter().flat_map(|w| w.to_le_bytes()).collect()
        }
        OP_BJJ_FIXED_BASE_MUL => fold_points(&babyjubjub::fixed_base_muls(items)),
        OP_SECP256K1_FIXED_BASE_MUL => fold_points(&secp256k1::fixed_base_muls(items)),
        OP_COMMIT_32B => {
            // Each committed byte goes through sp1-zkvm's software public-values hasher.
            for x in items {
                sp1_zkvm::io::commit_slice(x);
            }
            Vec::new()
        }
        _ => panic!("unknown op"),
    };
    println!("cycle-tracker-report-end: op");
    sp1_zkvm::io::commit_slice(&out);
}

/// Limbs are little-endian u32 words; output coordinates are big-endian bytes.
fn words_to_be(words: &[u32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        out[28 - 4 * i..32 - 4 * i].copy_from_slice(&word.to_be_bytes());
    }
    out
}

mod babyjubjub {
    use super::*;
    use sp1_zkvm::lib::syscall_uint256_mulmod;

    // BN254 scalar field r, the base field of Baby Jubjub.
    const R: [u32; 8] = [
        0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
    ];
    // 2d for the reduced form a = -1, d = 1218...8846 (gnark-crypto bn254/twistededwards).
    const D2: Fr = Fr([
        0xf9afd71b, 0x5d099f85, 0x5db6203e, 0xdf026a6b, 0xb278cb9a, 0xc3909ff8, 0xdd1172a8, 0x0578d36f,
    ]);
    // Prime-subgroup base point, as in gnark-crypto and EIP-2494.
    const BX: Fr = Fr([
        0xfe553f9f, 0xf1f9195a, 0xe6f2a277, 0x377c749a, 0xc199e94c, 0x8a4eb7a4, 0x6ce19d35, 0x1561ff83,
    ]);
    const BY: Fr = Fr([
        0x872d7d8b, 0x4b3c257a, 0xb9e13377, 0xfce0051f, 0xd16bf9ed, 0x25572e1c, 0xf7a0b249, 0x25797203,
    ]);
    const ZERO: Fr = Fr([0; 8]);
    const ONE: Fr = Fr([1, 0, 0, 0, 0, 0, 0, 0]);

    /// Field element, always fully reduced below R.
    #[derive(Clone, Copy)]
    #[repr(C, align(4))]
    struct Fr([u32; 8]);

    /// Multiplication uses SP1's uint256_mulmod precompile; the modulus follows y in memory.
    #[inline(always)]
    fn mul(a: &Fr, b: &Fr) -> Fr {
        let mut x = a.0;
        let mut y_and_modulus = [0u32; 16];
        y_and_modulus[..8].copy_from_slice(&b.0);
        y_and_modulus[8..].copy_from_slice(&R);
        unsafe { syscall_uint256_mulmod(&mut x, y_and_modulus.as_ptr() as *const [u32; 8]) };
        Fr(x)
    }

    #[inline(always)]
    fn add(a: &Fr, b: &Fr) -> Fr {
        // a, b < R < 2^254, so the sum fits in 256 bits and one conditional subtraction reduces it.
        let mut sum = [0u32; 8];
        let mut carry = 0u64;
        for i in 0..8 {
            let v = a.0[i] as u64 + b.0[i] as u64 + carry;
            sum[i] = v as u32;
            carry = v >> 32;
        }
        let mut diff = [0u32; 8];
        let mut borrow = false;
        for i in 0..8 {
            let (v, b1) = sum[i].overflowing_sub(R[i]);
            let (v, b2) = v.overflowing_sub(borrow as u32);
            diff[i] = v;
            borrow = b1 | b2;
        }
        Fr(if borrow { sum } else { diff })
    }

    #[inline(always)]
    fn sub(a: &Fr, b: &Fr) -> Fr {
        let mut diff = [0u32; 8];
        let mut borrow = false;
        for i in 0..8 {
            let (v, b1) = a.0[i].overflowing_sub(b.0[i]);
            let (v, b2) = v.overflowing_sub(borrow as u32);
            diff[i] = v;
            borrow = b1 | b2;
        }
        if borrow {
            let mut carry = 0u64;
            for i in 0..8 {
                let v = diff[i] as u64 + R[i] as u64 + carry;
                diff[i] = v as u32;
                carry = v >> 32;
            }
        }
        Fr(diff)
    }

    /// Fermat inversion a^(R-2); used once per batch.
    fn inv(a: &Fr) -> Fr {
        let mut e = R;
        e[0] -= 2;
        let mut res = ONE;
        for i in (0..8).rev() {
            for bit in (0..32).rev() {
                res = mul(&res, &res);
                if (e[i] >> bit) & 1 == 1 {
                    res = mul(&res, a);
                }
            }
        }
        res
    }

    fn batch_inv(zs: &[Fr]) -> Vec<Fr> {
        let mut prefix = Vec::with_capacity(zs.len());
        let mut acc = ONE;
        for z in zs {
            prefix.push(acc);
            acc = mul(&acc, z);
        }
        let mut inv_acc = inv(&acc);
        let mut out = vec![ZERO; zs.len()];
        for i in (0..zs.len()).rev() {
            out[i] = mul(&inv_acc, &prefix[i]);
            inv_acc = mul(&inv_acc, &zs[i]);
        }
        out
    }

    /// Extended twisted Edwards coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z.
    #[derive(Clone, Copy)]
    struct Ext {
        x: Fr,
        y: Fr,
        z: Fr,
        t: Fr,
    }

    /// Affine table entry in Niels form (y - x, y + x, 2dxy).
    #[derive(Clone, Copy)]
    struct Niels {
        ymx: Fr,
        ypx: Fr,
        t2d: Fr,
    }

    const IDENTITY: Ext = Ext { x: ZERO, y: ONE, z: ONE, t: ZERO };

    // add-2008-hwcd-3 for a = -1. Complete here because d is a non-square and -1 is a square.
    #[inline(always)]
    fn finish(a: Fr, b: Fr, c: Fr, d: Fr) -> Ext {
        let e = sub(&b, &a);
        let f = sub(&d, &c);
        let g = add(&d, &c);
        let h = add(&b, &a);
        Ext { x: mul(&e, &f), y: mul(&g, &h), t: mul(&e, &h), z: mul(&f, &g) }
    }

    fn add_ext(p: &Ext, q: &Ext) -> Ext {
        let a = mul(&sub(&p.y, &p.x), &sub(&q.y, &q.x));
        let b = mul(&add(&p.y, &p.x), &add(&q.y, &q.x));
        let c = mul(&mul(&p.t, &D2), &q.t);
        let zz = mul(&p.z, &q.z);
        finish(a, b, c, add(&zz, &zz))
    }

    #[inline(always)]
    fn add_niels(p: &Ext, q: &Niels) -> Ext {
        let a = mul(&sub(&p.y, &p.x), &q.ymx);
        let b = mul(&add(&p.y, &p.x), &q.ypx);
        let c = mul(&p.t, &q.t2d);
        finish(a, b, c, add(&p.z, &p.z))
    }

    fn table() -> Vec<Niels> {
        let mut points = Vec::with_capacity(WINDOWS * TABLE);
        let mut base = Ext { x: BX, y: BY, z: ONE, t: mul(&BX, &BY) };
        for _ in 0..WINDOWS {
            let mut acc = IDENTITY;
            for _ in 0..TABLE {
                points.push(acc);
                acc = add_ext(&acc, &base);
            }
            base = acc; // 256 * base
        }
        let zinv = batch_inv(&points.iter().map(|p| p.z).collect::<Vec<_>>());
        points
            .iter()
            .zip(zinv.iter())
            .map(|(p, zi)| {
                let x = mul(&p.x, zi);
                let y = mul(&p.y, zi);
                Niels { ymx: sub(&y, &x), ypx: add(&y, &x), t2d: mul(&mul(&x, &y), &D2) }
            })
            .collect()
    }

    pub fn fixed_base_muls(preimages: &[[u8; 32]]) -> Vec<([u8; 32], [u8; 32])> {
        println!("cycle-tracker-report-start: table");
        let table = table();
        println!("cycle-tracker-report-end: table");
        println!("cycle-tracker-report-start: scalar_mul");
        let points: Vec<Ext> = preimages
            .iter()
            .map(|y| {
                // All 256 bits are used, with no y < L condition, as in the gnark circuit.
                let mut acc = IDENTITY;
                for i in 0..WINDOWS {
                    acc = add_niels(&acc, &table[i * TABLE + y[31 - i] as usize]);
                }
                acc
            })
            .collect();
        let zinv = batch_inv(&points.iter().map(|p| p.z).collect::<Vec<_>>());
        let out = points
            .iter()
            .zip(zinv.iter())
            .map(|(p, zi)| (words_to_be(&mul(&p.x, zi).0), words_to_be(&mul(&p.y, zi).0)))
            .collect();
        println!("cycle-tracker-report-end: scalar_mul");
        out
    }
}

mod secp256k1 {
    use super::*;
    use sp1_zkvm::lib::{
        secp256k1::Secp256k1Point,
        utils::{AffinePoint, WeierstrassAffinePoint},
    };

    pub fn fixed_base_muls(preimages: &[[u8; 32]]) -> Vec<([u8; 32], [u8; 32])> {
        println!("cycle-tracker-report-start: table");
        let mut table = Vec::with_capacity(WINDOWS * TABLE);
        let mut base = Secp256k1Point::new(Secp256k1Point::GENERATOR);
        for _ in 0..WINDOWS {
            let mut acc = Secp256k1Point::infinity();
            for _ in 0..TABLE {
                table.push(acc);
                acc.complete_add_assign(&base);
            }
            base = acc; // 256 * base
        }
        println!("cycle-tracker-report-end: table");
        println!("cycle-tracker-report-start: scalar_mul");
        let out = preimages
            .iter()
            .map(|y| {
                // Complete addition handles the identity, doubling and negation cases.
                let mut acc = Secp256k1Point::infinity();
                for i in 0..WINDOWS {
                    acc.complete_add_assign(&table[i * TABLE + y[31 - i] as usize]);
                }
                if acc.is_infinity() {
                    return ([0u8; 32], [0u8; 32]);
                }
                let limbs = acc.limbs_ref();
                (words_to_be(&limbs[..8]), words_to_be(&limbs[8..]))
            })
            .collect();
        println!("cycle-tracker-report-end: scalar_mul");
        out
    }
}
