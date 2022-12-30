//use super::rescue::{generate_mds_matrix, read_le};
use crate::hasher::rescue_hasher::{Power, RescueEngine, RescueHashParams, RescueParamsInternal};
use core::marker::PhantomData;
use ff::{Field, PrimeField};
use franklin_crypto::group_hash::{BlakeHasher, GroupHasher};
use halo2_proofs::halo2curves::{bn256, pairing::Engine};
use num::integer::ExtendedGcd;
use num::{BigInt, BigUint, Integer, One, ToPrimitive, Zero};

use std::fmt;
use std::ops::MulAssign;
pub trait SBox<E: RescueEngine>: Sized + Clone {
    fn apply(&self, elements: &mut [E::Fr]);
}

#[derive(Clone)]
pub struct QuinticSBox<E: RescueEngine> {
    pub _marker: PhantomData<E>,
}

impl<E: RescueEngine> SBox<E> for QuinticSBox<E> {
    fn apply(&self, elements: &mut [E::Fr]) {
        for element in elements.iter_mut() {
            let mut quad = *element;
            quad.square();
            quad.square();
            element.mul_assign(&quad);
        }
    }
}

#[derive(Clone)]
pub struct PowerSBox<E: RescueEngine> {
    pub power: <E::Fr as PrimeField>::Repr,
    pub inv: u64,
}

impl Power for bn256::Fr {
    fn pow<S: AsRef<[u8]>>(&self, exp: S) -> Self {
        let mut res = Self::one();
        for e in exp.as_ref().iter().rev() {
            for i in (0..8).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res.mul_assign(self);
                }
            }
        }

        res
    }
}

impl<E: RescueEngine> SBox<E> for PowerSBox<E> {
    fn apply(&self, elements: &mut [E::Fr]) {
        for element in elements.iter_mut() {
            *element = element.pow(self.power);
        }
    }
}

impl<E: RescueEngine> fmt::Debug for PowerSBox<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
            .field(&self.power.as_ref())
            .field(&self.inv)
            .finish()
    }
}
impl<E: RescueEngine> fmt::Debug for QuinticSBox<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("").finish()
    }
}
impl<E: RescueEngine> Default for PowerSBox<E> {
    fn default() -> Self {
        Self {
            power: Default::default(),
            inv: Default::default(),
        }
    }
}

impl<E: RescueEngine> Default for QuinticSBox<E> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Bn256RescueParams {
    c: u32,
    r: u32,
    rounds: u32,
    round_constants: Vec<bn256::Fr>,
    mds_matrix: Vec<bn256::Fr>,
    security_level: u32,
    sbox_0: PowerSBox<bn256::Bn256>,
    sbox_1: QuinticSBox<bn256::Bn256>,
    custom_gates_allowed: bool,
}
impl Bn256RescueParams {
    pub const fn empty() -> Self {
        let c = 1u32;
        let r = 2u32;
        let rounds = 22u32;
        let security_level = 126u32;
        let round_constants = vec![];
        let mds_matrix = vec![];
        let alpha_inv_repr = [0u8; 32];
        Self {
            c,
            r,
            rounds,
            round_constants,
            mds_matrix,
            security_level,
            sbox_0: PowerSBox {
                power: alpha_inv_repr,
                inv: 5u64,
            },
            sbox_1: QuinticSBox {
                _marker: std::marker::PhantomData,
            },
            custom_gates_allowed: false,
        }
    }
}

/*
impl Bn256RescueParams {
    pub fn new_checked_2_into_1() -> Self {
        let c = 1u32;
        let r = 2u32;
        let rounds = 22u32;
        let security_level = 126u32;

        Self::new_for_params::<BlakeHasher>(c, r, rounds, security_level)
    }
    pub fn new_for_params<H: GroupHasher>(
        c: u32,
        r: u32,
        rounds: u32,
        _security_level: u32,
    ) -> Self {
        use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
        use franklin_crypto::constants;

        let state_width = c + r;
        let num_round_constants = (1 + rounds * 2) * state_width;
        let num_round_constants = num_round_constants as usize;

        // generate round constants based on some seed and hashing
        let round_constants = {
            let tag = b"Rescue_f";
            let mut round_constants = Vec::with_capacity(num_round_constants);
            let mut nonce = 0u32;
            let mut nonce_bytes = [0u8; 4];

            loop {
                (&mut nonce_bytes[0..4])
                    .write_u32::<BigEndian>(nonce)
                    .unwrap();
                let mut h = H::new(&tag[..]);
                h.update(constants::GH_FIRST_BLOCK);
                h.update(&nonce_bytes[..]);
                let h = h.finalize();
                assert!(h.len() == 32);

                let mut constant_repr = <bn256::Fr as PrimeField>::Repr::default();
                //constant_repr.read_le(&h[..]).unwrap();
                read_le(&mut constant_repr, &h[..]).unwrap();
                /*
                if let Ok(constant) = bn256::Fr::from_repr(constant_repr) {
                    if !constant.is_zero() {
                        round_constants.push(constant);
                    }
                }
                 */
                //Update 22-12-29
                let ct_option = bn256::Fr::from_repr(constant_repr);
                if ct_option.is_some().unwrap_u8() == 1 {
                    round_constants.push(ct_option.unwrap());
                }
                if round_constants.len() == num_round_constants {
                    break;
                }

                nonce += 1;
            }

            round_constants
        };

        let mds_matrix = {
            use rand::chacha::ChaChaRng;
            use rand::SeedableRng;
            // Create an RNG based on the outcome of the random beacon
            let mut rng = {
                // This tag is a first one in a sequence of b"ResMxxxx"
                // that produces MDS matrix without eigenvalues for rate = 2,
                // capacity = 1 variant over Bn254 curve
                let tag = b"ResM0003";
                let mut h = H::new(&tag[..]);
                h.update(constants::GH_FIRST_BLOCK);
                let h = h.finalize();
                assert!(h.len() == 32);
                let mut seed = [0u32; 8];
                for i in 0..8 {
                    seed[i] = (&h[..])
                        .read_u32::<BigEndian>()
                        .expect("digest is large enough for this to work");
                }

                ChaChaRng::from_seed(&seed)
            };

            generate_mds_matrix::<bn256::Bn256, _>(state_width, &mut rng)
        };

        let alpha = BigUint::from(5u64);

        let mut p_minus_one_biguint = BigUint::from(0u64);
        //for limb in bn256::Fr::char().as_ref().iter().rev() {
        for limb in <bn256::Fr as PrimeField>::Repr.as_ref().iter().rev() {
            p_minus_one_biguint <<= 64;
            p_minus_one_biguint += BigUint::from(*limb);
        }

        p_minus_one_biguint -= BigUint::one();

        fn biguint_to_u64_array(mut v: BigUint) -> [u64; 4] {
            let m: BigUint = BigUint::from(1u64) << 64;
            let mut ret = [0; 4];

            for idx in 0..4 {
                ret[idx] = (&v % &m).to_u64().expect("is guaranteed to fit");
                v >>= 64;
            }
            assert!(v.is_zero());
            ret
        }

        let alpha_signed = BigInt::from(alpha);
        let p_minus_one_signed = BigInt::from(p_minus_one_biguint);

        let ExtendedGcd { gcd, x: _, y, .. } = p_minus_one_signed.extended_gcd(&alpha_signed);
        assert!(gcd.is_one());
        let y = if y < BigInt::zero() {
            let mut y = y;
            y += p_minus_one_signed;

            y.to_biguint().expect("must be > 0")
        } else {
            y.to_biguint().expect("must be > 0")
        };

        let inv_alpha = biguint_to_u64_array(y);

        let mut alpha_inv_repr = <bn256::Fr as PrimeField>::Repr::default();
        for (r, limb) in alpha_inv_repr.as_mut().iter_mut().zip(inv_alpha.iter()) {
            *r = *limb;
        }

        Self {
            c: c,
            r: r,
            rounds: rounds,
            round_constants: round_constants,
            mds_matrix: mds_matrix,
            security_level: 126,
            sbox_0: PowerSBox {
                power: alpha_inv_repr,
                inv: 5u64,
            },
            sbox_1: QuinticSBox {
                _marker: std::marker::PhantomData,
            },
            custom_gates_allowed: false,
        }
    }

    pub fn set_allow_custom_gate(&mut self, allowed: bool) {
        self.custom_gates_allowed = allowed;
    }
}
 */
impl RescueParamsInternal<bn256::Bn256> for Bn256RescueParams {
    fn set_round_constants(&mut self, to: Vec<bn256::Fr>) {
        assert_eq!(self.round_constants.len(), to.len());
        self.round_constants = to;
    }
}
impl RescueHashParams<bn256::Bn256> for Bn256RescueParams {
    type SBox0 = PowerSBox<bn256::Bn256>;
    type SBox1 = QuinticSBox<bn256::Bn256>;
    fn capacity(&self) -> u32 {
        self.c
    }
    fn rate(&self) -> u32 {
        self.r
    }
    fn num_rounds(&self) -> u32 {
        self.rounds
    }
    fn round_constants(&self, round: u32) -> &[bn256::Fr] {
        let t = self.c + self.r;
        let start = (t * round) as usize;
        let end = (t * (round + 1)) as usize;

        &self.round_constants[start..end]
    }
    fn mds_matrix_row(&self, row: u32) -> &[bn256::Fr] {
        let t = self.c + self.r;
        let start = (t * row) as usize;
        let end = (t * (row + 1)) as usize;

        &self.mds_matrix[start..end]
    }
    fn security_level(&self) -> u32 {
        self.security_level
    }
    fn output_len(&self) -> u32 {
        self.capacity()
    }
    fn absorbtion_cycle_len(&self) -> u32 {
        self.rate()
    }
    fn compression_rate(&self) -> u32 {
        self.absorbtion_cycle_len() / self.output_len()
    }
    fn sbox_0(&self) -> &Self::SBox0 {
        &self.sbox_0
    }
    fn sbox_1(&self) -> &Self::SBox1 {
        &self.sbox_1
    }
    fn can_use_custom_gates(&self) -> bool {
        self.custom_gates_allowed
    }
}

impl RescueEngine for bn256::Bn256 {
    type Params = Bn256RescueParams;
    type Fr = bn256::Fr;
}
