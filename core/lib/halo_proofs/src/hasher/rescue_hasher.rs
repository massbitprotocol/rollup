/// Default hasher for the zkSync state hash calculation.
use ff::{Field, PrimeField};
//use franklin_crypto::rescue::{bn256::Bn256RescueParams, rescue_hash};
use crate::hasher::bn256::Bn256RescueParams;
use halo2_proofs::halo2curves::{bn256, pairing::Engine};
use std::fmt;
use std::ops::{Add, AddAssign, MulAssign};
use zksync_crypto::merkle_tree::hasher::Hasher;
//use crate::rescue::CsSBox;
//use super::csbox::CsSBox;
use crate::hasher::bn256::SBox;
use crate::params::BN256_DEFAULT_PARAMS;
pub trait RescueEngine: Engine {
    type Params: RescueHashParams<Self> + Default;
    type Fr: ff::PrimeField + ff::Field + Power;
}
pub trait Power {
    fn pow<S: AsRef<[u8]>>(&self, exp: S) -> Self;
}
pub trait RescueHashParams<E: RescueEngine>: RescueParamsInternal<E> {
    //type SBox0: CsSBox<E>;
    //type SBox1: CsSBox<E>;
    type SBox0: SBox<E>;
    type SBox1: SBox<E>;
    fn capacity(&self) -> u32;
    fn rate(&self) -> u32;
    fn state_width(&self) -> u32 {
        self.capacity() + self.rate()
    }
    fn num_rounds(&self) -> u32;
    fn round_constants(&self, round: u32) -> &[E::Fr];
    fn mds_matrix_row(&self, row: u32) -> &[E::Fr];
    fn security_level(&self) -> u32;
    fn output_len(&self) -> u32 {
        self.capacity()
    }
    fn absorbtion_cycle_len(&self) -> u32 {
        self.rate()
    }
    fn compression_rate(&self) -> u32 {
        self.absorbtion_cycle_len() / self.output_len()
    }

    fn sbox_0(&self) -> &Self::SBox0;
    fn sbox_1(&self) -> &Self::SBox1;
    fn can_use_custom_gates(&self) -> bool {
        false
    }
}

pub trait RescueParamsInternal<E: RescueEngine>:
    Send + Sync + Sized + Clone + std::fmt::Debug
{
    fn set_round_constants(&mut self, to: Vec<E::Fr>);
}

pub struct RescueHasher<E: RescueEngine> {
    params: &'static E::Params,
}
impl<E: RescueEngine> fmt::Debug for RescueHasher<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RescueHasher").finish()
    }
}

// We have to implement `Clone` manually, since deriving it will depend on
// the `Clone` implementation of `E::Params` (and will `.clone()` will not work
// if `E::Params` are not `Clone`), which is redundant: we only hold a reference
// and can just copy it.
impl<E: RescueEngine> Clone for RescueHasher<E> {
    fn clone(&self) -> Self {
        Self {
            params: self.params,
        }
    }
}
pub type Bn256RescueHasher = RescueHasher<bn256::Bn256>;

impl Default for RescueHasher<bn256::Bn256> {
    fn default() -> Self {
        Self {
            params: &BN256_DEFAULT_PARAMS,
        }
    }
}
impl<E: RescueEngine> Hasher<E::Fr> for RescueHasher<E> {
    /// Gets the hash of the bit sequence.
    fn hash_bits<I: IntoIterator<Item = bool>>(&self, input: I) -> E::Fr {
        let bits: Vec<bool> = input.into_iter().collect();
        let packed = compute_multipacking::<E>(&bits);
        let sponge_output = rescue_hash::<E>(self.params, &packed);
        assert_eq!(sponge_output.len(), 1);
        sponge_output[0]
    }

    fn hash_elements<I: IntoIterator<Item = E::Fr>>(&self, elements: I) -> E::Fr {
        let packed: Vec<_> = elements.into_iter().collect();
        let sponge_output = rescue_hash::<E>(self.params, &packed);

        assert_eq!(sponge_output.len(), 1);
        sponge_output[0]
    }

    fn compress(&self, lhs: &E::Fr, rhs: &E::Fr, _i: usize) -> E::Fr {
        let sponge_output = rescue_hash::<E>(self.params, &[*lhs, *rhs]);

        assert_eq!(sponge_output.len(), 1);
        sponge_output[0]
    }
}

pub fn compute_multipacking<E: RescueEngine>(bits: &[bool]) -> Vec<E::Fr> {
    let mut result = vec![];

    for bits in bits.chunks(E::Fr::CAPACITY as usize) {
        let mut cur = E::Fr::zero();
        let mut coeff = E::Fr::one();

        for bit in bits {
            if *bit {
                cur.add_assign(&coeff);
            }

            coeff.double();
        }

        result.push(cur);
    }

    result
}

pub fn rescue_hash<E: RescueEngine>(params: &E::Params, input: &[E::Fr]) -> Vec<E::Fr> {
    sponge_fixed_length::<E>(params, input)
}

fn sponge_fixed_length<E: RescueEngine>(params: &E::Params, input: &[E::Fr]) -> Vec<E::Fr> {
    assert!(input.len() > 0);
    assert!(input.len() < 256);
    let input_len = input.len() as u8;
    let mut state = vec![E::Fr::zero(); params.state_width() as usize];
    // specialized for input length
    let mut repr = <E::Fr as PrimeField>::Repr::default();
    repr.as_mut()[0] = input_len;
    let len_fe = <E::Fr as PrimeField>::from_repr(repr).unwrap();
    let last_state_elem_idx = state.len() - 1;
    state[last_state_elem_idx] = len_fe;

    let rate = params.rate() as usize;
    let mut absorbtion_cycles = input.len() / rate;
    if input.len() % rate != 0 {
        absorbtion_cycles += 1;
    }
    let padding_len = absorbtion_cycles * rate - input.len();
    let padding = vec![E::Fr::one(); padding_len];

    let mut it = input.iter().chain(&padding);
    for _ in 0..absorbtion_cycles {
        for i in 0..rate {
            state[i].add_assign(it.next().unwrap());
        }
        state = rescue_mimc::<E>(params, &state);
    }

    debug_assert!(it.next().is_none());

    state[..(params.capacity() as usize)].to_vec()
}

pub fn rescue_mimc<E: RescueEngine>(params: &E::Params, old_state: &[E::Fr]) -> Vec<E::Fr> {
    let mut state = old_state.to_vec();
    let mut mds_application_scratch = vec![E::Fr::zero(); state.len()];
    assert_eq!(state.len(), params.state_width() as usize);
    // add round constatnts
    for (s, c) in state.iter_mut().zip(params.round_constants(0).iter()) {
        s.add_assign(c);
    }

    // parameters use number of rounds that is number of invocations of each SBox,
    // so we double
    for round_num in 0..(2 * params.num_rounds()) {
        // apply corresponding sbox
        if round_num & 1u32 == 0 {
            params.sbox_0().apply(&mut state);
        } else {
            params.sbox_1().apply(&mut state);
        }

        // add round keys right away
        mds_application_scratch.copy_from_slice(params.round_constants(round_num + 1));

        // mul state by MDS
        for (row, place_into) in mds_application_scratch.iter_mut().enumerate() {
            let tmp = scalar_product::<E>(&state[..], params.mds_matrix_row(row as u32));
            place_into.add_assign(&tmp);
            // *place_into = scalar_product::<E>(& state[..], params.mds_matrix_row(row as u32));
        }

        // place new data into the state
        state.copy_from_slice(&mds_application_scratch[..]);
    }

    state
}

fn scalar_product<E: RescueEngine>(input: &[E::Fr], by: &[E::Fr]) -> E::Fr {
    assert!(input.len() == by.len());
    let mut result = E::Fr::zero();
    for (a, b) in input.iter().zip(by.iter()) {
        let mut tmp = *a;
        tmp.mul_assign(b);
        result.add_assign(&tmp);
    }

    result
}
