// Pedersen hash implementation of the Hasher trait
use franklin_crypto::rescue::RescueEngine;
//use franklin_crypto::bellman::pairing::Engine;
//use franklin_crypto::rescue::RescueHashParams;
use franklin_crypto::circuit::rescue::CsSBox;
use franklin_crypto::{circuit::multipack, rescue::rescue_hash};
use halo2_proofs::halo2curves::{bn256::Bn256, pairing::Engine};
use zksync_crypto::params;

use crate::Fp;

use super::Hasher;
use core::fmt;

pub trait RescueEngine: Engine {
    type Params: RescueHashParams<Self>;
    type Fr;
}

pub trait RescueHashParams<E: RescueEngine>: RescueParamsInternal<E> {
    type SBox0: CsSBox<E>;
    type SBox1: CsSBox<E>;
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

impl RescueEngine for Bn256 {
    type Fr = Fp;
}

/// Default hasher for the zkSync state hash calculation.
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

impl<E: RescueEngine> Hasher<E::Fr> for RescueHasher<E> {
    fn hash_bits<I: IntoIterator<Item = bool>>(&self, input: I) -> E::Fr {
        let bits: Vec<bool> = input.into_iter().collect();
        let packed = multipack::compute_multipacking::<E>(&bits);
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

pub type BabyRescueHasher = RescueHasher<Bn256>;

impl Default for RescueHasher<Bn256> {
    fn default() -> Self {
        Self {
            params: &params::RESCUE_PARAMS,
        }
    }
}

#[test]
fn test_resue_hash() {
    let hasher = BabyRescueHasher::default();

    let hash = hasher.hash_bits(vec![false, false, false, true, true, true, true, true]);
    hasher.compress(&hash, &hash, 0);
    hasher.compress(&hash, &hash, 1);
}
