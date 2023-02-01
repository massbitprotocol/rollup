use crate::hasher::RescueEngine;
use crate::keccak256::util::{pack, unpack, xor_fields};
use ff::PrimeField;
use halo2_proofs::halo2curves::{bn256, pairing::Engine};
use zksync_crypto::merkle_tree::hasher::Hasher;

use super::plain::Keccak;
type Fr = bn256::Fr;
/// Default hasher for the zkSync state hash calculation.
#[derive(Default, Clone, Debug)]
pub struct Keccak256Hasher {}
impl Keccak256Hasher {
    fn to_bytes(bools: &[bool]) -> Vec<u8> {
        let n = bools.len();
        let mut out = vec![];
        let mut idx = 0;
        while idx < n {
            let mut cur = 0u8;
            let remain = n - out.len() >> 3;
            let byte_size = if remain <= 8 { remain } else { 8 };
            for i in 0..byte_size {
                let bit = bools[idx];
                cur |= (bit as u8) << i;
            }
            idx += byte_size;
            out.push(cur);
        }
        out
    }
}

impl Hasher<Fr> for Keccak256Hasher {
    /// Gets the hash of the bit sequence.
    fn hash_bits<I: IntoIterator<Item = bool>>(&self, input: I) -> Fr {
        let bits: Vec<bool> = input.into_iter().collect();
        let bytes = Keccak256Hasher::to_bytes(bits.as_slice());
        let mut keccak = Keccak::default();
        keccak.update(bytes.as_slice());
        let hashed_bits = keccak.digest();
        let packed = pack::<Fr>(hashed_bits.as_slice());
        packed
    }

    fn hash_elements<I: IntoIterator<Item = Fr>>(&self, elements: I) -> Fr {
        let mut bits: Vec<u8> = vec![];
        elements
            .into_iter()
            .for_each(|elm| elm.to_repr().as_ref().iter().for_each(|b| bits.push(*b)));
        let mut keccak = Keccak::default();
        keccak.update(bits.as_slice());
        let hashed_bits = keccak.digest();
        let packed = pack::<Fr>(hashed_bits.as_slice());
        packed
    }

    fn compress(&self, lhs: &Fr, rhs: &Fr, _i: usize) -> Fr {
        let xored_bits = xor_fields(lhs, rhs);
        let mut keccak = Keccak::default();
        keccak.update(&xored_bits);
        let hashed_bits = keccak.digest();
        let packed = pack::<Fr>(hashed_bits.as_slice());
        packed
    }
}
