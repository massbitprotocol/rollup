use eth_types::Field;
use ff::PrimeField;
use halo2_proofs::{circuit::Value, halo2curves::bn256};
use keccak256::plain::Keccak;
use zkevm_circuits::keccak_circuit::util::pack;
use zksync_crypto::merkle_tree::hasher::Hasher;
type Fr = bn256::Fr;
// pub trait HashValues<F: Field> {
//     fn hash_values(&self) -> Value<F>;
// }
// impl<F: Field> HashValues<F> for Value<(F, F)> {
//     fn hash_values(&self) -> Value<F> {
//         match self.inner {
//             Some((a, b)) => (Value::known(a), Value::known(b)),
//             None => (Value::unknown(), Value::unknown()),
//         }
//     }
// }
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
impl<F: Field> Hasher<F> for Keccak256Hasher {
    /// Gets the hash of the bit sequence.
    fn hash_bits<I: IntoIterator<Item = bool>>(&self, input: I) -> F {
        let bits: Vec<bool> = input.into_iter().collect();
        let bytes = Keccak256Hasher::to_bytes(bits.as_slice());
        let mut keccak = Keccak::default();
        keccak.update(bytes.as_slice());
        let hashed_bits = keccak.digest();
        let packed = pack::<F>(hashed_bits.as_slice());
        packed
    }

    fn hash_elements<I: IntoIterator<Item = F>>(&self, elements: I) -> F {
        let mut bits: Vec<u8> = vec![];
        elements
            .into_iter()
            .for_each(|elm| elm.to_repr().as_ref().iter().for_each(|b| bits.push(*b)));
        let mut keccak = Keccak::default();
        keccak.update(bits.as_slice());
        let hashed_bits = keccak.digest();
        let packed = pack::<F>(hashed_bits.as_slice());
        packed
    }

    fn compress(&self, lhs: &F, rhs: &F, _i: usize) -> F {
        let mut bits: Vec<u8> = vec![];
        lhs.to_repr().as_ref().iter().for_each(|b| bits.push(*b));
        rhs.to_repr().as_ref().iter().for_each(|b| bits.push(*b));
        // let xored_bits = xor_fields(lhs, rhs);
        let mut keccak = Keccak::default();
        keccak.update(bits.as_slice());
        let hashed_bits = keccak.digest();
        let packed = pack::<F>(hashed_bits.as_slice());
        // println!(
        //     "Keccak 256 hasher: left {:?}; right {:?}; hash {:?}",
        //     lhs, rhs, &packed
        // );
        packed
    }
}

pub fn xor_fields<F: Field>(a: &F, b: &F) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (idx, (a, b)) in a
        .to_repr()
        .as_ref()
        .iter()
        .zip(b.to_repr().as_ref().iter())
        .enumerate()
    {
        bytes[idx] = *a ^ *b;
    }
    bytes
}
