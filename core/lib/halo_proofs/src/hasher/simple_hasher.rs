use halo2_proofs::halo2curves::{bn256::Bn256, pairing::Engine};
use zksync_crypto::merkle_tree::hasher::Hasher;
/// Default hasher for the zkSync state hash calculation.
#[derive(Default, Clone, Debug)]
pub struct SimpleHasher {}
impl<Hash> Hasher<Hash> for SimpleHasher {
    /// Gets the hash of the bit sequence.
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
