use crate::gadgets::cond_swap::{CondSwapChip, CondSwapConfig, CondSwapInstructions};
use halo2_gadgets::utilities::{i2lebsp, UtilitiesInstructions};

use crate::state::State;
use crate::transactions::Transaction;
use eth_types::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Value};
use halo2_proofs::plonk::Instance;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Fixed, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use zkevm_circuits::keccak_circuit::keccak_packed_multi::{
    KeccakCircuitConfig, KeccakCircuitConfigArgs,
};
use zkevm_circuits::keccak_circuit::KeccakConfig;
use zkevm_circuits::table::KeccakTable;
use zkevm_circuits::util::{Challenges, SubCircuitConfig};
pub trait MerkleInstructions<
    F: Field,
    const PATH_LENGTH: usize,
    const K: usize,
    const MAX_WORDS: usize,
>: CondSwapInstructions<F> + UtilitiesInstructions<F> + Chip<F>
{
    /// Compute MerkleCRH for a given `layer`. The hash that computes the root
    /// is at layer 0, and the hashes that are applied to two leaves are at
    /// layer `MERKLE_DEPTH - 1` = layer 31.
    #[allow(non_snake_case)]
    fn hash_layer(
        &self,
        layouter: impl Layouter<F>,
        l: usize,
        left: Self::Var,
        right: Self::Var,
    ) -> Result<Self::Var, Error>;
}
/// Gadget representing a Merkle path that proves a leaf exists in a Merkle tree at a
/// specific position.
#[derive(Clone, Debug)]
pub struct MerklePath<
    F: Field,
    MerkleChip,
    const PATH_LENGTH: usize,
    const K: usize,
    const MAX_WORDS: usize,
    const PAR: usize,
> where
    MerkleChip: MerkleInstructions<F, PATH_LENGTH, K, MAX_WORDS> + Clone,
{
    chips: [MerkleChip; PAR],
    leaf_pos: Value<u32>,
    // The Merkle path is ordered from leaves to root.
    path: Value<[F; PATH_LENGTH]>,
}

#[allow(non_snake_case)]
impl<
        F: Field,
        MerkleChip,
        const PATH_LENGTH: usize,
        const K: usize,
        const MAX_WORDS: usize,
        const PAR: usize,
    > MerklePath<F, MerkleChip, PATH_LENGTH, K, MAX_WORDS, PAR>
where
    MerkleChip: MerkleInstructions<F, PATH_LENGTH, K, MAX_WORDS> + Clone,
{
    /// Calculates the root of the tree containing the given leaf at this Merkle path.
    ///
    /// Implements [Zcash Protocol Specification Section 4.9: Merkle Path Validity][merklepath].
    ///
    /// [merklepath]: https://zips.z.cash/protocol/protocol.pdf#merklepath
    pub fn calculate_root(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: MerkleChip::Var,
    ) -> Result<MerkleChip::Var, Error> {
        // Each chip processes `ceil(PATH_LENGTH / PAR)` layers.
        let layers_per_chip = (PATH_LENGTH + PAR - 1) / PAR;

        // Assign each layer to a chip.
        let chips = (0..PATH_LENGTH).map(|i| self.chips[i / layers_per_chip].clone());

        // The Merkle path is ordered from leaves to root, which is consistent with the
        // little-endian representation of `pos` below.
        let path = self.path.transpose_array();

        // Get position as a PATH_LENGTH-bit bitstring (little-endian bit order).
        let pos: [Value<bool>; PATH_LENGTH] = {
            let pos: Value<[bool; PATH_LENGTH]> = self.leaf_pos.map(|pos| i2lebsp(pos as u64));
            pos.transpose_array()
        };

        let mut node = leaf;
        for (l, ((sibling, pos), chip)) in path.iter().zip(pos.iter()).zip(chips).enumerate() {
            // `l` = MERKLE_DEPTH - layer - 1, which is the index obtained from
            // enumerating this Merkle path (going from leaf to root).
            // For example, when `layer = 31` (the first sibling on the Merkle path),
            // we have `l` = 32 - 31 - 1 = 0.
            // On the other hand, when `layer = 0` (the final sibling on the Merkle path),
            // we have `l` = 32 - 0 - 1 = 31.

            // Constrain which of (node, sibling) is (left, right) with a conditional swap
            // tied to the current bit of the position.
            let pair = {
                let pair = (node, *sibling);

                // Swap node and sibling if needed
                chip.swap(layouter.namespace(|| "node position"), pair, *pos)?
            };

            // Compute the node in layer l from its children:
            //     M^l_i = MerkleCRH(l, M^{l+1}_{2i}, M^{l+1}_{2i+1})
            node = chip.hash_layer(
                layouter.namespace(|| format!("MerkleCRH({}, left, right)", l)),
                l,
                pair.0,
                pair.1,
            )?;
        }

        Ok(node)
    }
}

#[derive(Clone)]
pub struct MerkleKeccakChip<F: Field> {
    config: MerkleKeccakConfig<F>,
}

#[derive(Clone, Debug)]
pub struct MerkleKeccakConfig<F: Field> {
    advices: [Column<Advice>; 5],
    q_decompose: Selector,
    pub_col: Column<Instance>,
    pub(crate) cond_swap_config: CondSwapConfig,
    pub(crate) keccak_config: KeccakConfig<F>,
}

impl<F: Field> Chip<F> for MerkleKeccakChip<F> {
    type Config = MerkleKeccakConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> MerkleKeccakChip<F> {
    /// Configures the [`MerkleChip`].
    pub fn configure(meta: &mut ConstraintSystem<F>) -> MerkleKeccakConfig<F> {
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let keccak_config = {
            let challenges = challenges.exprs(meta);
            KeccakCircuitConfig::new(
                meta,
                KeccakCircuitConfigArgs {
                    keccak_table,
                    challenges,
                },
            )
        };
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let cond_swap_config = CondSwapChip::configure(meta, advices);
        //let advices = keccak_config.advices();
        //let cond_swap_config = CondSwapChip::configure(meta, advices);

        // This selector enables the decomposition gate.
        let q_decompose = meta.selector();

        // Check that pieces have been decomposed correctly for Sinsemilla hash.
        // <https://zips.z.cash/protocol/protocol.pdf#orchardmerklecrh>
        //
        // a = a_0||a_1 = l || (bits 0..=239 of left)
        // b = b_0||b_1||b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        // c = bits 5..=254 of right
        //
        // The message pieces `a`, `b`, `c` are constrained by Sinsemilla to be
        // 250 bits, 20 bits, and 250 bits respectively.
        //
        // The pieces and subpieces are arranged in the following configuration:
        // |  A_0  |  A_1  |  A_2  |  A_3  |  A_4  | q_decompose |
        // -------------------------------------------------------
        // |   a   |   b   |   c   |  left | right |      1      |
        // |  z1_a |  z1_b |  b_1  |  b_2  |   l   |      0      |
        /*
        meta.create_gate("Decomposition check", |meta| {
            let q_decompose = meta.query_selector(q_decompose);
            let l_whole = meta.query_advice(advices[4], Rotation::next());

            let two_pow_5 = F::from(1 << 5);
            let two_pow_10 = two_pow_5.square();

            // a_whole is constrained by Sinsemilla to be 250 bits.
            let a_whole = meta.query_advice(advices[0], Rotation::cur());
            // b_whole is constrained by Sinsemilla to be 20 bits.
            let b_whole = meta.query_advice(advices[1], Rotation::cur());
            // c_whole is constrained by Sinsemilla to be 250 bits.
            let c_whole = meta.query_advice(advices[2], Rotation::cur());
            let left_node = meta.query_advice(advices[3], Rotation::cur());
            let right_node = meta.query_advice(advices[4], Rotation::cur());

            // a = a_0||a_1 = l || (bits 0..=239 of left)
            //
            // z_1 of SinsemillaHash(a) = a_1
            // => a_0 = a - (a_1 * 2^10)
            let z1_a = meta.query_advice(advices[0], Rotation::next());
            let a_1 = z1_a;
            // Derive a_0 (constrained by SinsemillaHash to be 10 bits)
            let a_0 = a_whole - a_1.clone() * two_pow_10;

            // b = b_0||b_1||b_2
            //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
            // The Orchard specification allows this representation to be non-canonical.
            // <https://zips.z.cash/protocol/protocol.pdf#merklepath>
            //
            //    z_1 of SinsemillaHash(b) = b_1 + 2^5 b_2
            // => b_0 = b - (z1_b * 2^10)
            let z1_b = meta.query_advice(advices[1], Rotation::next());
            // b_1 has been constrained to be 5 bits outside this gate.
            let b_1 = meta.query_advice(advices[2], Rotation::next());
            // b_2 has been constrained to be 5 bits outside this gate.
            let b_2 = meta.query_advice(advices[3], Rotation::next());
            // Constrain b_1 + 2^5 b_2 = z1_b
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-bit-lengths?partial
            let b1_b2_check = z1_b.clone() - (b_1.clone() + b_2.clone() * two_pow_5);
            // Derive b_0 (constrained by SinsemillaHash to be 10 bits)
            let b_0 = b_whole - (z1_b * two_pow_10);

            // Check that left = a_1 (240 bits) || b_0 (10 bits) || b_1 (5 bits)
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-decomposition?partial
            let left_check = {
                let reconstructed = {
                    let two_pow_240 = F::from_u128(1 << 120).square();
                    a_1 + (b_0 + b_1 * two_pow_10) * two_pow_240
                };
                reconstructed - left_node
            };

            // Check that right = b_2 (5 bits) || c (250 bits)
            // The Orchard specification allows this representation to be non-canonical.
            // <https://zips.z.cash/protocol/protocol.pdf#merklepath>
            // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-decomposition?partial
            let right_check = b_2 + c_whole * two_pow_5 - right_node;

            Constraints::with_selector(
                q_decompose,
                [
                    ("l_check", a_0 - l_whole),
                    ("left_check", left_check),
                    ("right_check", right_check),
                    ("b1_b2_check", b1_b2_check),
                ],
            )
        });
        */
        MerkleKeccakConfig {
            advices,
            q_decompose,
            cond_swap_config,
            keccak_config,
            pub_col: todo!(),
        }
    }
    pub fn construct(config: MerkleKeccakConfig<F>) -> Self {
        MerkleKeccakChip { config }
    }
}
/*
impl<F: Field, const PATH_LENGTH: usize, const K: usize, const MAX_WORDS: usize>
    MerkleInstructions<F, PATH_LENGTH, K, MAX_WORDS> for MerkleKeccakChip<F>
{
    #[allow(non_snake_case)]
    fn hash_layer(
        &self,
        mut layouter: impl Layouter<F>,
        // l = MERKLE_DEPTH - layer - 1
        l: usize,
        left: Self::Var,
        right: Self::Var,
    ) -> Result<Self::Var, Error> {
        let config = self.config().clone();

        // We need to hash `l || left || right`, where `l` is a 10-bit value.
        // We allow `left` and `right` to be non-canonical 255-bit encodings.
        //
        // a = a_0||a_1 = l || (bits 0..=239 of left)
        // b = b_0||b_1||b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        // c = bits 5..=254 of right
        //
        // We start by witnessing all of the individual pieces, and range-constraining the
        // short pieces b_1 and b_2.
        //
        // https://p.z.cash/halo2-0.1:sinsemilla-merkle-crh-bit-lengths?partial

        // `a = a_0||a_1` = `l` || (bits 0..=239 of `left`)
        let a = MessagePiece::from_subpieces(
            self.clone(),
            layouter.namespace(|| "Witness a = a_0 || a_1"),
            [
                RangeConstrained::bitrange_of(Value::known(&pallas::Base::from(l as u64)), 0..10),
                RangeConstrained::bitrange_of(left.value(), 0..240),
            ],
        )?;

        // b = b_0 || b_1 || b_2
        //   = (bits 240..=249 of left) || (bits 250..=254 of left) || (bits 0..=4 of right)
        let (b_1, b_2, b) = {
            // b_0 = (bits 240..=249 of `left`)
            let b_0 = RangeConstrained::bitrange_of(left.value(), 240..250);

            // b_1 = (bits 250..=254 of `left`)
            // Constrain b_1 to 5 bits.
            let b_1 = RangeConstrained::witness_short(
                &config.sinsemilla_config.lookup_config(),
                layouter.namespace(|| "b_1"),
                left.value(),
                250..(pallas::Base::NUM_BITS as usize),
            )?;

            // b_2 = (bits 0..=4 of `right`)
            // Constrain b_2 to 5 bits.
            let b_2 = RangeConstrained::witness_short(
                &config.sinsemilla_config.lookup_config(),
                layouter.namespace(|| "b_2"),
                right.value(),
                0..5,
            )?;

            let b = MessagePiece::from_subpieces(
                self.clone(),
                layouter.namespace(|| "Witness b = b_0 || b_1 || b_2"),
                [b_0, b_1.value(), b_2.value()],
            )?;

            (b_1, b_2, b)
        };

        // c = bits 5..=254 of `right`
        let c = MessagePiece::from_subpieces(
            self.clone(),
            layouter.namespace(|| "Witness c"),
            [RangeConstrained::bitrange_of(
                right.value(),
                5..(pallas::Base::NUM_BITS as usize),
            )],
        )?;

        // hash = SinsemillaHash(Q, 𝑙⋆ || left⋆ || right⋆)
        //
        // `hash = ⊥` is handled internally to `SinsemillaChip::hash_to_point`: incomplete
        // addition constraints allows ⊥ to occur, and then during synthesis it detects
        // these edge cases and raises an error (aborting proof creation).
        //
        // Note that MerkleCRH as-defined maps ⊥ to 0. This is for completeness outside
        // the circuit (so that the ⊥ does not propagate into the type system). The chip
        // explicitly doesn't map ⊥ to 0; in fact it cannot, as doing so would require
        // constraints that amount to using complete addition. The rationale for excluding
        // this map is the same as why Sinsemilla uses incomplete addition: this situation
        // yields a nontrivial discrete log relation, and by assumption it is hard to find
        // these.
        //
        // https://p.z.cash/proto:merkle-crh-orchard
        let (point, zs) = self.hash_to_point(
            layouter.namespace(|| format!("hash at l = {}", l)),
            Q,
            vec![a.inner(), b.inner(), c.inner()].into(),
        )?;
        let hash = Self::extract(&point);

        // `SinsemillaChip::hash_to_point` returns the running sum for each `MessagePiece`.
        // Grab the outputs we need for the decomposition constraints.
        let z1_a = zs[0][1].clone();
        let z1_b = zs[1][1].clone();

        // Check that the pieces have been decomposed properly.
        //
        // The pieces and subpieces are arranged in the following configuration:
        // |  A_0  |  A_1  |  A_2  |  A_3  |  A_4  | q_decompose |
        // -------------------------------------------------------
        // |   a   |   b   |   c   |  left | right |      1      |
        // |  z1_a |  z1_b |  b_1  |  b_2  |   l   |      0      |
        {
            layouter.assign_region(
                || "Check piece decomposition",
                |mut region| {
                    // Set the fixed column `l` to the current l.
                    // Recall that l = MERKLE_DEPTH - layer - 1.
                    // The layer with 2^n nodes is called "layer n".
                    config.q_decompose.enable(&mut region, 0)?;
                    region.assign_advice_from_constant(
                        || format!("l {}", l),
                        config.advices[4],
                        1,
                        pallas::Base::from(l as u64),
                    )?;

                    // Offset 0
                    // Copy and assign `a` at the correct position.
                    a.inner().cell_value().copy_advice(
                        || "copy a",
                        &mut region,
                        config.advices[0],
                        0,
                    )?;
                    // Copy and assign `b` at the correct position.
                    b.inner().cell_value().copy_advice(
                        || "copy b",
                        &mut region,
                        config.advices[1],
                        0,
                    )?;
                    // Copy and assign `c` at the correct position.
                    c.inner().cell_value().copy_advice(
                        || "copy c",
                        &mut region,
                        config.advices[2],
                        0,
                    )?;
                    // Copy and assign the left node at the correct position.
                    left.copy_advice(|| "left", &mut region, config.advices[3], 0)?;
                    // Copy and assign the right node at the correct position.
                    right.copy_advice(|| "right", &mut region, config.advices[4], 0)?;

                    // Offset 1
                    // Copy and assign z_1 of SinsemillaHash(a) = a_1
                    z1_a.copy_advice(|| "z1_a", &mut region, config.advices[0], 1)?;
                    // Copy and assign z_1 of SinsemillaHash(b) = b_1
                    z1_b.copy_advice(|| "z1_b", &mut region, config.advices[1], 1)?;
                    // Copy `b_1`, which has been constrained to be a 5-bit value
                    b_1.inner()
                        .copy_advice(|| "b_1", &mut region, config.advices[2], 1)?;
                    // Copy `b_2`, which has been constrained to be a 5-bit value
                    b_2.inner()
                        .copy_advice(|| "b_2", &mut region, config.advices[3], 1)?;

                    Ok(())
                },
            )?;
        }

        // Check layer hash output against Sinsemilla primitives hash
        /*
        #[cfg(test)]
        {
            use crate::{sinsemilla::primitives::HashDomain, utilities::i2lebsp};

            use group::ff::PrimeFieldBits;

            left.value()
                .zip(right.value())
                .zip(hash.value())
                .assert_if_known(|((left, right), hash)| {
                    let l = i2lebsp::<10>(l as u64);
                    let left: Vec<_> = left
                        .to_le_bits()
                        .iter()
                        .by_vals()
                        .take(pallas::Base::NUM_BITS as usize)
                        .collect();
                    let right: Vec<_> = right
                        .to_le_bits()
                        .iter()
                        .by_vals()
                        .take(pallas::Base::NUM_BITS as usize)
                        .collect();
                    let merkle_crh = HashDomain::from_Q(Q.into());

                    let mut message = l.to_vec();
                    message.extend_from_slice(&left);
                    message.extend_from_slice(&right);

                    let expected = merkle_crh.hash(message.into_iter()).unwrap();

                    expected.to_repr() == hash.to_repr()
                });
        }
         */
        Ok(hash)
    }
}
 */
impl<F: Field> UtilitiesInstructions<F> for MerkleKeccakChip<F> {
    type Var = AssignedCell<F, F>;
}
